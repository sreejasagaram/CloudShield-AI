"""Persistent local vector retrieval over curated AWS documentation summaries."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, TypeGuard, TypedDict, cast

import chromadb
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from chromadb.config import Settings
from chromadb.api.types import Metadata
from numpy.typing import NDArray

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KNOWLEDGE_PATH = PROJECT_ROOT / "data" / "rag" / "knowledge.json"
DEFAULT_VECTOR_DB_PATH = PROJECT_ROOT / "data" / "rag" / "chroma_db"
COLLECTION_NAME = "cloudshield-aws-knowledge"
VECTOR_MODEL_ID = "tfidf-word-ngram-1-2-v1"
VECTOR_DB_ENV = "CLOUDSHIELD_VECTOR_DB_DIR"


class KnowledgeChunk(TypedDict):
    source_id: str
    title: str
    publisher: str
    url: str
    topic: str
    rule_ids: list[str]
    summary: str


def _is_knowledge_chunk(value: object) -> TypeGuard[KnowledgeChunk]:
    if not isinstance(value, dict):
        return False
    chunk = cast(dict[str, object], value)
    required_text_fields = ("source_id", "title", "publisher", "url", "topic", "summary")
    rule_ids = chunk.get("rule_ids")
    if not isinstance(rule_ids, list):
        return False
    valid_rule_ids: list[object] = cast(list[object], rule_ids)
    return (
        all(isinstance(chunk.get(field), str) for field in required_text_fields)
        and all(isinstance(rule_id, str) for rule_id in valid_rule_ids)
    )


def _dense_vectors(matrix: Any) -> NDArray[np.float32]:
    return np.asarray(matrix.toarray(), dtype=np.float32)


class SourceRetriever:
    """Retrieve rule-relevant summaries from a local persistent Chroma index."""

    def __init__(
        self,
        knowledge_path: str | Path = DEFAULT_KNOWLEDGE_PATH,
        min_similarity: float = 0.01,
        persist_directory: str | Path | None = None,
    ) -> None:
        path = Path(knowledge_path)
        try:
            knowledge_text = path.read_text(encoding="utf-8")
            knowledge: Any = json.loads(knowledge_text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"Cannot load RAG knowledge collection {path}: {error}") from error
        if not isinstance(knowledge, dict):
            raise ValueError(f"RAG knowledge collection {path} must be a JSON object.")
        raw_collection = cast(dict[str, object], knowledge)
        raw_chunks_value: object = raw_collection.get("chunks")
        if not isinstance(raw_chunks_value, list):
            raise ValueError(f"RAG knowledge collection {path} must contain a chunks array.")
        raw_chunks: list[object] = cast(list[object], raw_chunks_value)

        self.chunks: list[KnowledgeChunk] = []
        for index, chunk in enumerate(raw_chunks):
            if not _is_knowledge_chunk(chunk):
                raise ValueError(f"RAG knowledge chunk {index} has invalid metadata.")
            self.chunks.append(chunk)

        if not self.chunks:
            raise ValueError(f"RAG knowledge collection {path} has no chunks.")

        self.min_similarity = min_similarity
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words="english")
        self.document_vectors: Any = self.vectorizer.fit_transform(
            [self._document_text(chunk) for chunk in self.chunks]
        )
        self.collection = self._open_collection(
            Path(
                persist_directory
                or os.environ.get(VECTOR_DB_ENV)
                or DEFAULT_VECTOR_DB_PATH
            ),
            knowledge_text,
        )

    @staticmethod
    def _document_text(chunk: KnowledgeChunk) -> str:
        return " ".join(
            (
                chunk["source_id"],
                chunk["title"],
                chunk["topic"],
                chunk["summary"],
                " ".join(chunk["rule_ids"]),
            )
        )

    def _open_collection(self, persist_directory: Path, knowledge_text: str) -> Any:
        fingerprint = hashlib.sha256(
            f"{VECTOR_MODEL_ID}\n{knowledge_text}".encode("utf-8")
        ).hexdigest()
        client = chromadb.PersistentClient(
            path=str(persist_directory),
            settings=Settings(anonymized_telemetry=False),
        )
        collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={
                "hnsw:space": "cosine",
                "knowledge_fingerprint": fingerprint,
                "vector_model": VECTOR_MODEL_ID,
            },
        )
        if (collection.metadata or {}).get("knowledge_fingerprint") != fingerprint:
            client.delete_collection(COLLECTION_NAME)
            collection = client.create_collection(
                name=COLLECTION_NAME,
                metadata={
                    "hnsw:space": "cosine",
                    "knowledge_fingerprint": fingerprint,
                    "vector_model": VECTOR_MODEL_ID,
                },
            )

        chunk_ids = [chunk["source_id"] for chunk in self.chunks]
        metadatas: list[Metadata] = []
        for chunk in self.chunks:
            metadata_rule_ids: list[str | int | float | bool] = []
            metadata_rule_ids.extend(chunk["rule_ids"])
            metadata: Metadata = {
                "title": chunk["title"],
                "publisher": chunk["publisher"],
                "url": chunk["url"],
                "topic": chunk["topic"],
                "rule_ids": metadata_rule_ids,
            }
            metadatas.append(metadata)
        collection.upsert(
            ids=chunk_ids,
            embeddings=_dense_vectors(self.document_vectors),
            documents=[chunk["summary"] for chunk in self.chunks],
            metadatas=metadatas,
        )
        stored_ids = collection.get(include=["metadatas"])["ids"]
        obsolete_ids = sorted(set(stored_ids) - set(chunk_ids))
        if obsolete_ids:
            collection.delete(ids=obsolete_ids)
        return collection

    def retrieve(
        self,
        query: str,
        rule_id: str,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Return source chunks matching the rule and query, best match first."""
        if not query.strip() or top_k < 1:
            return []

        query_vector = _dense_vectors(self.vectorizer.transform([query]))
        results = self.collection.query(
            query_embeddings=query_vector,
            n_results=self.collection.count(),
            include=["documents", "metadatas", "distances"],
        )
        ranked: list[dict[str, Any]] = []
        ids = results["ids"][0]
        documents = results["documents"][0]
        metadata_rows = results["metadatas"][0]
        distances = results["distances"][0]
        for source_id, summary, metadata, distance in zip(
            ids,
            documents,
            metadata_rows,
            distances,
        ):
            if metadata is None or rule_id not in metadata["rule_ids"]:
                continue
            similarity = max(0.0, 1.0 - float(distance))
            if similarity < self.min_similarity:
                continue
            ranked.append(
                {
                    "source_id": source_id,
                    "title": metadata["title"],
                    "publisher": metadata["publisher"],
                    "url": metadata["url"],
                    "topic": metadata["topic"],
                    "rule_ids": metadata["rule_ids"],
                    "summary": summary,
                    "similarity": similarity,
                }
            )
        ranked.sort(key=lambda item: (-item["similarity"], item["source_id"]))
        return ranked[:top_k]
