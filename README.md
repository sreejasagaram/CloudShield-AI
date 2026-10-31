# CloudShield AI

CloudShield AI is a beginner-friendly, explainable local prototype for reviewing a small set of AWS-style cloud configuration examples. It includes five deterministic checks, a small labeled dataset, an authenticated local dashboard, JSON configuration upload and vulnerability scanning, private custom examples, and source-grounded AI explanations generated locally with Ollama.

## Scope

The scanner reads local JSON examples only. The ten built-in examples in `data/configs/` are read-only; signed-in users can create and manage validated custom examples stored in the SQLite database. The API accepts server-generated configuration IDs, not arbitrary file paths. Optional AI explanations use the local Ollama API at `http://localhost:11434` and the `qwen2.5:3b` model by default; no API key or paid AI service is required. The model receives only the deterministic finding and retrieved AWS documentation summaries. It never accesses AWS accounts, changes resources, or remediates findings, and it does not decide whether a rule fires or change severity. The project is not a replacement for a cloud security platform. JSON files are simplified teaching fixtures, not deployable infrastructure templates. AWS concepts and prototype-specific assumptions are distinguished in the documentation.

## Phase 1 documents

- [Problem statement](docs/problem_statement.md)
- [Security rules](docs/security_rules.md)
- [Dataset guide](docs/dataset.md)
- [RAG source register](docs/rag_sources.md)
- [Sample configurations](data/configs/)
- [Expected results](data/expected/results.json)
- [Deployment preparation and hosting comparison](docs/deployment.md)
- [Demo guide](docs/demo_guide.md)

## Run a scan

Requires Python 3.10 or later; there are no third-party dependencies. From the project root in PowerShell, set the source directory for the current shell:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
```

Print readable findings:

```powershell
python -m cloudshield.cli .\data\configs\s3-public-vulnerable.json
```

Print structured JSON for later integration:

```powershell
python -m cloudshield.cli .\data\configs\iam-wildcard-vulnerable.json --format json
```

An input error is printed to standard error and exits with status `2`.

## Run the dashboard

Requires Python 3.10 or later. From the project root in PowerShell, create and activate a virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\requirements.txt
```

Start the local development server:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m cloudshield.api
```

Open <http://127.0.0.1:5000/> in your browser. Register an account, sign in, and use the dashboard to scan built-in examples, manage private custom examples, or upload a UTF-8 JSON cloud configuration (maximum 1 MB) for vulnerability checking. Uploaded files are scanned in memory and are not saved. The upload feature accepts the documented CloudShield scenario JSON format; it does not scan arbitrary PDFs, source code, or general documents.

The dashboard binds to `127.0.0.1` for local development. Press `Ctrl+C` in the server terminal to stop it. For deployment, use the supplied Dockerfile and a persistent writable volume for `/var/lib/cloudshield`.

## Optional source-grounded explanations

The source summaries and metadata are stored in [data/rag/knowledge.json](data/rag/knowledge.json), based on the verified references in [docs/rag_sources.md](docs/rag_sources.md). On first app startup, CloudShield converts those summaries to local TF-IDF word and two-word-ngram vectors using scikit-learn, then stores and searches the vectors with Chroma's persistent local client. This is **lexical** retrieval, not semantic retrieval: it does not use a language-model embedding service or download an embedding model. Chroma stores the title, URL, rule IDs, and topic metadata with each chunk. Its generated database is saved under `data/rag/chroma_db/` by default, is ignored by Git, and can be rebuilt from the JSON collection if removed. Set `CLOUDSHIELD_VECTOR_DB_DIR` to use another writable directory, such as a hosted persistent-volume mount.

The explanation workflow is fixed and read-only: the scanner first produces the finding and severity; the agent then makes one call to its sole tool, `retrieve_trusted_sources`; finally, the provider is asked for an explanation using only those retrieved sources. The workflow has a two-step limit, validates citations against retrieved source IDs, and tells the user when context is insufficient. It has no filesystem, shell, AWS, or remediation tools. The original simple retrieval-and-explanation path remains available as a fallback if the bounded workflow cannot run.

The retriever, database, and Ollama model run locally. Only an explicit **Explain with sources** request sends the finding and retrieved summary text to the configured local Ollama service. Ollama must be running and the selected model must be installed. The default is `qwen2.5:3b`; set `CLOUDSHIELD_OLLAMA_MODEL` to use another local model, `CLOUDSHIELD_OLLAMA_URL` to select another loopback Ollama URL, or `CLOUDSHIELD_OLLAMA_TIMEOUT_SECONDS` to adjust the request timeout.

In PowerShell, install and start the model before launching CloudShield:

```powershell
ollama pull qwen2.5:3b
ollama serve
```

In a second PowerShell terminal, start the Flask dashboard as described above. The dashboard's AI panel reports whether the local service and configured model are available. CloudShield binds to `127.0.0.1`; it does not expose Ollama or the website to the internet.
