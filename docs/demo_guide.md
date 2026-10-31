# CloudShield AI demo guide

This is a local prototype demo. It scans only the sample JSON files in `data/configs/`; it does not connect to AWS or change cloud resources.

## Before the demo

Install dependencies and start the dashboard from the project root in PowerShell:

```powershell
python -m pip install -r .\requirements.txt
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m cloudshield.api
```

Open <http://127.0.0.1:5000/>. Start Ollama and install the local model in a separate PowerShell terminal:

```powershell
ollama pull qwen2.5:3b
ollama serve
```

## Suggested walkthrough

### 1. Scan a vulnerable sample

Choose `s3-public-vulnerable.json` and select **Scan configuration**. Point out the `CS-S3-001` high-severity finding, the affected sample resource, and the evidence showing the public policy principal and bucket-level public-access-block values. The rule engine—not AI—created the finding.

### 2. Scan a corrected sample

Choose `s3-public-secure.json` and scan again. The dashboard should report no findings for this sample. Explain that this is a prototype result for this fixture, not a conclusion about a live bucket or all applicable AWS account/access-point controls.

### 3. Generate a retrieval-grounded explanation

Select `s3-public-vulnerable.json`, scan, and choose **Explain with sources**. CloudShield sends the deterministic finding and retrieved source summaries to the local `qwen2.5:3b` Ollama model. The explanation should cite the source IDs and links returned by retrieval. If Ollama is unavailable or the model is missing, the dashboard reports that state without changing the finding or scan result. No API key or paid service is used.

## Optional container demo

Build and run the production-server container locally:

```powershell
docker build -t cloudshield-ai:local .
docker run --rm -p 8080:8080 cloudshield-ai:local
```

Open <http://127.0.0.1:8080/>. The database is ephemeral in this command because no volume is mounted; for a persistence demo, mount a durable writable directory and set `CLOUDSHIELD_VECTOR_DB_DIR` as described in [deployment.md](deployment.md).

## Known limitations to disclose

- The five deterministic rules check simplified teaching fixtures, not a live AWS account.
- Retrieval covers five short summaries and uses lexical TF-IDF vectors; it is not semantic retrieval and may miss relevant wording.
- The explanation model may make mistakes. Citations are restricted to retrieved source IDs, but citations do not guarantee every claim is accurate.
- The app has no user authentication or authorization and is not ready for unrestricted public access.
- The example Chroma database is local persistent storage, not a multi-replica shared database.
- No remediation, cloud changes, or automatic security decisions are performed.
