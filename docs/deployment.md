# Deployment preparation

This project is prepared as a container image, but it has not been built, published, or deployed. A hosting platform and access-control design still need to be chosen.

## What the container does

The root [Dockerfile](../Dockerfile) installs the pinned-by-range dependencies, runs the Flask WSGI application with Waitress, exposes port `8080`, and runs as an unprivileged user. The root [.dockerignore](../.dockerignore) excludes tests, local environments, caches, generated local data, and secret files. The image includes the built-in scanner fixtures and curated knowledge JSON but not developer-created configurations or a copy of a developer's vector database.

Build and run locally from the project root:

```powershell
docker build -t cloudshield-ai:local .
docker run --rm -p 8080:8080 cloudshield-ai:local
```

Open <http://127.0.0.1:8080/>. The container does not include Ollama; local AI explanations require an Ollama service reachable from the application process. For the supported laptop setup, run the Flask application natively as described in the root README and keep both services bound to the local machine. The container does not enable Flask debug mode and uses Waitress.

To keep the Chroma directory across local container restarts, create a named Docker volume and mount it at the configured path:

```powershell
docker volume create cloudshield-rag
docker run --rm -p 8080:8080 --mount source=cloudshield-rag,target=/var/lib/cloudshield/chroma cloudshield-ai:local
```

The named volume remains until explicitly removed. Treat it as app data and include it in any backup/retention plan.

## Custom configuration persistence

The dashboard's custom examples are validated with the existing scenario validator, assigned server-generated IDs, and stored as JSON files in a server-controlled directory. In a source checkout, the default is `data/custom_configs/`; in the container, `CLOUDSHIELD_CUSTOM_CONFIG_DIR` defaults to `/var/lib/cloudshield/custom-configs`. The application user (UID/GID `10001` in Docker) needs write access to that directory. Custom files are excluded from Git and the Docker build context and are never copied into the image.

To keep custom examples across container restarts, create and mount a separate named volume:

```powershell
docker volume create cloudshield-configs
docker run --rm -p 8080:8080 --mount source=cloudshield-configs,target=/var/lib/cloudshield/custom-configs cloudshield-ai:local
```

The Chroma index and custom examples use separate storage paths and may use separate named volumes. Back up the custom-configuration volume if those examples matter. Custom examples are shared by all clients of this app instance: there is no authentication or per-user ownership, so keep the demo private and access-restricted. The dashboard provides controls to create, inspect, edit, and delete custom examples; built-in examples remain read-only.

## Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PORT` | Platform-dependent | `8080` in the container | Port Waitress listens on inside the container. |
| `CLOUDSHIELD_VECTOR_DB_DIR` | No | `data/rag/chroma_db` in a source checkout; `/var/lib/cloudshield/chroma` in the container | Writable local directory used by persistent Chroma. |
| `CLOUDSHIELD_CUSTOM_CONFIG_DIR` | No | `data/custom_configs` in a source checkout; `/var/lib/cloudshield/custom-configs` in the container | Writable directory for validated user-created JSON examples. Mount durable storage here to preserve them across container replacement. |
| `CLOUDSHIELD_OLLAMA_URL` | No | `http://localhost:11434` | Local Ollama API base URL. Only loopback addresses are accepted. |
| `CLOUDSHIELD_OLLAMA_MODEL` | No | `qwen2.5:3b` | Installed local Ollama model used for explanations. |
| `CLOUDSHIELD_OLLAMA_TIMEOUT_SECONDS` | No | `120` | Maximum time allowed for a local model response. |

No paid AI API key or external AI service is used. Scanning remains available if Ollama is unavailable or the configured model is not installed.

## Chroma persistence requirements

Chroma is embedded in the app process, not a hosted service. The database must be on durable writable storage:

1. Configure `CLOUDSHIELD_VECTOR_DB_DIR` to the platform's persistent volume mount path.
2. Mount that volume at the same path for each deployment/restart.
3. Ensure the mounted directory is writable by container UID/GID `10001`.
4. Keep one app replica/writer for this prototype. Do not mount the same Chroma directory into several concurrently running replicas or machines; this prototype has no distributed database coordination.

Without a persistent mount, the vector DB may be erased on restart or redeploy. The app can rebuild it from `data/rag/knowledge.json`, but persistence is still needed to meet the durable-storage goal and avoid repeated initialization. Back up the volume and knowledge JSON together before production use. Local Chroma database files contain the curated source collection and are not intended to contain secrets.

## Restrict access before a public demo

The app currently has **no user authentication or authorization**. Before making a hosted URL publicly accessible:

- Place it behind a trusted identity-aware access gateway or add reviewed application authentication.
- Limit access to invited demo users; do not rely on an unlisted URL.
- Keep any future integration credentials in the host's secret manager; never bake them into the image or commit them.
- Set request limits and monitor resource usage for local model inference.
- Use TLS, review network ingress, set resource limits, and check platform logs for accidental secret exposure.
- Do not use this sample-config auditor as a real-account assessment or production security control.

Do not expose Flask's development server. The container uses Waitress; follow the chosen host's ingress, TLS, identity, network, and secret-management requirements.

## Hosting options to choose from

No hosting platform was specified. These options were checked against their current official documentation; this is a comparison, not a deployment or endorsement.

| Platform | Container support | Durable Chroma storage | Secrets and access | Trade-offs |
|---|---|---|---|---|
| **Render Web Service** | Builds from the repository's Dockerfile and supplies a public web-service URL. | A persistent disk preserves filesystem changes across restarts/redeploys, but Render documents it for paid services and notes that only changes under its mount path persist. A disk is available to only one service instance; Render does not allow scaling that service to multiple instances, and disk-backed redeploys do not use zero-downtime replacement. | Dashboard environment variables and secret files are supported. Add an authentication/access gate before sharing a public service. | Likely simplest for a single-instance demo; verify current pricing and accept the disk-backed scale/redeploy limitations. |
| **Fly.io** | Fly Launch builds/deploys containers and supports app configuration in `fly.toml`. | Fly Volumes are local persistent storage attached to one machine in one region; the docs describe one volume per machine and no shared volume. Design this app as one machine with one volume. | `fly secrets` supplies runtime secrets as environment variables. Public HTTP exposure still needs an access-control plan. | Flexible but requires CLI/configuration and careful single-machine volume placement; scaling to multiple instances does not make one local Chroma DB shared. |
| **Azure Container Apps** | Runs container apps with a managed ingress/service model. | Microsoft's storage documentation distinguishes replica-scoped `EmptyDir` (lifetime of replica) from persistent Azure Files mounts. Configure Azure Files for Chroma; do not use `EmptyDir` for durable index data. | Container Apps has a secrets feature; configure access restrictions/identity and keep the API key in a secret, not plain revision config. | Fits teams already using Azure; more Azure resource and storage setup than a small demo platform. Validate Azure Files performance and mount permissions for Chroma. |

Official documentation:

- [Render Docker deploys](https://render.com/docs/docker), [persistent disks](https://render.com/docs/disks), [environment variables](https://render.com/docs/configure-environment-variables), and [web services](https://render.com/docs/web-services).
- [Fly Launch](https://docs.fly.io/launch/), [volume overview](https://docs.fly.io/volumes/overview/), [app secrets](https://docs.fly.io/apps/secrets/), and [app configuration](https://docs.fly.io/reference/configuration/).
- [Azure Container Apps storage mounts](https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts) and [secrets](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets).

Before proceeding, choose one platform based on account familiarity, budget, identity/access needs, and how you want to operate/backup the persistent data. For a first restricted single-instance demo, Render is the simplest path if its paid persistent disk and access-control options meet your needs; Fly.io is a reasonable alternative if comfortable managing a single machine and volume; Azure is the better fit when the project should use existing Azure governance and storage.

## Remaining deployment steps

1. Choose a hosting provider and confirm account, region, pricing, storage, and access controls.
2. Build the image locally and confirm the health check and demo workflow.
3. Create a persistent volume and configure `CLOUDSHIELD_VECTOR_DB_DIR` to its mount.
4. Configure authentication/private access and TLS before inviting demo users.
5. Provide a locally managed Ollama service for explanations; do not expose it to the internet.
6. Deploy, verify restart persistence and access restrictions, then document the live endpoint privately.

No cloud resources were created and no deployment was performed during this work.
