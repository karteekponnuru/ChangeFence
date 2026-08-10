# ChangeFence Playground

The Playground is a small interactive web app backed by the real ChangeFence engine. It is designed for demos, recruiter/technical evaluation, and early product exploration.

## What a visitor can do

1. Toggle a Procurement → Finance delegation and run a real ChangeFence Impact analysis.
2. See the candidate authority graph and the newly reachable `payment.execute` capability.
3. See the external security-owned policy (`FIN-001`) produce a deterministic `BLOCK`.
4. Paste their own baseline, candidate, and policy YAML and run the engine.
5. Run live Runtime checks and receive `ALLOW`, `REVIEW`, or `BLOCK`.

The Playground intentionally does **not** use an external LLM. This keeps the public demo deterministic, cheap, and reproducible.

## Architecture

```text
Browser
  |
  | same-origin HTTPS
  v
FastAPI / Uvicorn
  |-- serves Playground HTML/CSS/JS
  |-- POST /api/analyze
  |-- POST /api/runtime
  |-- GET  /api/example
  |
  v
ChangeFence Python engine
  |-- authority graph
  |-- external policy registry
  |-- Impact
  `-- Runtime
```

There is no database. User YAML is written only to an operating-system temporary directory for the duration of each request and then removed.

## Run locally

```bash
python -m pip install -e ".[web]"
uvicorn changefence.webapp:app --reload --port 8080
```

Open `http://localhost:8080`.

## Run tests

```bash
python -m pip install -e ".[dev]"
pytest
```

## Docker

```bash
docker build -t changefence-playground .
docker run --rm -p 8080:8080 changefence-playground
```

## Google Cloud Run

The repository is packaged as one stateless container, so Cloud Run can scale it down when unused.

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

gcloud run deploy changefence-playground \
  --source . \
  --region us-west1 \
  --allow-unauthenticated \
  --port 8080 \
  --memory 512Mi \
  --cpu 1 \
  --max-instances 3
```

After deployment, Cloud Run returns the public URL.

For a portfolio demo, keep `--max-instances` low to cap accidental cost exposure. Add Cloud Armor/rate limiting or authenticated access before using this endpoint for enterprise or untrusted high-volume workloads.

## Public-demo security boundaries

- Request bodies have explicit size limits.
- YAML is parsed with ChangeFence's safe parser.
- External policy is authoritative when supplied; developer-embedded rules are ignored.
- Policy files cannot contain agent/tool architecture.
- The public Playground does not run Ollama/OpenAI/Bedrock or execute user-provided code.
- User-controlled values rendered in the UI are escaped before HTML insertion.
- The Playground does not issue real human approval leases. Production approval should remain behind an authenticated trusted host/issuer.

## Not production hosting yet

The Playground is a technical MVP. A production service would still need authentication, rate limiting, tenancy isolation, durable policy storage, production approval state, telemetry, and managed secrets/KMS.
