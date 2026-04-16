# Simple GCP deploy helper

Use `scripts/deploy-gcp.sh` for one-command deployments.

## 1) Docker image deployment (Cloud Run)

```bash
PROJECT_ID=my-project \
REGION=us-central1 \
SERVICE_NAME=my-service \
IMAGE=us-central1-docker.pkg.dev/my-project/apps/my-service:latest \
npm run infra:deploy:run
```

Notes:
- This is the path for Docker images.
- Cloud Functions 2nd gen does not deploy directly from arbitrary Docker images.

## 2) Source deployment (Cloud Functions 2nd gen)

```bash
MODE=functions \
PROJECT_ID=my-project \
REGION=us-central1 \
SERVICE_NAME=my-function \
RUNTIME=nodejs22 \
ENTRY_POINT=handler \
SOURCE=. \
npm run infra:deploy:function
```

Optional flags:
- `ALLOW_UNAUTHENTICATED=false`
- `HTTP_TRIGGER=false` with `EVENT_TRIGGER_FLAGS='--trigger-topic=my-topic'`

## Show help

```bash
./scripts/deploy-gcp.sh --help
```
