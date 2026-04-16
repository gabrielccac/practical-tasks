#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Simple GCP deploy wrapper.

Required environment variables:
  PROJECT_ID     GCP project id
  REGION         GCP region (e.g. us-central1)
  SERVICE_NAME   Cloud Run service or Function name

Optional environment variables:
  MODE                     run (default) or functions

  # MODE=run (Docker image -> Cloud Run)
  IMAGE                    Full image URL (required for run mode)
  ALLOW_UNAUTHENTICATED    true (default) or false
  PORT                     Container port (default: 8080)

  # MODE=functions (source -> Cloud Functions 2nd gen)
  SOURCE                   Source directory (default: .)
  RUNTIME                  Runtime, e.g. nodejs22 (required for functions mode)
  ENTRY_POINT              Function entry point (required for functions mode)
  HTTP_TRIGGER             true (default) or false
  EVENT_TRIGGER_FLAGS      Raw trigger flags when HTTP_TRIGGER=false

Examples:
  PROJECT_ID=my-proj REGION=us-central1 SERVICE_NAME=capture \
  IMAGE=us-central1-docker.pkg.dev/my-proj/apps/capture:latest \
  ./scripts/deploy-gcp.sh

  MODE=functions PROJECT_ID=my-proj REGION=us-central1 SERVICE_NAME=capture-fn \
  RUNTIME=nodejs22 ENTRY_POINT=handler SOURCE=. \
  ./scripts/deploy-gcp.sh
USAGE
}

is_true() {
  [[ "${1:-}" == "true" || "${1:-}" == "1" || "${1:-}" == "yes" ]]
}

MODE="${MODE:-run}"
PROJECT_ID="${PROJECT_ID:-}"
REGION="${REGION:-}"
SERVICE_NAME="${SERVICE_NAME:-}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$PROJECT_ID" || -z "$REGION" || -z "$SERVICE_NAME" ]]; then
  echo "Missing required values: PROJECT_ID, REGION and SERVICE_NAME must be set." >&2
  usage
  exit 1
fi

if ! command -v gcloud >/dev/null 2>&1; then
  echo "gcloud CLI is required but not found in PATH." >&2
  exit 1
fi

if [[ "$MODE" == "run" ]]; then
  IMAGE="${IMAGE:-}"
  if [[ -z "$IMAGE" ]]; then
    echo "MODE=run requires IMAGE." >&2
    exit 1
  fi

  ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-true}"
  PORT="${PORT:-8080}"

  cmd=(
    gcloud run deploy "$SERVICE_NAME"
    --project "$PROJECT_ID"
    --region "$REGION"
    --platform managed
    --image "$IMAGE"
    --port "$PORT"
  )

  if is_true "$ALLOW_UNAUTHENTICATED"; then
    cmd+=(--allow-unauthenticated)
  else
    cmd+=(--no-allow-unauthenticated)
  fi

  echo "Deploying Cloud Run service '$SERVICE_NAME' from image '$IMAGE'..."
  "${cmd[@]}"
  echo "Cloud Run deploy finished."
  exit 0
fi

if [[ "$MODE" == "functions" ]]; then
  SOURCE="${SOURCE:-.}"
  RUNTIME="${RUNTIME:-}"
  ENTRY_POINT="${ENTRY_POINT:-}"
  HTTP_TRIGGER="${HTTP_TRIGGER:-true}"
  ALLOW_UNAUTHENTICATED="${ALLOW_UNAUTHENTICATED:-true}"
  EVENT_TRIGGER_FLAGS="${EVENT_TRIGGER_FLAGS:-}"

  if [[ -z "$RUNTIME" || -z "$ENTRY_POINT" ]]; then
    echo "MODE=functions requires RUNTIME and ENTRY_POINT." >&2
    exit 1
  fi

  cmd=(
    gcloud functions deploy "$SERVICE_NAME"
    --gen2
    --project "$PROJECT_ID"
    --region "$REGION"
    --source "$SOURCE"
    --runtime "$RUNTIME"
    --entry-point "$ENTRY_POINT"
  )

  if is_true "$HTTP_TRIGGER"; then
    cmd+=(--trigger-http)
    if is_true "$ALLOW_UNAUTHENTICATED"; then
      cmd+=(--allow-unauthenticated)
    else
      cmd+=(--no-allow-unauthenticated)
    fi
  else
    if [[ -z "$EVENT_TRIGGER_FLAGS" ]]; then
      echo "Set EVENT_TRIGGER_FLAGS when HTTP_TRIGGER=false (example: --trigger-topic=my-topic)." >&2
      exit 1
    fi

    # shellcheck disable=SC2206
    extra_flags=( $EVENT_TRIGGER_FLAGS )
    cmd+=("${extra_flags[@]}")
  fi

  echo "Deploying Cloud Function '$SERVICE_NAME' from source '$SOURCE'..."
  "${cmd[@]}"
  echo "Cloud Functions deploy finished."
  exit 0
fi

echo "Invalid MODE='$MODE'. Expected 'run' or 'functions'." >&2
usage
exit 1
