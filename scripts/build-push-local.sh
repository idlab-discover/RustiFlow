#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

GHCR_USER="${GHCR_USER:-Str-Gen}"
GHCR_REGISTRY="${GHCR_REGISTRY:-ghcr.io}"
GHCR_OWNER="${GHCR_OWNER:-str-gen}"
IMAGE_NAME="${IMAGE_NAME:-rustiflow}"
PLATFORM="${PLATFORM:-linux/amd64}"
BUILDER_NAME="${BUILDER_NAME:-rustiflow-builder}"

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD)"
BRANCH_TAG="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD | tr '[:upper:]' '[:lower:]' | tr '/' '-')"
IMAGE_REF="$GHCR_REGISTRY/$GHCR_OWNER/$IMAGE_NAME"

echo "Using existing Docker login for $GHCR_REGISTRY as $GHCR_USER"

docker buildx create --name "$BUILDER_NAME" --use >/dev/null 2>&1 || docker buildx use "$BUILDER_NAME"
docker buildx inspect --bootstrap

echo "Building and pushing $IMAGE_REF for $PLATFORM"
docker buildx build \
    --progress plain \
    --platform "$PLATFORM" \
    --provenance false \
    --sbom false \
    -f "$REPO_ROOT/Dockerfile" \
    -t "$IMAGE_REF:sha-$GIT_SHA" \
    --load \
    "$REPO_ROOT"
docker tag "$IMAGE_REF:sha-$GIT_SHA" "$IMAGE_REF:$BRANCH_TAG"
docker push "$IMAGE_REF:sha-$GIT_SHA"
docker push "$IMAGE_REF:$BRANCH_TAG"

echo "Building and pushing slim variant for $PLATFORM"
docker buildx build \
    --progress plain \
    --platform "$PLATFORM" \
    --provenance false \
    --sbom false \
    -f "$REPO_ROOT/Dockerfile-slim" \
    -t "$IMAGE_REF:sha-$GIT_SHA-slim" \
    --load \
    "$REPO_ROOT"
docker tag "$IMAGE_REF:sha-$GIT_SHA-slim" "$IMAGE_REF:$BRANCH_TAG-slim"
docker push "$IMAGE_REF:sha-$GIT_SHA-slim"
docker push "$IMAGE_REF:$BRANCH_TAG-slim"

echo "Pushed:"
echo "  $IMAGE_REF:sha-$GIT_SHA"
echo "  $IMAGE_REF:$BRANCH_TAG"
echo "  $IMAGE_REF:sha-$GIT_SHA-slim"
echo "  $IMAGE_REF:$BRANCH_TAG-slim"
