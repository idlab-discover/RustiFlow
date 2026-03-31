#!/usr/bin/env bash
set -euo pipefail

GHCR_USER="${GHCR_USER:-Str-Gen}"
GHCR_REGISTRY="${GHCR_REGISTRY:-ghcr.io}"
GHCR_OWNER="${GHCR_OWNER:-idlab-discover}"
IMAGE_NAME="${IMAGE_NAME:-rustiflow}"
PLATFORM="${PLATFORM:-linux/amd64}"
BUILDER_NAME="${BUILDER_NAME:-rustiflow-builder}"
TOKEN_FILE="${GHCR_TOKEN_FILE:-/home/strgenix/postdoc/projects/AIDE-FL/rgbcore-classic-arch.key}"

if [[ ! -f "$TOKEN_FILE" ]]; then
    echo "missing GHCR token file: $TOKEN_FILE" >&2
    exit 1
fi

GIT_SHA="$(git rev-parse --short HEAD)"
BRANCH_TAG="$(git rev-parse --abbrev-ref HEAD | tr '[:upper:]' '[:lower:]' | tr '/' '-')"
IMAGE_REF="$GHCR_REGISTRY/$GHCR_OWNER/$IMAGE_NAME"

echo "Logging in to $GHCR_REGISTRY as $GHCR_USER"
cat "$TOKEN_FILE" | docker login "$GHCR_REGISTRY" -u "$GHCR_USER" --password-stdin

docker buildx create --name "$BUILDER_NAME" --use >/dev/null 2>&1 || docker buildx use "$BUILDER_NAME"
docker buildx inspect --bootstrap

echo "Building and pushing $IMAGE_REF for $PLATFORM"
docker buildx build \
    --platform "$PLATFORM" \
    -f Dockerfile \
    -t "$IMAGE_REF:sha-$GIT_SHA" \
    -t "$IMAGE_REF:$BRANCH_TAG" \
    --push \
    .

echo "Building and pushing slim variant for $PLATFORM"
docker buildx build \
    --platform "$PLATFORM" \
    -f Dockerfile-slim \
    -t "$IMAGE_REF:sha-$GIT_SHA-slim" \
    -t "$IMAGE_REF:$BRANCH_TAG-slim" \
    --push \
    .

echo "Pushed:"
echo "  $IMAGE_REF:sha-$GIT_SHA"
echo "  $IMAGE_REF:$BRANCH_TAG"
echo "  $IMAGE_REF:sha-$GIT_SHA-slim"
echo "  $IMAGE_REF:$BRANCH_TAG-slim"
