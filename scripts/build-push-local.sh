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

# Build the release bundle once, then install that exact bundle into both
# variants, as the GHCR workflow does.
BUNDLE_DIR="$(mktemp -d)"
trap 'rm -rf -- "$BUNDLE_DIR"' EXIT
echo "Building the release bundle for $PLATFORM"
docker buildx build \
    --progress plain \
    --platform "$PLATFORM" \
    --target bundle \
    --build-arg "RUSTIFLOW_COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD)" \
    --build-arg "SOURCE_DATE_EPOCH=$(git -C "$REPO_ROOT" log -1 --format=%ct)" \
    --output "type=local,dest=$BUNDLE_DIR" \
    "$REPO_ROOT"

for variant in default slim; do
    suffix=""
    [ "$variant" = slim ] && suffix="-slim"
    echo "Building and pushing the $variant variant of $IMAGE_REF for $PLATFORM"
    docker buildx build \
        --progress plain \
        --platform "$PLATFORM" \
        --provenance false \
        --sbom false \
        --target "$variant" \
        --build-context "bundle=$BUNDLE_DIR" \
        -t "$IMAGE_REF:sha-$GIT_SHA$suffix" \
        --load \
        "$REPO_ROOT"
    docker tag "$IMAGE_REF:sha-$GIT_SHA$suffix" "$IMAGE_REF:$BRANCH_TAG$suffix"
    docker push "$IMAGE_REF:sha-$GIT_SHA$suffix"
    docker push "$IMAGE_REF:$BRANCH_TAG$suffix"
done

echo "Pushed:"
echo "  $IMAGE_REF:sha-$GIT_SHA"
echo "  $IMAGE_REF:$BRANCH_TAG"
echo "  $IMAGE_REF:sha-$GIT_SHA-slim"
echo "  $IMAGE_REF:$BRANCH_TAG-slim"
