#!/usr/bin/env bash
set -euo pipefail

# Build the enclave Docker image and extract artifact hash.
#
# NOTE: artifact_hash is the sha256 of the binary inside the image.
# It is NOT the SNP measurement. Reproducible SNP measurement requires
# platform-specific tooling not yet integrated.

IMAGE_NAME="${IMAGE_NAME:-av-tee-relay}"
IMAGE_TAG="${IMAGE_TAG:-$(git rev-parse --short HEAD)}"

echo "Building enclave image: ${IMAGE_NAME}:${IMAGE_TAG}"
docker build -f Dockerfile.enclave -t "${IMAGE_NAME}:${IMAGE_TAG}" .

# Extract artifact hash (sha256 of the tee-relay binary)
CONTAINER_ID=$(docker create "${IMAGE_NAME}:${IMAGE_TAG}")
docker cp "${CONTAINER_ID}:/usr/local/bin/tee-relay" /tmp/tee-relay-artifact
docker rm "${CONTAINER_ID}" > /dev/null

ARTIFACT_HASH=$(sha256sum /tmp/tee-relay-artifact | awk '{print $1}')
rm /tmp/tee-relay-artifact

# OCI image digest
OCI_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null || echo "not pushed")

echo ""
echo "=== Enclave Build Summary ==="
echo "image:         ${IMAGE_NAME}:${IMAGE_TAG}"
echo "artifact_hash: ${ARTIFACT_HASH}"
echo "oci_digest:    ${OCI_DIGEST}"
echo ""
echo "NOTE: artifact_hash is the sha256 of the binary. It is NOT the SNP measurement."
