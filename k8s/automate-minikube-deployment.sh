#!/bin/bash

set -e
set -a
[ -f .env ] && source .env
set +a
# Check if GHCR_PAT is set
if [ -z "$GHCR_PAT" ]; then
  echo "⚠️ GHCR_PAT is not set. Please set it in your .env file."
  exit 1
fi
# Check if minikube is running
if ! minikube status &> /dev/null; then
  echo "⚠️ Minikube is not running. Please start it first."
  exit 1
fi
# Set variables
GHCR_USER=nlinh2911
IMAGE_TAG=latest
K8S_DIR=./k8s
IMAGES=("auth-service" "auth-db")

echo "=====Automating Minikube deployment for auth-service and auth-db====="
echo "🔐 Logging into GHCR..."
echo "$GHCR_PAT" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

# Ensure Minikube is using the correct Docker environment
# Your image is built directly inside Minikube's Docker and available for pods to use.
eval $(minikube docker-env)

for IMAGE in "${IMAGES[@]}"; do
  GHCR_IMAGE="ghcr.io/$GHCR_USER/$IMAGE:$IMAGE_TAG"
  LOCAL_TAG="$IMAGE:$IMAGE_TAG"

  echo "⬇️ Pulling $GHCR_IMAGE"
  docker pull "$GHCR_IMAGE"

  echo "🏷 Retagging as $LOCAL_TAG"
  # echo "Debug: GHCR_IMAGE=$GHCR_IMAGE"
  # echo "Debug: LOCAL_TAG=$LOCAL_TAG"
  # docker images | grep "$GHCR_USER" || echo "⚠️ Image $GHCR_IMAGE not found in local Docker"
  docker tag "$GHCR_IMAGE" "$LOCAL_TAG"

#   echo "📦 Loading $LOCAL_TAG into Minikube"
#   minikube image load "$LOCAL_TAG"

  echo "✅ Done loading images into Minikube Docker"
  
  # Optional: remove GHCR-tagged images after retagging
  echo "🗑️ Removing GHCR images from local Docker"
  docker rmi ghcr.io/$GHCR_USER/auth-service:$IMAGE_TAG || true
  docker rmi ghcr.io/$GHCR_USER/auth-db:$IMAGE_TAG || true
  
  # Clean up dangling images
  echo "🧹 Cleaning up unused Docker images..."
  docker image prune -f

  echo
done

echo "🚀 Applying Kubernetes manifests from $K8S_DIR..."
minikube kubectl -- apply -f "$K8S_DIR"

echo "🔁 Restarting auth-service Deployment..."
minikube kubectl -- rollout restart deployment auth-service --namespace=stox

echo "🔁 Restarting auth-db StatefulSet..."
minikube kubectl -- patch statefulset auth-db --namespace=stox \
  -p '{"spec":{"template":{"metadata":{"annotations":{"restartedAt":"'"$(date)"'"}}}}}'

echo "✅ Rollout complete!!!!"
