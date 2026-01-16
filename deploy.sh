#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

NAMESPACE="system-experio"
IMAGE_NAME="registry.experioservices.com/lm9dem"
VERSION=${1:-latest}

echo -e "${BLUE}Building and deploying lm9dem dashboard...${NC}"
echo "Image: ${IMAGE_NAME}:${VERSION}"
echo ""

# Build Docker image
echo -e "${BLUE}[1/4] Building Docker image...${NC}"
docker build -t ${IMAGE_NAME}:${VERSION} .

# Push to registry
echo -e "${BLUE}[2/4] Pushing to registry...${NC}"
docker push ${IMAGE_NAME}:${VERSION}

# Update deployment with new image if not latest
if [ "$VERSION" != "latest" ]; then
    echo -e "${BLUE}[3/4] Updating deployment with version ${VERSION}...${NC}"
    sed "s|image: registry.experioservices.com/lm9dem:latest|image: registry.experioservices.com/lm9dem:${VERSION}|g" deployment.yaml > deployment-${VERSION}.yaml
    kubectl apply -f deployment-${VERSION}.yaml
    rm deployment-${VERSION}.yaml
else
    echo -e "${BLUE}[3/4] Applying deployment...${NC}"
    kubectl apply -f deployment.yaml
fi

# Wait for rollout
echo -e "${BLUE}[4/4] Waiting for deployment to complete...${NC}"
kubectl rollout status deployment/lm9dem -n ${NAMESPACE} --timeout=300s

echo ""
echo -e "${GREEN}✅ lm9dem deployed successfully!${NC}"
echo ""
echo "Access the dashboard:"
echo "  Port forward: kubectl port-forward -n ${NAMESPACE} service/lm9dem 8080:8080"
echo "  Then visit: http://localhost:8080"
echo ""
echo "Or add to ingress to access via domain."