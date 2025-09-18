#!/bin/bash
# Health check script for GhostCP API

set -e

# Check if the API responds to health endpoint
if curl -f -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "API health check passed"
    exit 0
else
    echo "API health check failed"
    exit 1
fi