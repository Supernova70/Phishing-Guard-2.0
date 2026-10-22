#!/bin/bash
# =============================================================================
#  Phishing Guard — Graceful Shutdown
# =============================================================================
#  Run this before stopping your EC2 instance to avoid data corruption.
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Phishing Guard — Shutting down...${NC}"

COMPOSE="docker compose -f docker-compose.prod.yml"
sg docker -c "$COMPOSE down"

if [ -n "$(sg docker -c "$COMPOSE ps -q")" ]; then
    echo -e "${RED}ERROR: containers are still running after shutdown.${NC}"
    sg docker -c "$COMPOSE ps"
    exit 1
fi

echo ""
echo -e "${GREEN}All containers stopped safely. Data volumes were preserved.${NC}"
echo -e "${GREEN}You can now stop your EC2 instance.${NC}"
