#!/usr/bin/env bash
# CYBERDUDEBIVASH AI Security Hub — Deployment Script v185.1
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}🚀 CYBERDUDEBIVASH ARMY Deployment v185.1${NC}"

# Validate tests first
echo -e "${YELLOW}▶ Running validation suite...${NC}"
python test_hotfix.py || { echo -e "${RED}❌ Tests failed. Aborting deploy.${NC}"; exit 1; }

# Deploy options
case "${1:-all}" in
  backend|all)
    echo -e "${YELLOW}▶ Deploying backend...${NC}"
    # Replace with your actual deploy command:
    # scp cyberdudebivash_army_backend.py user@your-vps:/app/
    # ssh user@your-vps "cd /app && pip install -r requirements.txt && systemctl restart army-api"
    echo -e "${GREEN}✅ Backend deploy command placeholder executed.${NC}"
    ;;
  worker|all)
    echo -e "${YELLOW}▶ Deploying Cloudflare Worker...${NC}"
    if command -v wrangler &> /dev/null; then
      wrangler deploy worker/index.js --name cyberdudebivash-army
    else
      echo -e "${RED}⚠️ wrangler not installed. Install: npm install -g wrangler${NC}"
      exit 1
    fi
    ;;
  frontend|all)
    echo -e "${YELLOW}▶ Deploying frontend...${NC}"
    # Replace with your actual static host deploy:
    # aws s3 sync . s3://your-bucket --exclude "*" --include "index.html"
    echo -e "${GREEN}✅ Frontend deploy command placeholder executed.${NC}"
    ;;
esac

echo -e "${GREEN}🎉 Deployment complete.${NC}"
