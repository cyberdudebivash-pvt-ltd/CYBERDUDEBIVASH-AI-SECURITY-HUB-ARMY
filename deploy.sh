#!/bin/bash
# CYBERDUDEBIVASH® AI SECURITY HUB ARMY — Deployment Script
# Run on your VPS / cloud server

echo "🔥 Deploying CYBERDUDEBIVASH AI SECURITY HUB ARMY..."

# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the server
# For development:
# python cyberdudebivash_army_backend.py

# For production (with auto-restart):
# Using PM2:
# pm2 start "uvicorn cyberdudebivash_army_backend:app --host 0.0.0.0 --port 8080" --name "cyberdudebivash-army"

# Using systemd (recommended for production):
# sudo nano /etc/systemd/system/cyberdudebivash-army.service
# Add the following:
# [Unit]
# Description=CYBERDUDEBIVASH AI SECURITY HUB ARMY
# After=network.target
# 
# [Service]
# User=ubuntu
# WorkingDirectory=/var/www/cyberdudebivash-army
# ExecStart=/usr/bin/python3 -m uvicorn cyberdudebivash_army_backend:app --host 0.0.0.0 --port 8080
# Restart=always
# 
# [Install]
# WantedBy=multi-user.target
# 
# Then run:
# sudo systemctl enable cyberdudebivash-army
# sudo systemctl start cyberdudebivash-army

echo "✅ Deployment complete!"
echo "🌐 Dashboard: http://your-server-ip:8080/"
echo "📡 API Health: http://your-server-ip:8080/api/v1/health"
echo "📊 API Stats: http://your-server-ip:8080/api/v1/stats"
echo "🎯 API Threats: http://your-server-ip:8080/api/v1/threats"
