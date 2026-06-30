#!/bin/bash
echo "🛑 Stopping EDR System..."
pkill -f "uvicorn policy_server"
pkill -f "uvicorn ai_rule_engine"
pkill -f "http.server 5501"
pkill -f "canary.py"
echo "✅ EDR System Stopped!"
