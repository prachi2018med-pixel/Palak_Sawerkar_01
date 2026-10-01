#!/usr/bin/env bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000 &
sleep 2
export BACKEND_URL=${BACKEND_URL:-"http://localhost:8000"}
streamlit run frontend/app.py --server.port $PORT --server.address 0.0.0.0
