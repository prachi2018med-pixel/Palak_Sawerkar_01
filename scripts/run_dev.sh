#!/usr/bin/env bash
# CyberTrace AI — Unix/macOS dev launcher
# Run from repo root:  bash scripts/run_dev.sh

set -e
echo ""
echo "🛡️  CyberTrace AI — Development Launcher"
echo "=========================================="

echo ""
echo "📦  Installing dependencies…"
pip install -r requirements.txt -q

echo ""
echo "🌱  Seeding database…"
python scripts/seed_database.py

echo ""
echo "⚡  Starting FastAPI backend on http://localhost:8000 …"
uvicorn backend.main:app --reload --port 8000 &
BACKEND_PID=$!

sleep 2

echo "🖥️   Starting Streamlit on http://localhost:8501 …"
streamlit run frontend/app.py &
FRONTEND_PID=$!

echo ""
echo "✅  Both servers running."
echo "   Backend:  http://localhost:8000/docs"
echo "   Frontend: http://localhost:8501"
echo ""
echo "Press Ctrl+C to stop both servers."

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Servers stopped.'" INT TERM
wait $BACKEND_PID $FRONTEND_PID
