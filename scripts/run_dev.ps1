# CyberTrace AI — Windows dev launcher (PowerShell)
# Run from repo root:  .\scripts\run_dev.ps1

Write-Host "`n🛡️  CyberTrace AI — Development Launcher" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# ── Step 1: Install dependencies ─────────────────────────────────────────────
Write-Host "`n📦  Installing dependencies…" -ForegroundColor Yellow
pip install -r requirements.txt --quiet

# ── Step 2: Seed database ─────────────────────────────────────────────────────
Write-Host "`n🌱  Seeding database…" -ForegroundColor Yellow
python scripts/seed_database.py

# ── Step 3: Start FastAPI backend ─────────────────────────────────────────────
Write-Host "`n⚡  Starting FastAPI backend on http://localhost:8000 …" -ForegroundColor Green
$backend = Start-Process -FilePath "uvicorn" `
    -ArgumentList "backend.main:app --reload --port 8000" `
    -PassThru -WindowStyle Normal

Start-Sleep -Seconds 3

# ── Step 4: Start Streamlit frontend ──────────────────────────────────────────
Write-Host "🖥️   Starting Streamlit dashboard on http://localhost:8501 …" -ForegroundColor Green
$frontend = Start-Process -FilePath "streamlit" `
    -ArgumentList "run frontend/app.py" `
    -PassThru -WindowStyle Normal

Write-Host "`n✅  Both servers are running!" -ForegroundColor Cyan
Write-Host "   Backend:  http://localhost:8000/docs" -ForegroundColor White
Write-Host "   Frontend: http://localhost:8501" -ForegroundColor White
Write-Host "`nPress Ctrl+C or close the terminal windows to stop.`n" -ForegroundColor Gray

# Keep script alive
Wait-Process -Id $backend.Id, $frontend.Id
