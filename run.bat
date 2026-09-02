@echo off
title TrustGuard AI - SIH26228
cd /d "%~dp0"

echo [1/2] Starting backend...
start "TrustGuard Backend" cmd /k "cd /d "%~dp0backend" && if not exist .venv\Scripts\python.exe python -m venv .venv && .venv\Scripts\python.exe -m pip install -r requirements.txt && if not exist .env copy .env.example .env >nul && .venv\Scripts\python.exe -m uvicorn app.main:app --reload"

timeout /t 3 /nobreak >nul

echo [2/2] Starting frontend...
start "TrustGuard Frontend" cmd /k "cd /d "%~dp0frontend" && if not exist node_modules npm install && npm run dev"

timeout /t 5 /nobreak >nul
start http://localhost:5173

echo.
echo Backend:  http://127.0.0.1:8000/docs
echo Frontend: http://localhost:5173
echo.
pause
