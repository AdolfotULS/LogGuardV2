@echo off
echo [BD SIMULATOR] Starting PostgreSQL container...
docker compose up -d
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to start. Is Docker running?
    pause
    exit /b 1
)
echo.
echo [OK] Container running on localhost:5432
echo [OK] Logs will appear in .\logs\
echo.
docker compose ps
echo.
pause
