@echo off
echo [BD SIMULATOR] Stopping PostgreSQL container...
docker compose down
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to stop.
    pause
    exit /b 1
)
echo.
echo [OK] Container stopped. Data volume preserved.
echo     To also delete data: docker compose down -v
echo.
pause
