@echo off
cd /d "%~dp0"
echo Open http://127.0.0.1:5173 in your browser after the server starts.
echo Press Ctrl+C to stop InfraLedger.
if exist "trinetra.exe" (
  "trinetra.exe" -static dist
) else (
  "outputs\trinetra.exe" -static dist
)
pause
