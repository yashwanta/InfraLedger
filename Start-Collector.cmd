@echo off
setlocal
cd /d "%~dp0"
if not exist "collector.exe" (
  echo collector.exe is missing. Extract the entire Trinetra-Windows package first.
  pause
  exit /b 1
)
echo Trinetra infrastructure collector
echo Paste the device collector token from the app when prompted.
echo The token is used for this process only and is not saved to a file.
echo.
set /p "TRINETRA_TOKEN=Collector token: "
if not defined TRINETRA_TOKEN (
  echo A collector token is required.
  pause
  exit /b 1
)
set "TRINETRA_SERVER=http://127.0.0.1:5173"
set /p "TRINETRA_SERVER=Server URL [http://127.0.0.1:5173]: "
echo.
echo Keep this window open while discovery runs. Press Ctrl+C to stop.
"%~dp0collector.exe" -server "%TRINETRA_SERVER%" -interval 30s
pause
endlocal
