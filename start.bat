@echo off
setlocal EnableExtensions
title HACKERADE Scanner
cd /d "%~dp0"

set "PORT=3000"
set "URL=http://localhost:%PORT%"
set "OPEN_BROWSER=1"
if /i "%~1"=="--no-browser" set "OPEN_BROWSER=0"
if /i "%~1"=="-n" set "OPEN_BROWSER=0"

where node >nul 2>nul
if errorlevel 1 goto :no_node

call :check_up
if not errorlevel 1 goto :already_running

if not exist "node_modules" (
  echo [setup] node_modules missing, installing dependencies...
  call npm.cmd install
  if errorlevel 1 goto :install_failed
)

if not exist ".env.local" echo [warn] .env.local not found - VIRUSTOTAL_API_KEY is required for scans.

if "%OPEN_BROWSER%"=="1" (
  start "" /b powershell -NoProfile -WindowStyle Hidden -Command "for ($i = 0; $i -lt 240; $i++) { try { $c = [Net.Sockets.TcpClient]::new('127.0.0.1', %PORT%); $c.Close(); Start-Process '%URL%'; break } catch { Start-Sleep -Milliseconds 500 } }"
  echo [web] Browser will open automatically when the server is ready.
)

echo [info] Starting HACKERADE scanner on %URL%
echo [info] Press Ctrl+C in this window to stop it.
echo.

set /a RETRIES=0
:serve
call npm.cmd run dev <nul
if not errorlevel 1 goto :done
call :check_up
if not errorlevel 1 goto :done
set /a RETRIES+=1
if %RETRIES% GEQ 3 goto :serve_failed
echo.
echo [info] Next.js exited early, retrying (%RETRIES%/3)...
timeout /t 2 /nobreak >nul
goto :serve

:already_running
echo [info] Scanner is already running at %URL%
if "%OPEN_BROWSER%"=="1" (
  start "" "%URL%"
  echo [web] Opened it in your browser.
) else (
  echo [info] Browser skipped because --no-browser was passed.
)
exit /b 0

:done
echo.
echo [info] Scanner stopped.
exit /b 0

:serve_failed
echo.
echo [error] Could not start the scanner. Scroll up for the error output.
pause
exit /b 1

:install_failed
echo.
echo [error] npm install failed. Check your internet connection and try again.
pause
exit /b 1

:no_node
echo.
echo [error] Node.js was not found. Install it from https://nodejs.org and try again.
pause
exit /b 1

:check_up
powershell -NoProfile -Command "try { $c = [Net.Sockets.TcpClient]::new('127.0.0.1', %PORT%); $c.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
exit /b %ERRORLEVEL%
