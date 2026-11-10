@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

python scripts\verify_gost_standards.py %*

echo.
pause
