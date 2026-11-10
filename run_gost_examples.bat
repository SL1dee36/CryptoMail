@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
call verify_gost.bat %*
