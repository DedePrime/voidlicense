@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist node_modules call npm install --silent
echo Dashboard: http://localhost:8090
node server.js
pause
