@echo off
rem Double-click to start Hascham. It asks for your TinyFish key (hidden), then opens the page.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_hascham.ps1"
pause
