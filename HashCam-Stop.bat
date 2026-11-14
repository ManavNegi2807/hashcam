@echo off
rem Double-click to stop the recorder, console and website that HashCam.bat started.
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0tools\launcher.ps1" -Stop
