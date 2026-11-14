@echo off
rem Double-click to start HashCam: the recorder, the console and the website. Nothing to type.
rem The pairing token for the browser extension is copied to your clipboard.
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0tools\launcher.ps1"
