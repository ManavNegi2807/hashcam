@echo off
rem Double-click once to add the HashCam extension to Chrome (a few clicks, no typing).
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0tools\launcher.ps1" -ExtensionSetup
