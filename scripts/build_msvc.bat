@echo off
echo ERROR: MSVC builds are no longer supported by the Protocol Analyzer release pipeline.
echo Use: powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\build_dist.ps1"
exit /b 2
