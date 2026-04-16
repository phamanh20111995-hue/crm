@echo off
cd /d %~dp0\..
where py >nul 2>nul
if %errorlevel%==0 (
  py scripts\run_demo.py
) else (
  python scripts\run_demo.py
)
