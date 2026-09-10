@echo off
setlocal
title Pair - Developer Preview
cd /d "%~dp0"
echo Pair Developer Preview - builds the latest UI before opening
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\dev.ps1"
if errorlevel 1 pause
