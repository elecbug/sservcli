@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
where py >nul 2>nul
if errorlevel 1 goto python
py -3 -m sservcli.windows_launcher --start --config "%~dp0services.json"
if not errorlevel 1 goto success
:python
where python >nul 2>nul
if errorlevel 1 goto requirements
python -m sservcli.windows_launcher --start --config "%~dp0services.json"
if errorlevel 1 goto requirements
:success
popd
exit /b 0
:requirements
echo Run Build.cmd to check Python, Tcl/Tk, and OpenSSH Client.
pause
popd
exit /b 1
