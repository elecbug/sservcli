@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
if exist ".venv\Scripts\python.exe" goto environment
where py >nul 2>nul
if errorlevel 1 goto python
py -3 -m sservcli.windows_launcher --start --config "%~dp0services.json"
if not errorlevel 1 goto success
:python
where python >nul 2>nul
if errorlevel 1 goto requirements
python -m sservcli.windows_launcher --start --config "%~dp0services.json"
if errorlevel 1 goto requirements
goto success
:environment
".venv\Scripts\python.exe" -m sservcli.windows_launcher --start --config "%~dp0services.json"
if errorlevel 1 goto requirements
:success
popd
exit /b 0
:requirements
echo Run Build.cmd once to install the Python SSH dependencies. Python with Tcl/Tk is required.
pause
popd
exit /b 1
