@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
if exist ".venv\Scripts\python.exe" goto environment
where py >nul 2>nul
if errorlevel 1 goto python
py -3 -m sservcli.windows_launcher --setup
if not errorlevel 1 goto success
:python
where python >nul 2>nul
if errorlevel 1 goto requirements
python -m sservcli.windows_launcher --setup
if errorlevel 1 goto requirements
goto success
:environment
".venv\Scripts\python.exe" -m sservcli.windows_launcher --setup
if errorlevel 1 goto requirements
:verify
".venv\Scripts\python.exe" -m sservcli.windows_launcher --check
if errorlevel 1 goto requirements
:success
popd
exit /b 0
:requirements
echo Install Python 3.11 or newer with Tcl/Tk and the launcher from https://www.python.org/downloads/windows/
echo Enable OpenSSH Client in Windows Optional Features. No pip packages or compilation are needed.
popd
exit /b 1
