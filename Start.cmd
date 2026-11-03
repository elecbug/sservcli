@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
if not exist "sservcli.exe" goto build
if not exist "sservcli-askpass.exe" goto build
goto launch
:build
call Build.cmd
if errorlevel 1 goto failed
:launch
"sservcli.exe" start
if errorlevel 1 goto failed
"sservcli.exe" ui
echo Manage services at http://127.0.0.1:8000
popd
exit /b 0
:failed
echo Check Windows OpenSSH Client, services.json, and .token beside sservcli.exe.
pause
popd
exit /b 1
