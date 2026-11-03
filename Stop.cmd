@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
"sservcli.exe" stop
set "SSERVCLI_EXIT=%errorlevel%"
popd
exit /b %SSERVCLI_EXIT%
