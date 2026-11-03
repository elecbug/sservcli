@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
where go >nul 2>nul
if errorlevel 1 goto requirements
set "CGO_ENABLED=0"
set "GOWORK=off"
pushd client || goto failed
go build -trimpath -ldflags="-s -w" -o ..\sservcli.exe ./cmd/sservcli
if errorlevel 1 goto buildfailed
go build -trimpath -ldflags="-s -w -H=windowsgui" -o ..\sservcli-askpass.exe ./cmd/askpass
if errorlevel 1 goto buildfailed
popd
echo Built sservcli.exe. Enable Windows OpenSSH Client and run Start.cmd.
popd
exit /b 0
:buildfailed
popd
:failed
popd
exit /b 1
:requirements
echo Install Go from https://go.dev/dl/ to build the source ZIP.
echo A ZIP that already contains sservcli.exe needs no Go or Python installation.
popd
exit /b 1
