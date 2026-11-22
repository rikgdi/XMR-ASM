@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem =========================================================================
rem  XMRASM build script (MASM/ML64 + LINK, Windows x86-64)
rem  Usage: build.bat [clean]
rem =========================================================================

set "ROOT=%~dp0"
set "SRC=%ROOT%src"
set "OBJ=%ROOT%obj"
set "OUT=%ROOT%xmrasm.exe"

rem ---- locate Visual Studio / Windows SDK ---------------------------------
if defined VCVARS64 goto :vcvars_ok
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINSTALL=%%I"
)
if defined VSINSTALL if exist "!VSINSTALL!\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS64=!VSINSTALL!\VC\Auxiliary\Build\vcvars64.bat"
:vcvars_ok
if not defined VCVARS64 (
    echo error: vcvars64.bat not found; set VCVARS64 to its full path.
    exit /b 1
)

if /i "%~1"=="clean" (
    if exist "%OBJ%" rmdir /s /q "%OBJ%"
    if exist "%OUT%" del /f /q "%OUT%"
    echo clean done.
    exit /b 0
)

if not exist "%OBJ%" mkdir "%OBJ%"

call "%VCVARS64%" >nul
if errorlevel 1 (
    echo error: vcvars64 failed.
    exit /b 1
)

rem ---- Windows SDK library path (vcvars may not register it) -------------
set "SDKLIB="
for /d %%D in ("%ProgramFiles(x86)%\Windows Kits\10\Lib\10.*") do set "SDKLIB=%%~fD"
set "LIBPATH_EXTRA="
if defined SDKLIB set "LIBPATH_EXTRA=/LIBPATH:"%SDKLIB%\um\x64" /LIBPATH:"%SDKLIB%\ucrt\x64""

rem ---- assemble -----------------------------------------------------------
set "MODULES="
for %%F in ("%SRC%\*.asm") do set "MODULES=!MODULES! %%~nF"

for %%M in (!MODULES!) do (
    echo [asm] %%M.asm
    ml64 /nologo /c /Fo "%OBJ%\%%M.obj" "%SRC%\%%M.asm"
    if errorlevel 1 exit /b 1
)

rem ---- link ---------------------------------------------------------------
rem  NB: link with the static CRT + default entry (mainCRTStartup).  A bare
rem  /ENTRY:main no-CRT image is flagged and blocked by Smart App Control.
set "OBJECTS="
for %%F in ("%OBJ%\*.obj") do set "OBJECTS=!OBJECTS! "%OBJ%\%%~nF.obj""

echo [link] %OUT%
link /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 /OUT:"%OUT%" !OBJECTS! %LIBPATH_EXTRA% kernel32.lib user32.lib ws2_32.lib advapi32.lib libcmt.lib libvcruntime.lib libucrt.lib
if errorlevel 1 exit /b 1

echo build ok: %OUT%
endlocal
