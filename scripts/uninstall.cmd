@echo off
setlocal EnableExtensions
title usbbackup-r2 uninstaller

REM ===========================================================================
REM  usbbackup-r2 - uninstaller for Windows targets.
REM ---------------------------------------------------------------------------
REM  This is the entry point for removal only. It does NOT duplicate the code:
REM  the revert / purge logic lives in install.cmd's UNDO flow, which is the
REM  single implementation that gets tested. Two copies of an uninstaller would
REM  drift apart, and the copy that drifts is always the one that runs on the
REM  machine that matters.
REM
REM  Usage:
REM    uninstall.cmd            revert the delete-deny ACL and the failure
REM                             actions, keep the service and the files
REM    uninstall.cmd /PURGE     all of the above, plus stop and delete the
REM                             service and delete D:\backup\usbbackup-r2
REM    uninstall.cmd /DRYRUN    print the plan, change nothing
REM    uninstall.cmd /YES       do not pause at the end
REM
REM  Needs administrator rights; it re-launches itself through UAC if needed.
REM
REM  NOTE: keep this file ASCII-only with CRLF line endings.
REM ===========================================================================

set "SELF=%~dp0install.cmd"

if not exist "%SELF%" (
    echo [x] install.cmd was not found next to this script:
    echo     %SELF%
    echo     put uninstall.cmd in the same directory as install.cmd.
    echo.
    pause
    exit /b 1
)

echo ===========================================================================
echo    usbbackup-r2  -  uninstaller
echo ===========================================================================
echo    delegate : %SELF%
echo    action   : revert ACL + failure actions%1
if /i "%~1"=="/PURGE" echo               plus remove the service and the files
echo ===========================================================================
echo.

REM --yes is appended so the delegated run never blocks waiting for a keypress
REM when this script is called from an automated rollout.
call "%SELF%" %* /YES
exit /b %ERRORLEVEL%
