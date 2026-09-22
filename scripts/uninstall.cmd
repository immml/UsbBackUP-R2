@echo off
setlocal EnableExtensions EnableDelayedExpansion
title usbbackup-r2 uninstaller

REM ===========================================================================
REM  usbbackup-r2 - uninstaller for Windows targets.
REM ---------------------------------------------------------------------------
REM  Running this file with no arguments IS the uninstall: the delete-deny ACL
REM  comes off, the failure actions are cleared, the service is stopped and
REM  deleted, and the target directory is removed.
REM
REM  It used to default to a "soft" revert that kept the service and the files
REM  and required /PURGE to really remove them. That was wrong. A file named
REM  uninstall.cmd is expected to uninstall when it is double-clicked, and a
REM  run that ends in "DONE" while the service is still RUNNING reads - quite
REM  reasonably - as "it will not uninstall".
REM
REM  Usage:
REM    uninstall.cmd            full removal (this is the default)
REM    uninstall.cmd /KEEP      revert the ACL and the failure actions only,
REM                             keep the service and the files
REM    uninstall.cmd /DRYRUN    print the plan, change nothing
REM    uninstall.cmd /YES       do not pause at the end
REM
REM  This is the entry point for removal only. It does NOT duplicate the code:
REM  the revert / purge logic lives in install.cmd's UNDO flow, which is the
REM  single implementation that gets tested. Two copies of an uninstaller
REM  would drift apart, and the copy that drifts is always the one that runs
REM  on the machine that matters.
REM
REM  Needs administrator rights; the delegated run raises a UAC prompt if the
REM  current session does not have them.
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

REM ---- rebuild the switch list for install.cmd -------------------------------
REM  /PURGE by default, /UNDO for /KEEP. Defaulting to /PURGE, and the switch
REM  going through a whitelist, are both deliberate:
REM
REM  - /PURGE, because a file named uninstall.cmd is expected to uninstall.
REM  - /UNDO for /KEEP, because install.cmd only enters its revert flow when
REM    /UNDO or /PURGE is present. Dropping /PURGE alone does not turn the run
REM    into a revert, it turns it into a FRESH INSTALL.
REM  - a whitelist, because install.cmd treats any unrecognised argument as
REM    the SOURCE directory. Forwarding a stray switch would aim it at a
REM    directory that does not exist and the removal would quietly do nothing.
set "PURGE_OPT=/PURGE"
set "PASS="
set "ARGS=%*"
if defined ARGS for %%A in (%ARGS%) do (
    if /i "%%~A"=="/KEEP" (
        set "PURGE_OPT=/UNDO"
    ) else if /i "%%~A"=="/DRYRUN" (
        set "PASS=!PASS! /DRYRUN"
    ) else if /i "%%~A"=="/YES" (
        set "PASS=!PASS! /YES"
    ) else if /i "%%~A"=="/NOHARDEN" (
        set "PASS=!PASS! /NOHARDEN"
    ) else (
        echo [x] unrecognised switch: %%~A
        echo     known: /KEEP /DRYRUN /YES
        echo.
        pause
        exit /b 2
    )
)

echo ===========================================================================
echo    usbbackup-r2  -  uninstaller
echo ===========================================================================
echo    delegate : %SELF%
if /i "%PURGE_OPT%"=="/PURGE" (
    echo    action   : revert the ACL, clear the failure actions, stop
    echo               and delete the service, remove D:\backup\usbbackup-r2
) else (
    echo    action   : revert the ACL and the failure actions only - the
    echo               service and the files are KEPT ^(/KEEP^)
)
echo ===========================================================================
echo.

REM --yes is appended so the delegated run never blocks waiting for a keypress
REM when this script is called from an automated rollout.
call "%SELF%" %PURGE_OPT% !PASS! /YES
exit /b %ERRORLEVEL%
