@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ===========================================================================
REM  usbbackup-r2 - deployment helper for Windows targets
REM ---------------------------------------------------------------------------
REM  INSTALL mode (default) - move/install the tool and register the service:
REM    1) stop and delete the existing usbbackup-r2 service (if registered)
REM    2) copy the whole tool directory to D:\backup\usbbackup-r2
REM    3) re-register the service at the new location
REM    4) set start type = auto, then set failure actions (auto restart)
REM    5) start the service and verify: sc query / sc qfailure / status /
REM       accept --check / config-check
REM    6) delete the source directory after verification passed
REM    7) harden D:\backup: deny delete to Everyone (D + DC, inherited)
REM
REM  UNDO mode (/UNDO) - revert exactly what INSTALL mode changed:
REM    1) remove the delete-deny ACL from D:\backup
REM    2) clear the failure actions on the service
REM    Add /PURGE to also stop the service, uninstall it and delete the target.
REM
REM  Usage:
REM    install-to-d-backup.cmd                     source = C:\backup-agent
REM    install-to-d-backup.cmd "X:\path\to\tool"   use another source directory
REM    install-to-d-backup.cmd "I:\backup\tool-R3" install straight from the USB
REM    install-to-d-backup.cmd /DRYRUN             print the plan, change nothing
REM    install-to-d-backup.cmd /KEEPSRC            keep the source directory
REM    install-to-d-backup.cmd /NOHARDEN           skip the delete-deny ACL
REM    install-to-d-backup.cmd /UNDO               revert ACL + failure actions
REM    install-to-d-backup.cmd /PURGE              /UNDO plus remove service+dir
REM    install-to-d-backup.cmd /YES                do not pause at the end
REM
REM  Requires administrator rights. Double-click: it raises a UAC prompt.
REM
REM  Why the service is stopped first: while it runs it locks client.exe so the
REM  copy fails; and the service registers an ABSOLUTE path to the exe, so it
REM  has to be re-registered after the move.
REM
REM  About the delete-deny ACL (install step 7):
REM    "Everyone:(OI)(CI)(D,DC)" makes D:\backup undeletable from a console,
REM    from Explorer and from "rd /s /q" - administrators included, because a
REM    deny ACE beats the inherited allow. Denying DC (delete child) as well as
REM    D is what actually closes the hole: with D alone a child can still be
REM    removed through the parent directory delete-child right.
REM    Only a process that enables SeRestorePrivilege (imaging / backup tooling)
REM    can bypass it.
REM    The trade-off to remember: while it is in place you cannot upgrade, move
REM    or uninstall the tool until you revert it - run this file with /UNDO.
REM    The service itself is unaffected: artifacts go to %TEMP%\backup and the
REM    logs / audit log to %LOCALAPPDATA%\usbbackup-r2, not into D:\backup.
REM
REM  NOTE: keep this file ASCII-only. cmd.exe decodes a .cmd with the console
REM  code page, so non-ASCII text here gets mangled and breaks parsing.
REM ===========================================================================

REM ------------------------------ settings -----------------------------------
set "DST_ROOT=D:\backup"
set "APP_NAME=usbbackup-r2"
set "SVC_NAME=usbbackup-r2"
set "DEFAULT_SRC=C:\backup-agent"
REM Directory that gets the delete-deny ACL. Keep it at DST_ROOT so the whole
REM deployment tree is covered.
set "HARDEN_DIR=%DST_ROOT%"
set "HARDEN_PRINCIPAL=Everyone"
set "HARDEN_SPEC=Everyone:(OI)(CI)(D,DC)"
REM Failure action applied to the service: restart 3 times, counter reset 86400s.
set "FAILURE_RESET=86400"
set "FAILURE_ACTIONS=restart/0/restart/0/restart/0"
REM Optional service dependency. Leave empty for none. "Dhcp" makes the service
REM wait for a working IP configuration before it starts, which is only useful
REM if you want uploads to be able to reach R2 immediately after a reboot.
set "SVC_DEPEND="
REM ---------------------------------------------------------------------------

REM ---- re-launch from %TEMP% ------------------------------------------------
REM The script may sit inside the very directory being moved. cmd.exe reads a
REM .cmd line by line, so moving it away mid-run would break the rest.
if /i not "%~dp0"=="%TEMP%\" (
    copy /y "%~f0" "%TEMP%\ub_r2_move.cmd" >nul 2>&1
    "%TEMP%\ub_r2_move.cmd" %*
    exit /b %ERRORLEVEL%
)

REM ---- parse arguments ------------------------------------------------------
set "SRC="
set "DRYRUN="
set "KEEPSRC="
set "NO_PAUSE="
set "NOHARDEN="
set "UNDO="
set "PURGE="
for %%A in (%*) do (
    set "a=%%~A"
    if /i "!a!"=="/DRYRUN" (
        set "DRYRUN=1"
    ) else if /i "!a!"=="/KEEPSRC" (
        set "KEEPSRC=1"
    ) else if /i "!a!"=="/NOHARDEN" (
        set "NOHARDEN=1"
    ) else if /i "!a!"=="/UNDO" (
        set "UNDO=1"
    ) else if /i "!a!"=="/PURGE" (
        set "UNDO=1"
        set "PURGE=1"
    ) else if /i "!a!"=="/YES" (
        set "NO_PAUSE=1"
    ) else (
        set "SRC=%%~A"
    )
)
if not defined SRC set "SRC=%DEFAULT_SRC%"
set "DST=%DST_ROOT%\%APP_NAME%"

echo ===========================================================================
echo    usbbackup-r2  -  deployment helper
echo ===========================================================================
echo    source   : %SRC%
echo    target   : %DST%
echo    service  : %SVC_NAME%
echo    harden   : %HARDEN_DIR%   deny "%HARDEN_SPEC%"
if defined NOHARDEN echo    mode     : /NOHARDEN - the delete-deny ACL is skipped
if defined PURGE echo    mode     : PURGE - also remove the service and the target
if defined UNDO echo    mode     : UNDO - revert ACL and failure actions
if defined DRYRUN echo    mode     : DRYRUN - plan only, nothing is changed
echo ===========================================================================
echo.

if defined DRYRUN goto :dryrun
if defined UNDO goto :undo_flow

REM ---- guards ---------------------------------------------------------------
if "%SRC:~0,3%"=="%SRC%" (
    echo [x] source looks like a drive root: %SRC%  -- refused.
    goto :fail
)
if /i "%SRC%"=="%DST%" (
    echo [x] source and target are the same directory, nothing to move.
    goto :fail
)
if not exist "%SRC%\client.exe" (
    echo [x] no client.exe found in: %SRC%
    echo     check the source directory, or pass it as an argument, e.g.
    echo       install-to-d-backup.cmd "I:\backup\tool-R3"
    goto :fail
)

REM ---- administrator rights -------------------------------------------------
call :require_admin
if errorlevel 1 exit /b

REM ---- stop and delete the old service --------------------------------------
sc query "%SVC_NAME%" >nul 2>&1
if errorlevel 1 goto :no_service

echo [*] stopping service %SVC_NAME% ...
sc stop "%SVC_NAME%" >nul 2>&1
set /a W=0
:wait_stop
sc query "%SVC_NAME%" 2>nul | findstr /i "STOPPED" >nul
if not errorlevel 1 goto :svc_stopped
set /a W+=1
if !W! geq 30 (
    echo [WARN] timed out waiting for the service to stop, continuing anyway.
    goto :svc_stopped
)
ping -n 2 127.0.0.1 >nul 2>&1
goto :wait_stop

:svc_stopped
echo [*] deleting the service registration ...
sc delete "%SVC_NAME%" >nul 2>&1
set /a W=0
:wait_del
sc query "%SVC_NAME%" >nul 2>&1
if errorlevel 1 goto :after_stop
set /a W+=1
if !W! geq 20 (
    echo [WARN] service stays in "marked for deletion" too long, continuing anyway.
    goto :after_stop
)
ping -n 2 127.0.0.1 >nul 2>&1
goto :wait_del

:no_service
echo [*] no registered service found, skipping stop/delete.

:after_stop

REM ---- copy to D: -----------------------------------------------------------
if not exist "%DST_ROOT%" mkdir "%DST_ROOT%"
echo [*] copying %SRC%  to  %DST%
robocopy "%SRC%" "%DST%" /E /COPY:DAT /R:2 /W:2 /NFL /NDL /NJH /NJS /NP >nul
set "RC=%ERRORLEVEL%"
if %RC% geq 8 (
    echo [x] copy failed, robocopy exit code %RC%
    goto :fail
)
echo [*] copy done, robocopy exit code %RC%

REM ---- verify the copy is complete ------------------------------------------
for /f %%N in ('dir /a-d /s /b "%SRC%" 2^>nul ^| find /c /v ""') do set "NF_SRC=%%N"
for /f %%N in ('dir /a-d /s /b "%DST%" 2^>nul ^| find /c /v ""') do set "NF_DST=%%N"
echo [*] file count: source %NF_SRC% / target %NF_DST%
if not "%NF_SRC%"=="%NF_DST%" (
    echo [x] file count mismatch, copy is incomplete - aborted, source untouched.
    goto :fail
)

REM ---- register the service at the new location -----------------------------
pushd "%DST%"
echo [*] registering the service at the new location ...
client.exe install-service
if not errorlevel 1 goto :svc_registered
popd
echo [x] service registration failed. source directory kept, nothing lost.
goto :fail
:svc_registered

REM ---- enable auto-start ----------------------------------------------------
echo [*] setting start type to auto ...
sc config "%SVC_NAME%" start= auto >nul
if errorlevel 1 goto :autostart_fail
echo [*] auto-start enabled.
goto :autostart_done
:autostart_fail
echo [WARN] could not set auto-start. run it manually:  sc config %SVC_NAME% start= auto
:autostart_done

REM ---- optional dependency --------------------------------------------------
if not defined SVC_DEPEND goto :depend_done
echo [*] setting dependency: %SVC_DEPEND%
sc config "%SVC_NAME%" depend= %SVC_DEPEND% >nul
if errorlevel 1 echo [WARN] could not set the dependency, continuing.
:depend_done

REM ---- failure actions: restart on crash ------------------------------------
call :apply_failure

REM ---- start ----------------------------------------------------------------
echo [*] starting the service ...
sc start "%SVC_NAME%" >nul 2>&1
ping -n 4 127.0.0.1 >nul 2>&1

REM ---- verify ---------------------------------------------------------------
echo.
echo ------------------------------- verify -----------------------------------
sc query "%SVC_NAME%"
echo.
sc qfailure "%SVC_NAME%"
echo.
client.exe status
echo.
client.exe accept --check
echo.
client.exe config-check
popd

REM ---- drop the source directory --------------------------------------------
echo.
if defined KEEPSRC goto :keep_src
echo [*] removing the source directory %SRC% ...
rmdir /s /q "%SRC%" 2>nul
if exist "%SRC%" goto :src_remain
echo [*] source directory removed.
goto :finalize

:keep_src
echo [*] /KEEPSRC given, keeping the source directory: %SRC%
goto :finalize

:src_remain
echo [WARN] source directory could not be fully removed, delete it manually.
echo     if hardening has already been applied, run this file with /UNDO first.

:finalize
REM ---- harden the deployment directory --------------------------------------
if defined NOHARDEN goto :noharden
call :harden
goto :done

:noharden
echo.
echo [*] /NOHARDEN given - the delete-deny ACL was NOT applied.

:done
echo.
echo ===========================================================================
echo    DONE
echo    service %SVC_NAME% now points to: %DST%
echo    start type: auto (starts on boot)
echo    failure action: %FAILURE_ACTIONS%  reset period %FAILURE_RESET%s
if defined NOHARDEN echo    delete protection: NOT applied
if not defined NOHARDEN echo    delete protection: %HARDEN_DIR% denies delete to %HARDEN_PRINCIPAL%
echo ===========================================================================
echo    revert ACL + failure actions : this file with /UNDO
echo    remove the tool completely   : this file with /PURGE
echo.
echo    Note: client.json credentials use DPAPI (machine scope), so moving the
echo    directory on the same machine is fine - no need to regenerate them.
if not defined NO_PAUSE pause
exit /b 0

REM ===========================================================================
REM  UNDO mode
REM ===========================================================================
:undo_flow
call :require_admin
if errorlevel 1 exit /b

call :unharden
call :clear_failure

if not defined PURGE goto :undo_done

echo.
echo [*] PURGE: stopping and removing the service and the target directory ...
REM Check first: waiting on a service that is not registered would spin for 30s.
sc query "%SVC_NAME%" >nul 2>&1
if errorlevel 1 goto :undo_no_service

sc stop "%SVC_NAME%" >nul 2>&1
set /a W=0
:undo_wait_stop
sc query "%SVC_NAME%" 2>nul | findstr /i "STOPPED" >nul
if not errorlevel 1 goto :undo_stopped
set /a W+=1
if !W! geq 30 goto :undo_stopped
ping -n 2 127.0.0.1 >nul 2>&1
goto :undo_wait_stop
:undo_stopped

if not exist "%DST%\client.exe" goto :undo_no_tool
echo [*] uninstalling the service through the tool itself ...
pushd "%DST%"
client.exe uninstall-service
popd

:undo_no_tool
sc delete "%SVC_NAME%" >nul 2>&1
set /a W=0
:undo_wait_del
sc query "%SVC_NAME%" >nul 2>&1
if errorlevel 1 goto :undo_deleted
set /a W+=1
if !W! geq 20 goto :undo_deleted
ping -n 2 127.0.0.1 >nul 2>&1
goto :undo_wait_del

:undo_no_service
echo [*] no registered service found, skipping stop/delete.

:undo_deleted

if not exist "%DST%" goto :undo_dir_absent
rmdir /s /q "%DST%" 2>nul
if not exist "%DST%" goto :undo_dir_gone
echo [WARN] could not remove %DST% - a file is still locked. Reboot and run /PURGE again.
goto :undo_done

:undo_dir_gone
echo [*] %DST% removed.
goto :undo_prune_root

:undo_dir_absent
echo [*] %DST% does not exist, nothing to delete.

:undo_prune_root
if exist "%DST_ROOT%" rmdir "%DST_ROOT%" 2>nul

:undo_done
echo.
echo ===========================================================================
echo    UNDO DONE
if defined PURGE echo    service %SVC_NAME% removed, %DST% deleted.
echo    the ACL deny and the failure actions are reverted.
echo ===========================================================================
if not defined NO_PAUSE pause
exit /b 0

REM ===========================================================================
REM  DRYRUN
REM ===========================================================================
:dryrun
echo [DRYRUN] would run:
if defined UNDO goto :dryrun_undo_list
echo    1. sc stop %SVC_NAME%  then  sc delete %SVC_NAME%     (if registered)
echo    2. robocopy "%SRC%" "%DST%" /E /COPY:DAT
echo    3. cd /d "%DST%"  ^&^&  client.exe install-service
echo    4. sc config %SVC_NAME% start= auto                   (auto-start)
echo    5. sc failure %SVC_NAME% reset= %FAILURE_RESET% actions= %FAILURE_ACTIONS%
echo    6. sc start %SVC_NAME%
echo    7. verify: sc query / sc qfailure / status / accept --check / config-check
if defined KEEPSRC echo    8. keep the source directory %SRC%
if not defined KEEPSRC echo    8. rmdir /s /q "%SRC%"
if defined NOHARDEN echo    9. SKIP the delete-deny ACL
if not defined NOHARDEN echo    9. icacls "%HARDEN_DIR%" /deny "%HARDEN_SPEC%"
goto :dryrun_end

:dryrun_undo_list
echo    1. icacls "%HARDEN_DIR%" /remove:d "%HARDEN_PRINCIPAL%"
echo    2. sc failure %SVC_NAME% reset= 0 actions= ""
if not defined PURGE goto :dryrun_end
echo    3. sc stop %SVC_NAME%   then   client.exe uninstall-service
echo    4. rmdir /s /q "%DST%"

:dryrun_end
echo.
echo (DRYRUN finished, nothing was changed)
if not defined NO_PAUSE pause
exit /b 0

:fail
echo.
echo ABORTED: fix the problem reported above and run again.
if not defined NO_PAUSE pause
exit /b 1

REM ===========================================================================
REM  Subroutines (only reached through "call")
REM ===========================================================================

:require_admin
REM Do not rely on net session alone: it fails even in an admin session when the
REM Server service is stopped.
set "ADMIN="
fltmc >nul 2>&1
if not errorlevel 1 set "ADMIN=1"
if defined ADMIN exit /b 0
net session >nul 2>&1
if not errorlevel 1 set "ADMIN=1"
if defined ADMIN exit /b 0
echo [*] administrator rights required, raising a UAC prompt...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
exit /b 1

:harden
echo.
echo [*] hardening %HARDEN_DIR% : deny delete to %HARDEN_PRINCIPAL% ...
if not exist "%HARDEN_DIR%" goto :harden_missing
icacls "%HARDEN_DIR%" /deny "%HARDEN_SPEC%" >nul
if errorlevel 1 goto :harden_failed
echo [*] hardening applied: %HARDEN_SPEC%
echo     this covers the directory and everything under it: the console,
echo     Explorer and "rd /s /q" will all refuse to delete it, administrators
echo     included. Only SeRestorePrivilege (imaging / backup tooling) bypasses.
echo     revert with:  this file with /UNDO
exit /b 0

:harden_missing
echo [WARN] %HARDEN_DIR% does not exist, hardening skipped.
exit /b 1

:harden_failed
echo [WARN] icacls failed. %HARDEN_DIR% stays deletable.
echo     run it manually:  icacls "%HARDEN_DIR%" /deny "%HARDEN_SPEC%"
exit /b 1

:unharden
echo.
echo [*] reverting the delete-deny ACL on %HARDEN_DIR% ...
if not exist "%HARDEN_DIR%" goto :unharden_missing
REM Remove every principal that produces a delete deny, best effort: the one we
REM add, plus the three that a hand-written command line usually lists.
icacls "%HARDEN_DIR%" /remove:d "%HARDEN_PRINCIPAL%" >nul 2>&1
icacls "%HARDEN_DIR%" /remove:d "%USERNAME%" >nul 2>&1
icacls "%HARDEN_DIR%" /remove:d "SYSTEM" >nul 2>&1
icacls "%HARDEN_DIR%" /remove:d "Administrators" >nul 2>&1
echo [*] done. current ACL:
icacls "%HARDEN_DIR%"
exit /b 0

:unharden_missing
echo [*] %HARDEN_DIR% does not exist, nothing to revert.
exit /b 0

:apply_failure
echo.
echo [*] setting failure actions: restart on crash, reset %FAILURE_RESET%s ...
sc failure "%SVC_NAME%" reset= %FAILURE_RESET% actions= %FAILURE_ACTIONS% >nul
if errorlevel 1 goto :failure_failed
echo [*] failure actions set: %FAILURE_ACTIONS%
goto :failure_done
:failure_failed
echo [WARN] could not set failure actions. run it manually:
echo       sc failure %SVC_NAME% reset= %FAILURE_RESET% actions= %FAILURE_ACTIONS%
:failure_done
exit /b 0

:clear_failure
echo.
echo [*] clearing failure actions on %SVC_NAME% ...
sc failure "%SVC_NAME%" reset= 0 actions= "" >nul 2>&1
if errorlevel 1 goto :clear_failure_none
echo [*] failure actions cleared.
exit /b 0
:clear_failure_none
echo [WARN] the service is not registered, nothing to clear.
exit /b 0
