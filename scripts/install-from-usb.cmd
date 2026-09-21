@echo off
setlocal EnableExtensions EnableDelayedExpansion
title usbbackup-r2 one-click installer

REM ===========================================================================
REM  usbbackup-r2 - one-click installer for Windows targets
REM ---------------------------------------------------------------------------
REM  Run this file by DOUBLE-CLICKING it on the USB stick. Nothing else to do.
REM  It performs, in order:
REM    1) stop and delete an existing service registration (if any)
REM    2) copy the whole tool directory to D:\backup\usbbackup-r2
REM    3) verify the copy file by file (name and size)
REM    4) create the per-machine R2 credential (client.json). You are asked
REM       for the Secret Access Key once. Nothing is written to the stick.
REM    5) confirm the licence once (client.exe accept --yes)
REM    6) register the service at the new location and start it
REM    7) set start type = auto (starts on boot) and failure actions
REM       (restart 3x) so it recovers from a crash by itself
REM    8) verify: sc query / sc qfailure / status / config-check, plus an
REM       optional r2-check probe that proves the credential really works
REM    9) harden D:\backup: deny delete to Everyone (D + DC, inherited)
REM
REM  Why not run the tool straight from the stick: install-service registers an
REM  ABSOLUTE path to the exe, so the service would break the moment the stick
REM  is unplugged. The stick is only the distribution medium.
REM
REM  Usage:
REM    install-from-usb.cmd               double-click it, or run from a prompt
REM    install-from-usb.cmd /DRYRUN       print the plan, change nothing
REM    install-from-usb.cmd /NOAUTH       skip the credential step
REM    install-from-usb.cmd /NOVERIFY     skip the r2-check network probe
REM    install-from-usb.cmd /NOHARDEN     skip the delete-deny ACL
REM    install-from-usb.cmd /CLEAN        wipe the target directory first
REM    install-from-usb.cmd /YES          do not pause at the end
REM    install-from-usb.cmd /UNDO         revert ACL plus failure actions
REM    install-from-usb.cmd /PURGE        /UNDO plus remove service and files
REM    install-from-usb.cmd "X:\src"      use X:\src as source, not this dir
REM
REM  Requires administrator rights. If it is not elevated it re-launches itself
REM  through a UAC prompt, so a double-click is enough.
REM
REM  About the delete-deny ACL (step 9):
REM    A deny ACE for Delete + DeleteSubdirectoriesAndFiles makes D:\backup
REM    undeletable from a console, from Explorer and from "rd /s /q" - the
REM    administrator token included, because a deny ACE beats an inherited
REM    allow. Denying delete-child as well as delete is what closes the hole:
REM    with delete alone a child can still be removed through the parent
REM    directory delete-child right.
REM
REM    IMPORTANT - it is written through the .NET ACL API, NOT "icacls /deny":
REM    icacls silently ORs SYNCHRONIZE into the deny mask, and denying
REM    SYNCHRONIZE makes the whole subtree unreadable, because walking a path
REM    needs that right on every directory in it. With icacls the service could
REM    not read client.json any more, and this script could not even verify its
REM    own copy - it reported every file as missing. Denying exactly the two
REM    delete rights, nothing more, is what makes the protection usable.
REM
REM    Trade-off to remember: while it is in place you cannot upgrade, move or
REM    uninstall the tool until you revert it - run this file with /UNDO.
REM    Everything inside stays readable, so the service is unaffected:
REM    artifacts go to %TEMP%\backup and the logs / audit log to
REM    %LOCALAPPDATA%\usbbackup-r2, not into D:\backup.
REM
REM  NOTE: keep this file ASCII-only. cmd.exe decodes a .cmd with the console
REM  code page, so non-ASCII text here gets mangled and breaks parsing.
REM ===========================================================================

REM ------------------------------ settings -----------------------------------
set "DST_ROOT=D:\backup"
set "APP_NAME=usbbackup-r2"
set "SVC_NAME=usbbackup-r2"
set "CRED_FILE=client.json"
set "CRED_TEMPLATE=r2.json"
REM Directory that gets the delete-deny ACL. Keep it at DST_ROOT so the whole
REM deployment tree is covered.
set "HARDEN_DIR=%DST_ROOT%"
set "HARDEN_PRINCIPAL=Everyone"
REM Rights denied: Delete (0x10000) plus DeleteSubdirectoriesAndFiles (0x40).
REM Written through the .NET ACL API on purpose - "icacls /deny" silently ORs
REM in SYNCHRONIZE, which makes the whole subtree unreadable and would break
REM both the service and this script. See the header for the full story.
set "HARDEN_MASK=0x10040"
REM Failure action applied to the service: restart 3 times, counter reset 86400s.
set "FAILURE_RESET=86400"
set "FAILURE_ACTIONS=restart/0/restart/0/restart/0"
REM Optional service dependency. Leave empty for none. "Dhcp" makes the service
REM wait for a working IP configuration before it starts, which is only useful
REM if you want uploads to reach R2 right after a boot.
set "SVC_DEPEND="
REM ---------------------------------------------------------------------------

REM ---- source = the directory this script sits in ---------------------------
set "SRC=%~dp0"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"

REM ---- parse arguments ------------------------------------------------------
set "DRYRUN="
set "NO_PAUSE="
set "NOHARDEN="
set "NOAUTH="
set "NOVERIFY="
set "CLEAN="
set "UNDO="
set "PURGE="
for %%A in (%*) do (
    set "a=%%~A"
    if /i "!a!"=="/DRYRUN" (
        set "DRYRUN=1"
    ) else if /i "!a!"=="/NOHARDEN" (
        set "NOHARDEN=1"
    ) else if /i "!a!"=="/NOAUTH" (
        set "NOAUTH=1"
    ) else if /i "!a!"=="/NOVERIFY" (
        set "NOVERIFY=1"
    ) else if /i "!a!"=="/CLEAN" (
        set "CLEAN=1"
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
set "DST=%DST_ROOT%\%APP_NAME%"
REM Wording used by the DRYRUN plan for the robocopy step.
set "RCNOTE=merge into the existing target"
if defined CLEAN set "RCNOTE=fresh copy"

echo ===========================================================================
echo    usbbackup-r2  -  one-click installer
echo ===========================================================================
echo    source   : %SRC%
echo    target   : %DST%
echo    service  : %SVC_NAME%
echo    harden   : %HARDEN_DIR%   deny delete to %HARDEN_PRINCIPAL%  (mask %HARDEN_MASK%)
if defined CLEAN    echo    mode     : CLEAN - the target directory is wiped first
if defined NOAUTH   echo    mode     : /NOAUTH - the credential step is skipped
if defined NOVERIFY echo    mode     : /NOVERIFY - the R2 probe is skipped
if defined NOHARDEN echo    mode     : /NOHARDEN - the delete-deny ACL is skipped
if defined PURGE    echo    mode     : PURGE - also remove the service and the target
if defined UNDO     echo    mode     : UNDO - revert ACL and failure actions
if defined DRYRUN   echo    mode     : DRYRUN - plan only, nothing is changed
echo ===========================================================================
echo.

if defined DRYRUN goto :dryrun
if defined UNDO goto :undo_flow

REM ---- guards ---------------------------------------------------------------
if /i "%SRC%"=="%DST%" (
    echo [x] this script IS inside the install target.
    echo     run it from the USB stick, not from %DST%
    goto :fail
)
if "%SRC:~1,2%"==":\" if "%SRC:~3%"=="" (
    echo [x] source looks like a drive root: %SRC%  -- refused.
    goto :fail
)
if not exist "%SRC%\client.exe" (
    echo [x] no client.exe found in: %SRC%
    echo     put this script inside the tool directory on the stick, next to
    echo     client.exe, or pass the directory as an argument.
    goto :fail
)
if not exist "%DST_ROOT:~0,3%" (
    echo [x] drive %DST_ROOT:~0,2% does not exist on this machine.
    echo     edit DST_ROOT at the top of this file, or create the drive first.
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

REM ---- optional clean -------------------------------------------------------
if not defined CLEAN goto :copy
if not exist "%DST%" goto :copy
echo [*] /CLEAN: reverting the delete-deny ACL before wiping the target ...
call :unharden
echo [*] /CLEAN: removing %DST% ...
rmdir /s /q "%DST%" 2>nul
if exist "%DST%" (
    echo [x] could not remove %DST% - a file is still locked. Reboot and retry.
    goto :fail
)
echo [*] target directory wiped. note: client.json was removed too, the
echo     credential step below will create a fresh one.

REM ---- copy to D: -----------------------------------------------------------
:copy
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
call :verify_copy
if errorlevel 1 goto :fail

REM ---- credential -----------------------------------------------------------
call :cred_flow

REM ---- licence confirmation -------------------------------------------------
pushd "%DST%"
echo.
echo [*] confirming the licence for this machine (accept --yes) ...
client.exe accept --yes >nul 2>&1
if errorlevel 1 echo [WARN] accept --yes failed. run it by hand later: client.exe accept
popd

REM ---- register the service at the new location -----------------------------
pushd "%DST%"
echo [*] registering the service at the new location ...
client.exe install-service
if not errorlevel 1 goto :svc_registered
popd
echo [x] service registration failed. nothing was lost, the stick is intact.
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

REM ---- R2 credential probe --------------------------------------------------
call :verify_r2

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
echo    the USB stick can be unplugged now - nothing runs from it any more.
echo.
echo    revert ACL + failure actions : this file with /UNDO
echo    remove the tool completely   : this file with /PURGE
if not defined NOHARDEN echo    (run /UNDO first - otherwise the wipe is refused)
echo.
echo    Note: client.json uses DPAPI machine scope, so it is bound to THIS
echo    machine. Re-installing over it is fine; moving it to another machine
echo    is not - create a fresh one there.
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
echo    the USB stick was not touched.
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
if not defined CLEAN echo    2. no /CLEAN: keep the existing target, client.json included
if defined CLEAN echo    2. /CLEAN: strip the deny ACE on "%HARDEN_DIR%"  then  rmdir /s /q "%DST%"
echo    3. robocopy "%SRC%" "%DST%" /E /COPY:DAT   (!RCNOTE!)
echo    4. verify every file: name + size
if defined NOAUTH echo    5. SKIP the credential step (/NOAUTH)
if not defined NOAUTH echo    5. create %DST%\%CRED_FILE% from %CRED_TEMPLATE% (asks for the Secret once)
echo    6. client.exe accept --yes
echo    7. cd /d "%DST%"  then  client.exe install-service
echo    8. sc config %SVC_NAME% start= auto                   (auto-start)
echo    9. sc failure %SVC_NAME% reset= %FAILURE_RESET% actions= %FAILURE_ACTIONS%
echo   10. sc start %SVC_NAME%
echo   11. verify: sc query / sc qfailure / status / accept --check / config-check
if defined NOVERIFY echo   12. SKIP the R2 probe (/NOVERIFY)
if not defined NOVERIFY echo   12. usbkeygen-r2.exe r2-check --cred-file %CRED_FILE%   (network probe)
if defined NOHARDEN echo   13. SKIP the delete-deny ACL
if not defined NOHARDEN echo   13. deny delete on "%HARDEN_DIR%" via the .NET ACL API (mask %HARDEN_MASK%)
goto :dryrun_end

:dryrun_undo_list
echo    1. strip every deny ACE on "%HARDEN_DIR%" via the .NET ACL API
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
echo The USB stick was not modified.
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

:verify_copy
echo [*] verifying the copy: name and size of every source file ...
set "BAD="
set /a N=0
for /r "%SRC%" %%F in (*) do (
    set "REL=%%F"
    set "REL=!REL:%SRC%=!"
    if exist "%DST%!REL!" (
        for %%G in ("%DST%!REL!") do (
            if not "%%~zF"=="%%~zG" (
                echo     [x] size mismatch: !REL!
                set "BAD=1"
            )
        )
    ) else (
        echo     [x] missing in target: !REL!
        set "BAD=1"
    )
    set /a N+=1
)
echo [*] checked !N! file(s).
if defined BAD (
    echo [x] the copy is incomplete - aborted, the stick is untouched.
    exit /b 1
)
exit /b 0

:cred_flow
if defined NOAUTH goto :cred_skip
if not exist "%DST%\%CRED_FILE%" goto :cred_need_src

echo [*] an existing credential was found, reusing it: %DST%\%CRED_FILE%
goto :cred_done

:cred_need_src
if not exist "%SRC%\%CRED_FILE%" goto :cred_generate
echo [*] copying %CRED_FILE% from the source directory ...
copy /y "%SRC%\%CRED_FILE%" "%DST%\%CRED_FILE%" >nul
if exist "%DST%\%CRED_FILE%" goto :cred_made

:cred_generate
echo.
echo ---------------------------------------------------------------------------
echo   R2 credential - it is bound to THIS machine
echo ---------------------------------------------------------------------------
echo   Upload is ON, but no credential ships on the stick: a DPAPI credential
echo   only works on the machine that created it. So one is created here.
echo.
echo   You will be asked for the SECRET ACCESS KEY - 64 hex characters, typed
echo   with no echo. It is NOT the private-key passphrase: feeding the
echo   passphrase here shows up later as HTTP 403 SignatureDoesNotMatch.
echo   Nothing is written back to the stick. Ctrl+C aborts the install here.
echo.
pushd "%DST%"
usbkeygen-r2.exe cred --yes --from "%CRED_TEMPLATE%" --out "%CRED_FILE%" --scope upload --force
set "CRED_RC=%ERRORLEVEL%"
popd
if exist "%DST%\%CRED_FILE%" goto :cred_made
echo.
echo [WARN] no credential was created (exit code %CRED_RC%).
echo        the service still works, but uploads are skipped silently until a
echo        credential exists. create one later with:
echo          cd /d "%DST%"
echo          usbkeygen-r2.exe cred --yes --from r2.json --out client.json --scope upload
goto :cred_done

:cred_made
echo [*] credential ready: %DST%\%CRED_FILE%
goto :cred_done

:cred_skip
echo [*] /NOAUTH given - the credential step was skipped. uploads stay off
echo     until you create %DST%\%CRED_FILE% yourself.

:cred_done
exit /b 0

:verify_r2
if defined NOVERIFY goto :r2_skip
if not exist "%DST%\%CRED_FILE%" goto :r2_skip
echo.
echo [*] probing the credential against R2 (writes then deletes a probe object) ...
pushd "%DST%"
usbkeygen-r2.exe r2-check --yes --cred-file "%CRED_FILE%" --timeout 1
set "R2_RC=%ERRORLEVEL%"
popd
if "%R2_RC%"=="0" goto :r2_ok
echo.
echo [WARN] the R2 probe did not pass (exit code %R2_RC%).
echo        either this machine has no route to the endpoint, or the Secret was
echo        wrong. the service runs either way, but nothing will be uploaded.
echo        to start over, delete %DST%\%CRED_FILE% and run this file again.
exit /b 0
:r2_ok
echo [*] the R2 probe passed: credential accepted, upload path is live.
exit /b 0
:r2_skip
exit /b 0

:harden
echo.
echo [*] hardening %HARDEN_DIR% : deny delete to %HARDEN_PRINCIPAL% ...
if not exist "%HARDEN_DIR%" goto :harden_missing
REM The .NET ACL API, not "icacls /deny": icacls would OR SYNCHRONIZE into the
REM mask and leave the whole subtree unreadable.
powershell -NoProfile -Command "$p='%HARDEN_DIR%'; $a=Get-Acl -LiteralPath $p; $r=New-Object System.Security.AccessControl.FileSystemAccessRule('%HARDEN_PRINCIPAL%',%HARDEN_MASK%,[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[System.Security.AccessControl.PropagationFlags]'None',[System.Security.AccessControl.AccessControlType]'Deny'); $a.AddAccessRule($r); Set-Acl -LiteralPath $p -AclObject $a"
if errorlevel 1 goto :harden_failed
REM Read back through icacls: reading is not affected by the deny we just added.
icacls "%HARDEN_DIR%" 2>nul | findstr /i "DENY" >nul
if errorlevel 1 goto :harden_failed
echo [*] hardening applied: deny Delete + DeleteSubdirectoriesAndFiles to %HARDEN_PRINCIPAL%
echo     this covers the directory and everything under it: the console,
echo     Explorer and "rd /s /q" will all refuse to delete it, administrators
echo     included. Only SeRestorePrivilege (imaging / backup tooling) bypasses.
echo     reading is NOT affected, so the service keeps working normally.
echo     revert with:  this file with /UNDO
exit /b 0

:harden_missing
echo [WARN] %HARDEN_DIR% does not exist, hardening skipped.
exit /b 1

:harden_failed
echo [WARN] the delete-deny ACE could not be applied. %HARDEN_DIR% stays
echo     deletable. apply it by hand in an elevated PowerShell:
echo       $p='%HARDEN_DIR%'
echo       $a=Get-Acl -LiteralPath $p
echo       $r=New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone',0x10040,'ContainerInherit,ObjectInherit','None','Deny')
echo       $a.AddAccessRule($r); Set-Acl -LiteralPath $p -AclObject $a
exit /b 1

:unharden
echo.
echo [*] reverting the delete-deny ACL on %HARDEN_DIR% ...
if not exist "%HARDEN_DIR%" goto :unharden_missing
REM Strip every deny ACE whatever principal it names: the one we add, plus
REM anything a hand-written icacls command line left behind.
powershell -NoProfile -Command "$p='%HARDEN_DIR%'; $a=Get-Acl -LiteralPath $p; $k=@(); foreach($x in $a.Access){ if($x.AccessControlType -eq 'Deny'){ $k+=$x } }; foreach($y in $k){ [void]$a.RemoveAccessRuleSpecific($y) }; Set-Acl -LiteralPath $p -AclObject $a"
if errorlevel 1 echo [WARN] could not revert the ACL, revert it by hand in an elevated PowerShell.
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
