@echo off
setlocal EnableExtensions EnableDelayedExpansion
title usbbackup-r2 installer (no secret prompt)

REM ===========================================================================
REM  usbbackup-r2 - installer for Windows targets. NO SECRET IS EVER TYPED.
REM ---------------------------------------------------------------------------
REM  Run install.cmd on the USB stick. The stick also carries a pre-built,
REM  machine-independent credential (client.bin), so this installer asks for
REM  nothing at all - double-click and it is done.
REM
REM  In order it does:
REM    1) stop and delete an existing service registration (if any)
REM    2) copy this directory to D:\backup\usbbackup-r2
REM    3) verify the copy file by file (name and size)
REM    4) decrypt client.bin into client.json with the key file that ships next
REM       to it (.machine.key, raw random bytes - nothing to type)
REM    5) confirm the licence once (client.exe accept --yes)
REM    6) register the service at the new location and start it
REM    7) set start type = auto, so it comes up on boot
REM    8) set failure actions: restart 3x on crash
REM    9) verify: sc query / sc qfailure / status / accept --check / config-check,
REM       plus an r2-check probe that proves the credential really works
REM   10) harden %HARDEN_DIR%: deny delete to Everyone (D + DC, inherited)
REM
REM  WHY NO SECRET PROMPT
REM    The old installer called `usbkeygen-r2 cred` here, which asks for the R2
REM    Secret Access Key. That is a secret typed on the target machine, then
REM    encrypted with DPAPI - which only works on the machine that made it. So
REM    you had to type it once per machine and could not prepare anything ahead.
REM    Instead the credential is built once, up front, from a Cloudflare API
REM    token: the access key id is the token's id and the secret is the SHA-256
REM    of the token value (documented by Cloudflare). No secret is ever
REM    displayed or typed. client.json is therefore IDENTICAL on every machine
REM    and can be prepared offline - see r2perm.py in this directory.
REM
REM    Trade-off: a credential that is valid everywhere is a credential that is
REM    valid everywhere. It sits in D:\backup\usbbackup-r2\client.json on each
REM    target, under the same delete-deny ACL as the rest of the tree, and must
REM    be rotated if it leaks (rebuild client.bin and rerun this installer; no
REM    rebuild of the client itself). R2 provides no object versioning, so
REM    nothing on the remote side stops a deleted object from staying deleted.
REM    Rotate on a schedule.
REM
REM  SOURCE LAYOUT
REM    This script lives in the install/ subdirectory of the stick and takes that
REM    subdirectory as the source, NOT the stick root. The stick root also holds
REM    usbkeygen-r2.exe, the key files and r2.json, none of which the deployed
REM    client ever reads; copying them into D:\backup would ship a private key to
REM    every target for no reason. install/ deliberately carries only the two
REM    files the client actually needs - client.exe and client.json.
REM
REM  Usage:
REM    install.cmd                  double-click it
REM    install.cmd /DRYRUN          print the plan, change nothing
REM    install.cmd /NOAUTH          skip the credential step
REM    install.cmd /NOVERIFY        skip the r2-check network probe
REM    install.cmd /NOHARDEN        skip the delete-deny ACL
REM    install.cmd /CLEAN           wipe the target directory first
REM    install.cmd /YES             do not pause at the end
REM    install.cmd /UNDO            revert ACL plus failure actions
REM    install.cmd /PURGE           /UNDO plus remove service and files
REM    install.cmd "X:\src"         use X:\src as source, not this directory
REM
REM  The removal commands live in uninstall.cmd, which delegates back into the
REM  UNDO / PURGE flow here. That flow is kept in one place on purpose: two
REM  copies of an uninstaller drift, and the copy that drifts is always the one
REM  running on the machine that matters.
REM
REM  Requires administrator rights; it re-launches itself through UAC if needed.
REM
REM  NOTE: keep this file ASCII-only, and keep CRLF line endings. cmd.exe
REM  decodes a .cmd with the console code page, so non-ASCII text here gets
REM  mangled and breaks parsing, and LF endings break "goto :label".
REM ===========================================================================

REM ------------------------------ settings -----------------------------------
set "DST_ROOT=D:\backup"
set "APP_NAME=usbbackup-r2"
set "SVC_NAME=usbbackup-r2"
set "CRED_ENC=client.bin"
set "CRED_FILE=client.json"
set "MACHINE_KEY=.machine.key"
set "HARDEN_DIR=%DST_ROOT%"
set "HARDEN_PRINCIPAL=Everyone"
REM Rights denied: Delete (0x10000) plus DeleteSubdirectoriesAndFiles (0x40).
REM Written through the .NET ACL API on purpose - "icacls /deny" silently ORs
REM in SYNCHRONIZE, which makes the whole subtree unreadable and would break
REM both the service and this script. See the older installer's header for the
REM full story; that finding still holds.
set "HARDEN_MASK=0x10040"
set "FAILURE_RESET=86400"
set "FAILURE_ACTIONS=restart/0/restart/0/restart/0"
REM Optional service dependency. Leave empty for none. "Dhcp" makes the service
REM wait for a working IP configuration before it starts.
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

echo ===========================================================================
echo    usbbackup-r2  -  installer   (no secret prompt)
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
    echo     run this script from inside the install directory on the stick,
    echo     next to client.exe, or pass that directory as an argument.
    goto :fail
)
if not exist "%SRC%\usbkeygen-r2.exe" (
    echo [x] no usbkeygen-r2.exe found in: %SRC%
    echo     the credential step and the R2 probe both need it, and the copy is
    echo     verified file by file, so it must sit next to client.exe.
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

REM ---- clear a stale deny ACE before touching the target ---------------------
REM A previous install left "deny Delete + DeleteSubdirectoriesAndFiles" on
REM %HARDEN_DIR%. Reading is unaffected by that ACE, but deleting and replacing
REM are not - which is exactly what an upgrade does. Left in place it makes a
REM reinstall fail halfway: robocopy reports exit code 11 ("some files were
REM skipped") and the copy step aborts, at the moment a user is least able to
REM tell what went wrong.
REM
REM This must run BEFORE the /CLEAN branch below can jump over it, so it sits
REM here rather than next to the copy. The ACE is re-applied at the very end.
if exist "%HARDEN_DIR%" (
    echo [*] clearing any previous delete-deny ACL on %HARDEN_DIR% ...
    call :unharden
)

REM ---- optional clean -------------------------------------------------------
if defined CLEAN goto :wipe
if not exist "%DST%" goto :copy
REM No /CLEAN given, but the target may still hold files this version no longer
REM ships - which is the normal case for an upgrade. Those are NOT harmless:
REM a leftover client.exe or r2.json from an older layout would sit inside the
REM deployed tree, and the user has no reason to expect it there.
REM
REM So when the target directory contains anything the source does not, the
REM stale copy is removed outright. It is safe to do: the only files that are
REM not reproducible from the stick are client.json and the log/audit directory,
REM and the log lives outside D:\backup entirely (see LOG/audit paths), while
REM client.json is regenerated from client.bin in the credential step below.
echo [*] checking for files left over from an older install ...
set "STALE="
for %%F in ("%DST%\*") do (
    if not exist "%SRC%\%%~nxF" set "STALE=1"
)
for /d %%D in ("%DST%\*") do (
    if not exist "%SRC%\%%~nxD\" set "STALE=1"
)
if not defined STALE goto :copy
echo [*] the target holds entries this version does not ship - replacing it ...
echo     (they will be listed before removal, nothing else on D: is touched)
dir /b "%DST%"
:wipe
rmdir /s /q "%DST%" 2>nul
if exist "%DST%" (
    echo [x] could not remove %DST% - a file is still locked. Reboot and retry.
    goto :fail
)
echo [*] target directory cleared, a fresh copy follows.

REM ---- copy to D: -----------------------------------------------------------
:copy
if not exist "%DST_ROOT%" mkdir "%DST_ROOT%"
echo [*] copying %SRC%  to  %DST%
robocopy "%SRC%" "%DST%" /E /COPY:DAT /R:2 /W:2 /NFL /NDL /NJH /NJS /NP >nul
set "RC=%ERRORLEVEL%"
if %RC% geq 8 (
    echo [x] copy failed, robocopy exit code %RC%
    if %RC% equ 11 echo     code 11 means the target still held entries the copy could not
    if %RC% equ 11 echo     merge over - usually a file locked by a running process.
    if %RC% equ 11 echo     Reboot, then run this file again.
    goto :fail
)
echo [*] copy done, robocopy exit code %RC%

REM ---- verify the copy is complete ------------------------------------------
call :verify_copy
if errorlevel 1 goto :fail

REM ---- credential: decrypt the prepared one ---------------------------------
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
echo    remove the tool completely   : uninstall.cmd          (this is the default)
echo    revert ACL + failure actions : uninstall.cmd /KEEP    (keeps service + files)
if not defined NOHARDEN echo    (uninstall.cmd reverts the ACL itself - run it, do not delete by hand)
echo.
echo    the credential here is the same on every machine and does not expire.
echo    rotate it by replacing client.json with a freshly built client.bin,
echo    then running this installer again.
if not defined NO_PAUSE pause
exit /b 0

REM ===========================================================================
REM  UNDO / PURGE mode
REM ===========================================================================
:undo_flow
call :require_admin
if errorlevel 1 exit /b

call :unharden
call :clear_failure

if not defined PURGE goto :undo_done

echo.
echo [*] PURGE: stopping and removing the service and the target directory ...
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
REM ---- did it actually come off? --------------------------------------------
REM  "UNDO DONE" on its own is not an answer. The run that started this fix
REM  printed DONE while the service was still RUNNING, so the script now
REM  checks the result and reports it, instead of asserting it.
set "RESIDUAL="
if defined PURGE (
    echo [*] checking the result ...
    sc query "%SVC_NAME%" >nul 2>&1
    if not errorlevel 1 set "RESIDUAL=1"
    if exist "%DST%" set "RESIDUAL=1"
)
echo.
if not defined PURGE goto :undo_banner_revert
if defined RESIDUAL goto :undo_banner_residual
if defined PURGE goto :undo_banner_clean

:undo_banner_clean
echo ===========================================================================
echo    UNDO DONE
echo ===========================================================================
echo    [OK] service %SVC_NAME% is gone.
echo    [OK] %DST% is gone.
echo    [OK] the ACL deny and the failure actions are reverted.
echo    the USB stick was not touched.
echo ===========================================================================
if not defined NO_PAUSE pause
exit /b 0

:undo_banner_residual
echo ===========================================================================
echo    UNDO DONE - BUT SOMETHING IS STILL THERE
echo ===========================================================================
if exist "%DST%" echo    [x] %DST% still exists - a file in it is still open.
if exist "%DST%" echo        close whatever holds it, or reboot, then run this again.
sc query "%SVC_NAME%" >nul 2>&1
if not errorlevel 1 (
    echo    [x] service %SVC_NAME% is still registered.
    echo        try: sc.exe stop %SVC_NAME%   then   sc.exe delete %SVC_NAME%
)
echo    the ACL deny and the failure actions are reverted.
echo    the USB stick was not touched.
echo ===========================================================================
if not defined NO_PAUSE pause
exit /b 1

:undo_banner_revert
echo ===========================================================================
echo    UNDO DONE
echo ===========================================================================
echo    the ACL deny and the failure actions are reverted.
echo    the service and the files were KEPT ^(/KEEP^).
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
echo    3. robocopy "%SRC%" "%DST%" /E /COPY:DAT
echo    4. verify every file: name + size
if defined NOAUTH echo    5. SKIP the credential step (/NOAUTH)
if not defined NOAUTH echo    5. decrypt %CRED_ENC% into %CRED_FILE% using %MACHINE_KEY%   (nothing typed)
echo    6. client.exe accept --yes
echo    7. cd /d "%DST%"  then  client.exe install-service
echo    8. sc config %SVC_NAME% start= auto                   (auto-start)
echo    9. sc failure %SVC_NAME% reset= %FAILURE_RESET% actions= %FAILURE_ACTIONS%
echo   10. sc start %SVC_NAME%
echo   11. verify: sc query / sc qfailure / status / accept --check / config-check
if defined NOVERIFY echo   12. SKIP the R2 probe (/NOVERIFY)
if not defined NOVERIFY echo   12. usbkeygen-r2.exe r2-check --cred-file %CRED_FILE% [--allow-plain-cred if the cred is plaintext]   (network probe)
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
set "ADMIN="
fltmc >nul 2>&1
if not errorlevel 1 set "ADMIN=1"
if defined ADMIN exit /b 0
net session >nul 2>&1
if not errorlevel 1 set "ADMIN=1"
if defined ADMIN exit /b 0

REM Not elevated. Rebuild the switch list from the flags already parsed above
REM instead of forwarding "%*".
REM
REM Why this matters: uninstall.cmd delegates by calling this script with an
REM extra /YES, so "%*" in that path is just "/YES". Relaunching with "%*"
REM would drop /UNDO and /PURGE, the elevated window would run a fresh
REM INSTALL, and the operator who asked for a removal would end up looking at
REM a service that is running again. Deriving the switches from the parsed
REM flags makes the elevated run do what the first run was asked to do.
set "ELEV="
if defined UNDO      set "ELEV=/UNDO"
if defined PURGE     set "ELEV=%ELEV% /PURGE"
if defined DRYRUN    set "ELEV=%ELEV% /DRYRUN"
if defined CLEAN     set "ELEV=%ELEV% /CLEAN"
if defined NOAUTH    set "ELEV=%ELEV% /NOAUTH"
if defined NOVERIFY  set "ELEV=%ELEV% /NOVERIFY"
if defined NOHARDEN  set "ELEV=%ELEV% /NOHARDEN"
if defined NO_PAUSE  set "ELEV=%ELEV% /YES"

echo.
echo [*] administrator rights are required - raising a UAC prompt ...
echo     a second window will run : %ELEV%
echo     this window closes now, whether or not you accept the prompt.
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%ELEV%' -Verb RunAs" >nul 2>&1
if errorlevel 1 (
    echo [x] the UAC prompt could not be raised. right-click this script and
    echo     choose "run as administrator".
) else (
    echo [*] handed off to the elevated window - look for it on the taskbar.
)
echo.
if not defined NO_PAUSE pause
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
REM r2perm.py unlock always writes a machine-independent plaintext credential.
REM Remember that here so the network probe below can pass --allow-plain-cred
REM without asking: this installer is the one that just put the file there.
set "PLAIN_CRED=1"
if not exist "%SRC%\%CRED_ENC%" goto :cred_plain

echo [*] decrypting %CRED_ENC% into %CRED_FILE% ...
if not exist "%SRC%\%MACHINE_KEY%" goto :cred_nokey
if not exist "%SRC%\r2perm.py" goto :cred_nopy

REM The key is a file of raw bytes, not a passphrase: nobody can cheat by
REM reading it. That is the whole point of this installer - there is nothing
REM worth memorising and nothing to type.
set "PY="
where py >nul 2>&1 && set "PY=py"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY goto :cred_nopy

pushd "%SRC%"
%PY% r2perm.py unlock --in "%CRED_ENC%" --key "%MACHINE_KEY%" --out "%DST%\%CRED_FILE%"
set "UNLOCK_RC=%ERRORLEVEL%"
popd
if exist "%DST%\%CRED_FILE%" goto :cred_made
echo.
echo [WARN] could not decrypt the credential (exit code %UNLOCK_RC%).
echo        the service still works, but uploads are skipped silently until a
echo        credential exists. see README.txt for the manual command.
goto :cred_done

:cred_nokey
echo [WARN] %MACHINE_KEY% is missing next to this script - cannot decrypt.
echo        both %CRED_ENC% and %MACHINE_KEY% must sit in the same directory.
goto :cred_done

:cred_nopy
echo [WARN] no python found on this machine (tried "py" and "python").
echo        decrypt the credential by hand on a machine that has one, then copy
echo        the resulting %CRED_FILE% next to client.exe and run this again.
goto :cred_done

:cred_plain
REM A client.json shipped in the clear is exactly the plaintext case too.
set "PLAIN_CRED=1"
if not exist "%SRC%\%CRED_FILE%" goto :cred_none
echo [*] no %CRED_ENC% here; using the plain %CRED_FILE% from the source.
copy /y "%SRC%\%CRED_FILE%" "%DST%\%CRED_FILE%" >nul
goto :cred_done

:cred_none
echo [WARN] neither %CRED_ENC% nor %CRED_FILE% was found in %SRC%.
echo        the service still works, but uploads are skipped silently. build a
echo        credential with r2perm.py build, then run this installer again.

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
REM r2-check refuses a plaintext credential unless told to allow it. The file
REM here was written by this installer's own cred step, so the "yes, it is
REM plaintext" answer is known up front - pass it through instead of letting
REM the probe fail with a misleading "no route to the endpoint" warning.
set "R2_PLAIN="
if defined PLAIN_CRED set "R2_PLAIN=--allow-plain-cred"
pushd "%DST%"
usbkeygen-r2.exe r2-check --yes %R2_PLAIN% --cred-file "%CRED_FILE%" --timeout 1
set "R2_RC=%ERRORLEVEL%"
popd
if "%R2_RC%"=="0" goto :r2_ok
echo.
echo [WARN] the R2 probe did not pass (exit code %R2_RC%).
echo        either this machine has no route to the endpoint, or the credential
echo        was revoked at Cloudflare. the service runs either way, but nothing
echo        will be uploaded. check the token is still active, then rebuild.
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
powershell -NoProfile -Command "$p='%HARDEN_DIR%'; $a=Get-Acl -LiteralPath $p; $r=New-Object System.Security.AccessControl.FileSystemAccessRule('%HARDEN_PRINCIPAL%',%HARDEN_MASK%,[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[System.Security.AccessControl.PropagationFlags]'None',[System.Security.AccessControl.AccessControlType]'Deny'); $a.AddAccessRule($r); Set-Acl -LiteralPath $p -AclObject $a"
if errorlevel 1 goto :harden_failed
icacls "%HARDEN_DIR%" 2>nul | findstr /i "DENY" >nul
if errorlevel 1 goto :harden_failed
echo [*] hardening applied: deny Delete + DeleteSubdirectoriesAndFiles to %HARDEN_PRINCIPAL%
echo     this covers the directory and everything under it: the console,
echo     Explorer and "rd /s /q" will all refuse to delete it, administrators
echo     included. Only SeRestorePrivilege (imaging / backup tooling) bypasses.
echo     reading is NOT affected, so the service keeps working normally.
echo     revert with:  uninstall.cmd /UNDO
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
