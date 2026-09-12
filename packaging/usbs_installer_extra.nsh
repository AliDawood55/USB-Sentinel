; USB Sentinel installer customizations (Phase 10 packaging).
;
; Included into the CPack-generated NSIS script via CPACK_NSIS_DEFINES.
; Kept in a real .nsh file, rather than embedded as CMake string
; variables, because CPack re-serializes CPACK_NSIS_* string values into
; CPackConfig.cmake as plain double-quoted CMake strings without
; re-escaping embedded backslashes -- any Windows path written directly
; into those variables fails to reparse ("Invalid escape sequence").
; Referencing this file by path (CMake always renders
; CMAKE_CURRENT_SOURCE_DIR with forward slashes) sidesteps that
; entirely, and keeps the actual NSIS script reviewable as real code
; instead of a giant embedded string.
;
; The stock CPack NSIS template (NSIS.template.in, shipped with CMake)
; unconditionally sets "RequestExecutionLevel admin", and its own
; .onInit redirects the install directory to $DOCUMENTS and forces
; SetShellVarContext all whenever the installing account is an
; Administrator or Power User -- the common case on a personal machine.
; Left alone, that would silently violate the per-user, no-elevation
; install this project decided on for Phase 10. See ARCHITECTURE.md
; S16 for the full investigation (verified against this exact template
; file, not assumed).
;
; The registry side of this works because the stock template writes
; its Apps & Features entry through the NSIS "SHCTX" pseudo-hive, which
; follows SetShellVarContext (HKCU when "current", HKLM when "all") --
; forcing "current" is enough for a full per-user install to register
; correctly without ever touching HKLM.

RequestExecutionLevel user

; Opt-in "launch at login" checkbox on the finish page, unchecked by
; default -- repurposes the stock MUI "Show Readme" checkbox to call a
; function instead of opening a file. Confirmed against NSIS's own
; Modern UI documentation, not guessed.
!define MUI_FINISHPAGE_SHOWREADME
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Launch USB Sentinel when I log in"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION UsbsCreateStartupShortcut
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED

Function UsbsCreateStartupShortcut
  CreateDirectory "$SMSTARTUP"
  CreateShortCut "$SMSTARTUP\USB Sentinel.lnk" "$INSTDIR\bin\usb-sentinel-gui.exe"
FunctionEnd

; Invoked from CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS: runs at the top of
; the install Section, before any files are copied, but after every
; wizard page (including Directory) has already run. Only corrects
; $INSTDIR if it still holds the stock template's Administrator/Power-
; User fallback ($DOCUMENTS\USB Sentinel) -- i.e. only when the user
; did NOT deliberately browse to a different folder on the Directory
; page. A real, deliberate user choice is left alone.
;
; The stock template's install Section opens with a bare
; "SetOutPath $INSTDIR" *before* CPACK_NSIS_EXTRA_PREINSTALL_COMMANDS
; runs -- SetOutPath snapshots $INSTDIR's value at that moment as the
; destination for the "File /r" that copies the whole staged tree right
; after this macro, it does not track the variable live. Left alone,
; that snapshot is taken from the pre-correction $INSTDIR, so files
; land in the wrong place (the stock $DOCUMENTS fallback for an
; Administrator account) while every later use of $INSTDIR --
; CreateShortCut, WriteUninstaller, the registry entries -- reads the
; variable fresh and correctly picks up the corrected value: files in
; one place, shortcut pointing at another. Re-issuing SetOutPath here,
; after the correction, re-snapshots it before that copy happens.
!macro UsbsFixInstallContext
  SetShellVarContext current
  StrCmp "$INSTDIR" "$DOCUMENTS\USB Sentinel" 0 +2
    StrCpy $INSTDIR "$LOCALAPPDATA\Programs\USB Sentinel"
  SetOutPath "$INSTDIR"
!macroend

; Invoked from CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS: matches the same
; per-user shell context so the uninstaller finds (and only removes)
; what this installer actually created -- program files, the Start
; Menu entry, the optional Startup shortcut, and the HKCU uninstall
; registration. %LOCALAPPDATA%\USBSentinel\ (scan history and the
; user's own signatures file) is a separate directory tree this
; uninstaller never references, so it is untouched by construction,
; not by a special-cased exclusion.
!macro UsbsUninstallExtra
  SetShellVarContext current
  Delete "$SMSTARTUP\USB Sentinel.lnk"
!macroend
