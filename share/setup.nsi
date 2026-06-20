# General Symbol Definitions
!define APPNAME "GNOBAN"
!define REGKEY "SOFTWARE\${APPNAME}"

Name "${APPNAME} v${VERSION}"

RequestExecutionLevel user
SetCompressor /SOLID lzma
SetDateSave off
Unicode true

# MUI Symbol Definitions
!define MUI_ICON "pixmaps\gnoban.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "pixmaps\nsis-wizard.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "pixmaps\nsis-header.bmp"
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_STARTMENUPAGE_REGISTRY_ROOT HKCU
!define MUI_STARTMENUPAGE_REGISTRY_KEY ${REGKEY}
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME StartMenuGroup
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "${APPNAME}"
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Open configuration file"
!define MUI_FINISHPAGE_RUN_FUNCTION OpenConfig
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\orange-uninstall.ico"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\orange-uninstall.bmp"
!define MUI_UNFINISHPAGE_NOAUTOCLOSE

# Included files
!include Sections.nsh
!include MUI2.nsh
!include x64.nsh

# Variables
Var StartMenuGroup

# Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuGroup
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

# Installer languages
!insertmacro MUI_LANGUAGE English

# Installer attributes
InstallDir "$LOCALAPPDATA\${APPNAME}"
CRCCheck force
XPStyle on
BrandingText " "
ShowInstDetails show
VIProductVersion "${VERSION}.0"
VIAddVersionKey ProductName "${APPNAME}"
VIAddVersionKey ProductVersion "${APPNAME} v${VERSION}"
VIAddVersionKey FileVersion "${APPNAME} v${VERSION}"
VIAddVersionKey FileDescription "Installer for ${APPNAME}"
VIAddVersionKey LegalCopyright "Copyright (C) 2025-2026 CaesarCoder <caesrcd@tutamail.com>"
InstallDirRegKey HKCU "${REGKEY}" Path
ShowUninstDetails show

# Installer sections
Section -Main SEC0000
    SetOutPath "$INSTDIR"
    SetOverwrite on
    File "..\build\gnoban.exe"
    File /oname=COPYING.txt "..\COPYING"
    IfFileExists "$INSTDIR\gnoban.toml" config_exists
        File "examples\gnoban.toml"
    config_exists:
    File "pixmaps\gnoban.ico"
    WriteRegStr HKCU "${REGKEY}\Components" Main 1
SectionEnd

Section -post SEC0001
    WriteRegStr HKCU "${REGKEY}" Path "$INSTDIR"
    SetOutPath "$INSTDIR"
    WriteUninstaller "$INSTDIR\uninstall.exe"
    !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
    CreateDirectory "$SMPROGRAMS\$StartMenuGroup"
    CreateShortcut "$SMPROGRAMS\$StartMenuGroup\${APPNAME}.lnk" "$SYSDIR\cmd.exe" '/k ""$INSTDIR\gnoban.exe" -conf gnoban.toml"' "$INSTDIR\gnoban.ico"
    CreateShortcut "$SMPROGRAMS\$StartMenuGroup\Uninstall ${APPNAME}.lnk" "$INSTDIR\uninstall.exe"
    !insertmacro MUI_STARTMENU_WRITE_END
    CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$SYSDIR\cmd.exe" '/k ""$INSTDIR\gnoban.exe" -conf gnoban.toml"' "$INSTDIR\gnoban.ico"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" DisplayName "${APPNAME}"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" DisplayVersion "${VERSION}"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" DisplayIcon "$INSTDIR\gnoban.ico"
    WriteRegStr HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" UninstallString "$INSTDIR\uninstall.exe"
    WriteRegDWORD HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" NoModify 1
    WriteRegDWORD HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" NoRepair 1
    EnVar::SetHKCU
    EnVar::Check "Path" "$INSTDIR"
    Pop $0
    StrCmp $0 "0" done_path
        EnVar::AddValue "Path" "$INSTDIR"
        Pop $0
    done_path:
SectionEnd

# Macro for selecting uninstaller sections
!macro SELECT_UNSECTION SECTION_NAME UNSECTION_ID
    Push $R0
    ReadRegStr $R0 HKCU "${REGKEY}\Components" "${SECTION_NAME}"
    StrCmp $R0 1 0 next${UNSECTION_ID}
        !insertmacro SelectSection "${UNSECTION_ID}"
        GoTo done${UNSECTION_ID}
    next${UNSECTION_ID}:
        !insertmacro UnselectSection "${UNSECTION_ID}"
    done${UNSECTION_ID}:
    Pop $R0
!macroend

# Uninstaller sections
Section /o -un.Main UNSEC0000
    Delete "$INSTDIR\gnoban.exe"
    Delete "$INSTDIR\gnoban.ico"
    Delete "$INSTDIR\gnoban.log"
    Delete "$INSTDIR\gnoban.toml"
    Delete "$INSTDIR\COPYING.txt"
    DeleteRegValue HKCU "${REGKEY}\Components" Main
SectionEnd

Section -un.post UNSEC0001
    EnVar::SetHKCU
    EnVar::DeleteValue "Path" "$INSTDIR"
    Pop $0
    DeleteRegKey HKCU "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
    Delete "$SMPROGRAMS\$StartMenuGroup\Uninstall ${APPNAME}.lnk"
    Delete "$SMPROGRAMS\$StartMenuGroup\${APPNAME}.lnk"
    Delete "$SMSTARTUP\${APPNAME}.lnk"
    Delete "$DESKTOP\${APPNAME}.lnk"
    Delete "$INSTDIR\uninstall.exe"
    DeleteRegValue HKCU "${REGKEY}" StartMenuGroup
    DeleteRegValue HKCU "${REGKEY}" Path
    DeleteRegKey /IfEmpty HKCU "${REGKEY}\Components"
    DeleteRegKey /IfEmpty HKCU "${REGKEY}"
    RmDir "$SMPROGRAMS\$StartMenuGroup"
    RmDir "$INSTDIR"
    Push $R0
    StrCpy $R0 $StartMenuGroup 1
    StrCmp $R0 ">" no_smgroup
    no_smgroup:
        Pop $R0
SectionEnd

# Installer functions
Function .onInit
    InitPluginsDir
    ${If} ${RunningX64}
        ; disable registry redirection (enable access to 64-bit portion of registry)
        SetRegView 64
    ${Else}
        MessageBox MB_OK|MB_ICONSTOP "Cannot install 64-bit version on a 32-bit system."
        Abort
    ${EndIf}
FunctionEnd

# Uninstaller functions
Function un.onInit
    ReadRegStr $INSTDIR HKCU "${REGKEY}" Path
    !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuGroup
    !insertmacro SELECT_UNSECTION Main ${UNSEC0000}
FunctionEnd

# Open config functions
Function OpenConfig
    Exec '"$WINDIR\notepad.exe" "$INSTDIR\gnoban.toml"'
FunctionEnd
