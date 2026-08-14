; BARAQ setup script (Inno Setup 6).
; Compiled by scripts\build_installer.ps1 (stages dist + scripts under staging).
; Behaviour:
;   * installs the server folder-build to {app} (Program Files when elevated)
;   * installs no services yet - [Run] steps provision PostgreSQL (portable
;     cluster under %LOCALAPPDATA%\BARAQ\postgres), provision the
;     database, and register the backend autostart (NSSM service if present,
;     logon task otherwise). All machine-independent - no hard-coded paths.
;   * leaves the database data directory behind on uninstall (operator data)

#ifndef AppVersion
#define AppVersion "1.0.0"
#endif
#define AppName "BARAQ"
#define AppExeName "BARAQ.exe"

[Setup]
AppId={{0E2B7A4C-9F1E-4D3B-8A5C-BARAQSOC01}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=BARAQ
DefaultDirName={autopf}\BARAQ
DefaultGroupName=BARAQ
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputBaseFilename=BARAQ-Setup-{#AppVersion}
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "pg"; Description: "Provision local PostgreSQL 16 (downloads portable binaries into {#AppName}\pg on first install)"
Name: "service"; Description: "Register BARAQ to start automatically on logon (logon task, or NSSM service if present)"
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
; users-modify: the console writes logs/.env/secrets.dat/reports next to the
; exe, so non-elevated operators must be able to write under {app}.
Source: "staging\server\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs; Permissions: users-modify
Source: "staging\scripts\*"; DestDir: "{app}\scripts"; Flags: recursesubdirs createallsubdirs; Permissions: users-modify

[Icons]
Name: "{group}\BARAQ"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\BARAQ"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; 1) portable PostgreSQL: download binaries if needed, init+start cluster
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\download_postgres.ps1"""; Tasks: pg; Flags: waituntilterminated runhidden
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\pg_setup.ps1"" -Action ensure"; Flags: waituntilterminated runhidden
; 2) create the baraq database / app role and write .env
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\provision_postgres.ps1"" -Password baraq"; Flags: waituntilterminated runhidden
; 3) persistent autostart (NSSM service when available, logon task otherwise)
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\install_service.ps1"" install"; Tasks: service; Flags: waituntilterminated runhidden
; 4) fallback: if no autostart was chosen, still launch the console once
Filename: "{app}\{#AppExeName}"; Description: "Launch the BARAQ console now"; Flags: nowait postinstall runascurrentuser skipifsilent; Check: NotServiceChecked

[Code]
function NotServiceChecked(): Boolean;
begin
  Result := not WizardIsTaskSelected('service');
end;

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\install_service.ps1"" uninstall"; Flags: runhidden waituntilterminated
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\scripts\pg_setup.ps1"" -Action stop"; Flags: runhidden waituntilterminated

[UninstallDelete]
; operator data (database cluster, secrets vault, reports) intentionally kept
Type: filesandordirs; Name: "{app}\logs"