; napp.iss - Inno Setup script for NetMonApp

[Setup]
AppName=NetMonApp
AppVersion=latest
DefaultDirName={autopf}\NetMonApp
DefaultGroupName=NetMonApp
OutputDir=installer_output
OutputBaseFilename=NetMonAppInstaller
Compression=lzma2/ultra
SolidCompression=yes
SetupIconFile=assets\icon.ico
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\napp.exe
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "dist\napp.dist\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

[Icons]
Name: "{group}\NetMonApp"; Filename: "{app}\napp.exe"
Name: "{commondesktop}\NetMonApp"; Filename: "{app}\napp.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; GroupDescription: "Additional icons:"

[Run]
Filename: "{app}\napp.exe"; Description: "Launch NetMonApp"; Flags: nowait postinstall skipifsilent