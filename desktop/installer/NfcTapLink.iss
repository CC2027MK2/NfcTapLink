; 一碰传 · 桌面端 安装程序脚本（Inno Setup 6）
; 编译：ISCC.exe NfcTapLink.iss
; 说明：用户级安装，无需管理员；数据目录在 %LOCALAPPDATA%\NfcTapLink，卸载不删除。

#define MyAppName "一碰传 桌面端"
#define MyAppShortName "一碰传"
#define MyAppVersion "6.2.5"
#define MyAppFileVersion "6.2.5.0"
#define MyAppPublisher "本地工具"
#define MyAppExeName "NfcTapLink.exe"
#define BuildRoot "..\desktop_build"
; PyInstaller 从 desktop_build 目录运行，产物默认在 desktop_build\dist\NfcTapLink。
#define MyDist "dist\NfcTapLink"
#define MyOutputName "dist_installer_v21"

[Setup]
AppId={{B7A4D2E1-3F8C-4A59-9E26-71C0D58B4A13}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
VersionInfoVersion={#MyAppFileVersion}
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoDescription={#MyAppName} {#MyAppVersion} 安装程序
DefaultDirName={autopf}\NfcTapLink
DefaultGroupName={#MyAppShortName}
DisableProgramGroupPage=yes
DisableWelcomePage=no
AllowNoIcons=yes
OutputDir={#BuildRoot}\{#MyOutputName}
OutputBaseFilename=NfcTapLink_Setup_{#MyAppVersion}
SetupIconFile={#BuildRoot}\nfctap.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName} {#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
RestartApplications=no
MinVersion=10.0
ShowLanguageDialog=no
AppendDefaultDirName=no
UsedUserAreasWarning=no

[Languages]
Name: "zh"; MessagesFile: "compiler:Default.isl"

[Messages]
SetupAppTitle=安装程序
SetupWindowTitle=安装 %1
UninstallAppTitle=卸载
UninstallAppFullTitle=卸载 %1
InformationTitle=提示
ConfirmTitle=确认
ErrorTitle=错误
SetupLdrStartupMessage=将安装 %1，是否继续？
SetupAlreadyRunning=安装程序已在运行。
WindowsVersionNotSupported=本程序不支持当前 Windows 版本。
OnlyOnTheseArchitectures=本程序只能安装到 64 位 Windows。
SetupAppRunningError=检测到 %1 正在运行，请先退出它再继续安装。
UninstallAppRunningError=检测到 %1 正在运行，请先退出它再卸载。
PrivilegesRequiredOverrideTitle=选择安装方式
PrivilegesRequiredOverrideInstruction=选择安装方式
PrivilegesRequiredOverrideAllUsers=为所有用户安装(&A)
PrivilegesRequiredOverrideAllUsersRecommended=为所有用户安装(&A)（推荐）
PrivilegesRequiredOverrideCurrentUser=仅为当前用户安装(&M)
PrivilegesRequiredOverrideCurrentUserRecommended=仅为当前用户安装(&M)（推荐）
ExitSetupTitle=退出安装
ExitSetupMessage=安装尚未完成。现在退出将不会安装程序。%n%n稍后可以重新运行安装程序。
AboutSetupMenuItem=关于安装程序(&A)
ButtonBack=< 上一步
ButtonNext=下一步 >
ButtonInstall=安装
ButtonOK=确定
ButtonCancel=取消
ButtonYes=是
ButtonNo=否
ButtonFinish=完成
ButtonBrowse=浏览…
ButtonNewFolder=新建文件夹
ClickNext=点击“下一步”继续，或点击“取消”退出安装。
WelcomeLabel1=欢迎使用 [name] 安装向导
WelcomeLabel2=这将在您的电脑上安装 [name/ver]。%n%n安装后可直接查看接收文件目录与最近传输记录；手机碰一下 NFC 标签即可传图片、Word、APK 等任意文件。%n%n接收的文件保存在用户数据目录 %LOCALAPPDATA%\NfcTapLink\received，卸载本程序不会删除这些文件。%n%n本版本采用 nfctap/3：安装包不含任何长期密钥，首次启动在本机生成随机配对密钥；配对走双向挑战应答，上传内容做应用层加密与防篡改校验。安装后请从桌面端「服务与设置」复制标签 URI 并写入物理 NFC 标签，旧版标签会失效。%n%n安装包内附带手机端 APK（mobile\NfcTapLink.apk），可在手机上直接安装或更新。
WizardSelectDir=选择安装位置
SelectDirDesc=要将 [name] 安装到哪里？
SelectDirLabel3=安装程序将把 [name] 安装到以下文件夹。
SelectDirBrowseLabel=点击“下一步”继续；如需更换文件夹，请点击“浏览”。
WizardSelectTasks=选择附加任务
SelectTasksDesc=还要执行哪些附加任务？
SelectTasksLabel2=选择附加任务，然后点击“下一步”。
WizardReady=准备安装
ReadyLabel1=安装程序已准备好，将在您的电脑上安装 [name]。
ReadyLabel2a=点击“安装”开始，或点击“上一步”修改设置。
ReadyMemoDir=安装位置：
ReadyMemoTasks=附加任务：
WizardInstalling=正在安装
InstallingLabel=正在安装 [name]，请稍候。
FinishedHeadingLabel=[name] 安装完成
FinishedLabel=已成功安装 [name]。%n%n首次启动会自动开启接收服务与蓝牙广播；手机亮屏解锁后碰一下 NFC 标签即可传送图片。
FinishedLabelNoIcons=已成功安装 [name]。
ClickFinish=点击“完成”退出安装程序。
StatusClosingApplications=正在关闭相关程序…
StatusCreateDirs=正在创建目录…
StatusExtractFiles=正在解压文件…
StatusCreateIcons=正在创建快捷方式…
StatusSavingUninstall=正在保存卸载信息…
StatusRunProgram=正在完成安装…
ConfirmUninstall=确定要完全移除 %1 及其所有组件吗？%n%n注意：您接收的文件保存在用户数据目录中，不会被删除。
UninstallStatusLabel=正在移除 %1，请稍候。
UninstalledAll=%1 已成功移除。
WizardUninstalling=卸载状态
StatusUninstalling=正在卸载 %1…
ApplicationsFound=以下程序正在使用需要更新的文件，建议先退出它们。
CloseApplications=自动关闭这些程序(&A)
DontCloseApplications=不关闭这些程序(&D)
ErrorCloseApplications=无法自动关闭相关程序，请先手动退出后重试。
FileExists2=文件已存在。
ExistingFileNewer2=现有文件比要安装的文件更新。
RunEntryExec=启动 %1
RunEntryShellExec=启动 %1
ComponentsDiskSpaceMBLabel=至少需要的可用磁盘空间(MB)：
DiskSpaceMBLabel=至少需要的可用磁盘空间(MB)：
CannotInstallToUNCPath=不能安装到 UNC 路径。
InvalidPath=路径无效。
InvalidDrive=驱动器无效。
SetupAborted=安装已中止。%n%n请修正问题后重新运行安装程序。
ErrorCreatingDir=无法创建目录“%1”。
ErrorTooManyFilesInDir=目录“%1”中文件过多，无法安装。

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式(&D)"; GroupDescription: "附加快捷方式："
Name: "openreceived"; Description: "安装完成后打开接收文件目录(&R)"; GroupDescription: "安装后："; Flags: unchecked

[Files]
; 主程序（PyInstaller onedir 产物，含 _internal 依赖目录；不含 config.seed.json）
Source: "{#BuildRoot}\{#MyDist}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; 手机端 APK 与图标，一并随包提供
Source: "{#BuildRoot}\payload\NfcTapLink.apk"; DestDir: "{app}\mobile"; Flags: ignoreversion
Source: "{#BuildRoot}\nfctap.ico"; DestDir: "{app}"; Flags: ignoreversion
; 安装向导里的简要说明（普通随包文件，不额外弹查看窗口）
Source: "{#BuildRoot}\payload\使用说明.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppShortName}"; Filename: "{app}\{#MyAppExeName}"; Comment: "查看接收文件与最近传输"
Name: "{group}\接收文件目录"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--open-received"; Comment: "打开接收目录"
Name: "{group}\手机端 APK 所在文件夹"; Filename: "{app}\mobile"; Comment: "NfcTapLink.apk 可传到手机安装"
Name: "{group}\卸载 {#MyAppShortName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppShortName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; Comment: "一碰传 · 桌面端"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 {#MyAppShortName}"; Flags: nowait postinstall skipifsilent unchecked
Filename: "{app}\{#MyAppExeName}"; Parameters: "--open-received"; Description: "打开接收文件目录"; Flags: nowait postinstall skipifsilent unchecked runhidden; Tasks: openreceived

[Registry]
; 开机自启由桌面端「服务与设置」开关写入 HKCU\...\Run（用户级，无需管理员），
; 安装时不创建；这里只登记卸载时删除，保证卸载后不留自启动残迹。
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "NfcTapLink"; Flags: dontcreatekey uninsdeletevalue

[UninstallDelete]
; 只清理程序目录里运行时可能生成的临时文件，用户数据目录一律保留
Type: files; Name: "{app}\*.log"
