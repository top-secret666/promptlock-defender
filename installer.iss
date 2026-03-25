; PromptLock Defender — Inno Setup Installer Script
; ================================================
;
; Как использовать:
;   1. Скачайте Inno Setup: https://jrsoftware.org/isinfo.php
;   2. Сначала соберите EXE: python build_exe.py
;   3. Откройте этот файл в Inno Setup Compiler
;   4. Нажмите Build → Compile
;   5. Получите: Output\Setup_PromptLockDefender.exe
;
; Установщик:
;   - Копирует PromptLockDefender в Program Files
;   - Создаёт ярлык на рабочем столе и в меню Пуск
;   - Добавляет деинсталлятор
;   - Проверяет что Windows 10+ (Python 3.11 требует)

[Setup]
AppName=PromptLock Defender
AppVersion=2.0
AppPublisher=PromptLock Defender Team
AppPublisherURL=https://github.com/promptlock-defender
DefaultDirName={autopf}\PromptLockDefender
DefaultGroupName=PromptLock Defender
OutputDir=Output
OutputBaseFilename=Setup_PromptLockDefender
; Если есть иконка — раскомментируйте:
; SetupIconFile=icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Красивые цвета
WizardImageFile=compiler:WizModernImage-IS.bmp
WizardSmallImageFile=compiler:WizModernSmallImage-IS.bmp

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные ярлыки:"; Flags: checked

[Files]
; Копируем всю папку dist/PromptLockDefender/ в Program Files
Source: "dist\PromptLockDefender\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Копируем VC++ Redistributable если есть (опционально)
; Source: "redist\vc_redist.x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: VCRedistNeeded

[Icons]
Name: "{group}\PromptLock Defender"; Filename: "{app}\PromptLockDefender.exe"; Comment: "Антивирус для AI-ransomware угроз"
Name: "{group}\Удалить PromptLock Defender"; Filename: "{uninstallexe}"
Name: "{autodesktop}\PromptLock Defender"; Filename: "{app}\PromptLockDefender.exe"; Tasks: desktopicon; Comment: "Антивирус для AI-ransomware угроз"

[Run]
; Запустить после установки
Filename: "{app}\PromptLockDefender.exe"; Description: "Запустить PromptLock Defender"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Messages]
russian.BeveledLabel=PromptLock Defender v2.0

[Code]
// Проверка версии Windows при запуске установки
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('PromptLock Defender требует 64-битную Windows 10 или новее.' + #13#10 +
           'Ваша система не поддерживается.', mbError, MB_OK);
    Result := False;
  end;
end;
