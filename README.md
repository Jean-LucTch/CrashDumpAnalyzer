# CrashDumpAnalyzer

## English:

## Prerequisites

- Windows operating system
- Installed Windows Debugging Tools (cdb.exe)

### Installation of the Windows debugging tools

1. download the Windows SDK (for Windows 11 and earlier): [Windows SDK Download](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
2. start the installation program.
3. select **"Debugging Tools for Windows ”** and install them.

**Note:** Make a note of the installation path of `cdb.exe`. By default, this is `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`.

## Run the application

1. download the latest version of `CrashDumpAnalyzer.exe` from the GitHub releases.
2. make sure that `cdb.exe` is installed.
3. run `CrashDumpAnalyzer.exe`.
4. open a web browser and navigate to `http://localhost:5000`.

## Troubleshooting

- Error:** `Debugger not found`
  - **Solution:** Make sure that `cdb.exe` is installed in the expected location.


## German:

## Voraussetzungen

- Windows-Betriebssystem
- Installierte Windows Debugging Tools (cdb.exe)

### Installation der Windows Debugging Tools

1. Laden Sie das Windows SDK (für Windows 11 und früher) herunter: [Windows SDK Download](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
2. Starten Sie das Installationsprogramm.
3. Wählen Sie **"Debugging Tools for Windows"** aus und installieren Sie diese.

**Hinweis:** Notieren Sie sich den Installationspfad von `cdb.exe`. Standardmäßig ist dies `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`.

## Anwendung ausführen

1. Laden Sie die neueste Version von `CrashDumpAnalyzer.exe` von den GitHub-Releases herunter.
2. Stellen Sie sicher, dass `cdb.exe` installiert ist.
3. Führen Sie `CrashDumpAnalyzer.exe` aus.
4. Öffnen Sie einen Webbrowser und navigieren Sie zu `http://localhost:5000`.

## Fehlerbehebung

- **Fehler:** `Debugger nicht gefunden`
  - **Lösung:** Stellen Sie sicher, dass `cdb.exe` am erwarteten Ort installiert ist.
