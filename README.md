# CrashDumpAnalyzer

## English:

## Prerequisites

- Windows or Linux operating system
- On Windows, installing the Windows Debugging Tools (`cdb.exe`) enables extended analysis

### Installation of the Windows debugging tools

1. download the Windows 10 SDK: [Windows 10 SDK Download](https://developer.microsoft.com/de-de/windows/downloads/windows-10-sdk/)
2. start the installation program.
3. select **"Debugging Tools for Windows ”** and install them.

**Note:** Make a note of the installation path of `cdb.exe`. By default, this is `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`.

## Run the application

1. download the latest version of `CrashDumpAnalyzer.exe` from the GitHub releases.
2. on Windows, make sure that `cdb.exe` is installed (optional on other systems).
3. run `CrashDumpAnalyzer.exe`. The packaged application starts with a production
   server powered by Waitress.
4. open a web browser and navigate to `http://localhost:5000`.

Uploaded tickets are stored in a local SQLite database (`tickets.db`) which is
created automatically on first start. No additional setup is required to retain
analysis results between restarts.

## Troubleshooting

- **Error:** `Debugger not found`
  - **Solution:** Make sure that `cdb.exe` is installed in the expected location.

## German:

## Voraussetzungen

- Windows- oder Linux-Betriebssystem
- Unter Windows ermöglichen die Windows Debugging Tools (`cdb.exe`) eine erweiterte Analyse

### Installation der Windows Debugging Tools

1. Laden Sie das Windows 10 SDK herunter: [Windows 10 SDK Download](https://developer.microsoft.com/de-de/windows/downloads/windows-10-sdk/)
2. Starten Sie das Installationsprogramm.
3. Wählen Sie **"Debugging Tools for Windows"** aus und installieren Sie diese.

**Hinweis:** Notieren Sie sich den Installationspfad von `cdb.exe`. Standardmäßig ist dies `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe`.

## Anwendung ausführen

1. Laden Sie die neueste Version von `CrashDumpAnalyzer.exe` von den GitHub-Releases herunter.
2. Unter Windows sicherstellen, dass `cdb.exe` installiert ist (auf anderen Systemen optional).
3. Führen Sie `CrashDumpAnalyzer.exe` aus. Im Paket wird automatisch ein
   Produktionsserver (Waitress) gestartet.
4. Öffnen Sie einen Webbrowser und navigieren Sie zu `http://localhost:5000`.

Hochgeladene Tickets werden in einer lokalen SQLite-Datenbank (`tickets.db`)
gespeichert, die beim ersten Start automatisch erstellt wird. Die Analysen
bleiben so auch nach einem Neustart erhalten, ohne dass eine Einrichtung
erforderlich ist.

## Fehlerbehebung

- **Fehler:** `Debugger nicht gefunden`
  - **Lösung:** Stellen Sie sicher, dass `cdb.exe` am erwarteten Ort installiert ist.
