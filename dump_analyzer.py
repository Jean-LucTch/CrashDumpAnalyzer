import os
import re
import subprocess
from flask import flash
from flask_babel import gettext as _


def find_cdb_executable():
    possible_paths = [
        r'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe',
        r'C:\\Program Files\\Windows Kits\\10\\Debuggers\\x64\\cdb.exe',
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None


def get_exception_description(code):
    exception_codes = {
        '0xC0000005': 'Access Violation',
        '0x80000003': 'Breakpoint',
        '0x80000004': 'Single Step',
        '0xC0000094': 'Integer division by zero',
        '0xC0000095': 'Integer overflow',
        '0xC00000FD': 'Stack Overflow',
        '0xC0000135': 'DLL not found',
        '0xC0000139': 'Entry point not found',
        '0xC0000142': 'DLL initialization failed',
        '0xE0434352': '.NET exception',
        '0xC0000409': 'Stack buffer overflow',
    }
    code = code.strip()
    if code.lower().startswith('0x'):
        code = '0x' + code[2:].upper()
    else:
        code = '0x' + code.upper()
    return exception_codes.get(code, _('Unknown error'))


def extract_process_name(dump_data):
    """Extract process name from minidump data"""
    try:
        # Suche nach .exe Dateinamen im Dump
        # Konvertiere zu String und suche nach .exe
        dump_str = dump_data.decode('utf-8', errors='ignore')
        
        # Suche nach .exe Dateien
        exe_patterns = [
            r'([A-Za-z0-9_\-\.]+\.exe)',
            r'([A-Za-z0-9_\-\.]+\.dll)',
        ]
        
        for pattern in exe_patterns:
            matches = re.findall(pattern, dump_str)
            if matches:
                # Filtere bekannte System-Dateien
                system_files = ['ntdll.dll', 'kernel32.dll', 'user32.dll', 'gdi32.dll']
                for match in matches:
                    if match.lower() not in system_files:
                        return match
        return None
    except:
        return None


def extract_exception_code(dump_data):
    """Extract exception code from minidump data"""
    try:
        # Suche nach Exception-Codes im Dump
        dump_str = dump_data.decode('utf-8', errors='ignore')
        
        # Suche nach hexadezimalen Exception-Codes
        exception_patterns = [
            r'0x[0-9A-Fa-f]{8}',  # 8-stellige hex Codes
            r'0x[0-9A-Fa-f]{7}',  # 7-stellige hex Codes
        ]
        
        for pattern in exception_patterns:
            matches = re.findall(pattern, dump_str)
            if matches:
                # Filtere bekannte Exception-Codes
                known_codes = ['0xC0000005', '0x80000003', '0x80000004', '0xC0000094', 
                              '0xC0000095', '0xC00000FD', '0xC0000135', '0xC0000139', 
                              '0xC0000142', '0xE0434352', '0xC0000409']
                for match in matches:
                    if match.upper() in known_codes:
                        return match.upper()
                # Falls kein bekannter Code gefunden wurde, nimm den ersten
                if matches:
                    return matches[0].upper()
        return None
    except:
        return None


def extract_modules(dump_data):
    """Extract module names from minidump data"""
    try:
        # Suche nach Modul-Namen im Dump
        dump_str = dump_data.decode('utf-8', errors='ignore')
        
        # Suche nach .dll und .exe Dateien
        module_pattern = r'([A-Za-z0-9_\-\.]+\.(dll|exe))'
        matches = re.findall(module_pattern, dump_str)
        
        # Entferne Duplikate und System-Dateien
        modules = []
        system_files = ['ntdll.dll', 'kernel32.dll', 'user32.dll', 'gdi32.dll', 
                       'msvcrt.dll', 'ole32.dll', 'oleaut32.dll', 'advapi32.dll']
        
        for match in matches:
            module_name = match[0]
            if module_name.lower() not in system_files and module_name not in modules:
                modules.append(module_name)
        
        return modules[:20]  # Maximal 20 Module zurückgeben
    except:
        return []


def analyze_dump(dump_file_path, ticket_number, analysis_folder):
    debugger_path = find_cdb_executable()
    if debugger_path is None:
        # Erstelle eine einfache Dump-Analyse ohne externe Bibliothek
        try:
            with open(dump_file_path, 'rb') as f:
                dump_data = f.read()
            
            analysis_filename = f"analysis_{ticket_number}.txt"
            analysis_path = os.path.join(analysis_folder, analysis_filename)
            
            # Erstelle eine grundlegende Analyse
            analysis_content = []
            analysis_content.append(f"Minidump Analysis Report")
            analysis_content.append(f"=" * 50)
            analysis_content.append(f"File: {dump_file_path}")
            analysis_content.append(f"File size: {len(dump_data)} bytes")
            analysis_content.append("")
            
            # Versuche, grundlegende Informationen aus dem Dump zu extrahieren
            try:
                # Suche nach bekannten Minidump-Signaturen
                if len(dump_data) >= 4:
                    # Minidump Header sollte mit "MDMP" beginnen
                    if dump_data[:4] == b'MDMP':
                        analysis_content.append("✓ Valid Minidump file detected")
                        analysis_content.append("")
                        
                        # Versuche, grundlegende Informationen zu extrahieren
                        analysis_content.append("Basic Dump Information:")
                        
                        # Suche nach Prozessnamen im Dump
                        process_name = extract_process_name(dump_data)
                        if process_name:
                            analysis_content.append(f"  Process Name: {process_name}")
                        else:
                            analysis_content.append("  Process Name: Unknown")
                        
                        # Suche nach Exception-Codes
                        exception_code = extract_exception_code(dump_data)
                        if exception_code:
                            analysis_content.append(f"  Exception Code: {exception_code}")
                            exception_description = get_exception_description(exception_code)
                            if exception_description != _('Unknown error'):
                                analysis_content.append(f"  Exception Description: {exception_description}")
                        else:
                            analysis_content.append("  Exception Code: Unknown")
                        
                        # Suche nach geladenen Modulen
                        modules = extract_modules(dump_data)
                        if modules:
                            analysis_content.append("")
                            analysis_content.append("Loaded Modules (first 10):")
                            for i, module in enumerate(modules[:10]):
                                analysis_content.append(f"  {i+1}. {module}")
                        
                        # Bestimme den Anwendungsnamen
                        if process_name:
                            exe_name = process_name.split('\\')[-1] if '\\' in process_name else process_name
                        else:
                            exe_name = _("Unknown application")
                        
                        # Bestimme den Crash-Grund
                        if exception_code:
                            exception_description = get_exception_description(exception_code)
                            crash_reason = (f"{exception_code} - {exception_description}"
                                            if exception_description != _('Unknown error') else exception_code)
                        else:
                            crash_reason = _("Unknown error")
                    else:
                        analysis_content.append("✗ Invalid Minidump file (missing MDMP signature)")
                        exe_name = _("Invalid dump file")
                        crash_reason = _("File is not a valid minidump")
                else:
                    analysis_content.append("✗ File too small to be a valid minidump")
                    exe_name = _("Invalid dump file")
                    crash_reason = _("File too small")
                
                with open(analysis_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(analysis_content))
                
            except Exception as parse_error:
                # Fallback: Schreibe rohe Dump-Informationen
                analysis_content.append("Raw Dump Analysis:")
                analysis_content.append(f"  Error parsing dump: {str(parse_error)}")
                analysis_content.append("  This might be a corrupted or unsupported dump file.")
                
                with open(analysis_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(analysis_content))
                
                exe_name = _("Unknown application")
                crash_reason = _("Dump parsing failed")
                
        except Exception as e:
            exe_name = _("Errors in the analysis")
            crash_reason = str(e)
            # Schreibe auch den Fehler in die Analyse-Datei
            analysis_filename = f"analysis_{ticket_number}.txt"
            analysis_path = os.path.join(analysis_folder, analysis_filename)
            with open(analysis_path, 'w', encoding='utf-8') as f:
                f.write(f"Error during analysis: {str(e)}")
        return exe_name, crash_reason

    command = f'"{debugger_path}" -z "{dump_file_path}" -c "!analyze -v; q"'

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, errors = process.communicate(timeout=60)
        output = output.decode('utf-8', errors='ignore')
        errors = errors.decode('utf-8', errors='ignore')

        analysis_filename = f"analysis_{ticket_number}.txt"
        analysis_path = os.path.join(analysis_folder, analysis_filename)
        with open(analysis_path, 'w', encoding='utf-8') as f:
            f.write(output)

        process_name_match = re.search(r'PROCESS_NAME:\s+(\S+)', output)
        if process_name_match:
            exe_name = process_name_match.group(1)
        else:
            image_name_match = re.search(r'IMAGE_NAME:\s+(\S+)', output)
            exe_name = image_name_match.group(1) if image_name_match else _("Unknown application")

        exception_code_match = re.search(r'ExceptionCode:\s+(\S+)', output)
        if exception_code_match:
            exception_code = exception_code_match.group(1)
        else:
            exception_code = _("Unknown error")

        exception_description = get_exception_description(exception_code)
        if exception_description != _('Unknown error'):
            crash_reason = f"{exception_code} - {exception_description}"
        else:
            crash_reason = exception_code

    except subprocess.TimeoutExpired:
        exe_name = _("Analysis canceled")
        crash_reason = _("The debugger did not respond within the expected time.")
    except Exception as e:
        exe_name = _("Errors in the analysis")
        crash_reason = str(e)

    return exe_name, crash_reason
