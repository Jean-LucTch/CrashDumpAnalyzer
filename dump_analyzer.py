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


def analyze_dump(dump_file_path, ticket_number, analysis_folder):
    debugger_path = find_cdb_executable()
    if debugger_path is None:
        try:
            from minidump import MinidumpFile
        except Exception:
            flash(_('cdb.exe could not be found. Please install the Windows debugging tools.'))
            analysis_filename = f"analysis_{ticket_number}.txt"
            analysis_path = os.path.join(analysis_folder, analysis_filename)
            with open(analysis_path, 'w', encoding='utf-8') as f:
                f.write(_('Debugger not found'))
            return _("Unknown application"), _('Debugger not found')

        try:
            md = MinidumpFile.parse(dump_file_path)
            analysis_filename = f"analysis_{ticket_number}.txt"
            analysis_path = os.path.join(analysis_folder, analysis_filename)
            with open(analysis_path, 'w', encoding='utf-8') as f:
                f.write(str(md))

            exe_name = md.modules.modules[0].name if md.modules.modules else _("Unknown application")
            if md.exception:
                exception_code = f"0x{md.exception.exception_record.exception_code:08X}"
            else:
                exception_code = _("Unknown error")

            exception_description = get_exception_description(exception_code)
            crash_reason = (f"{exception_code} - {exception_description}"
                            if exception_description != _('Unknown error') else exception_code)
        except Exception as e:
            exe_name = _("Errors in the analysis")
            crash_reason = str(e)
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
