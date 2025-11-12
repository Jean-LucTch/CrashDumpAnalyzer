import os
import re
import subprocess
import struct
from flask import flash
from flask_babel import gettext as _

# Constants for minidump parsing
MAX_STACK_ADDRESSES = 100  # Maximum number of stack addresses to parse
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000


def find_cdb_executable():
    possible_paths = [
        r'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe',
        r'C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe',
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None


def get_exception_description(code):
    """Extended exception code descriptions with detailed information"""
    exception_codes = {
        '0xC0000005': 'Access Violation - Memory access violation (read/write to invalid address)',
        '0x80000003': 'Breakpoint - Debug breakpoint encountered',
        '0x80000004': 'Single Step - Single step exception during debugging',
        '0xC0000094': 'Integer division by zero - Division by zero in integer operation',
        '0xC0000095': 'Integer overflow - Integer arithmetic overflow',
        '0xC00000FD': 'Stack Overflow - Stack buffer overflow detected',
        '0xC0000135': 'DLL not found - Required DLL could not be loaded',
        '0xC0000139': 'Entry point not found - DLL entry point not found',
        '0xC0000142': 'DLL initialization failed - DLL failed to initialize',
        '0xE0434352': '.NET exception - Unhandled .NET Framework exception',
        '0xC0000409': 'Stack buffer overflow - Stack-based buffer overflow',
        '0xC0000006': 'In-page error - Memory page error (disk/network issue)',
        '0xC0000008': 'Invalid handle - Invalid handle used in system call',
        '0xC000000D': 'Invalid parameter - Invalid parameter passed to function',
        '0xC000000E': 'Invalid address - Invalid memory address',
        '0xC000000F': 'Invalid request - Invalid request to device driver',
        '0xC0000010': 'Invalid access - Invalid access to memory location',
        '0xC0000011': 'Invalid data - Invalid data format',
        '0xC0000012': 'Invalid instruction - Invalid instruction executed',
        '0xC0000013': 'Invalid lock sequence - Invalid lock sequence',
        '0xC0000014': 'Invalid page fault - Invalid page fault',
        '0xC0000015': 'Invalid system call - Invalid system call',
        '0xC0000016': 'Invalid thread - Invalid thread identifier',
        '0xC0000017': 'Invalid token - Invalid access token',
        '0xC0000018': 'Invalid view size - Invalid view size',
        '0xC0000019': 'Invalid file for section - Invalid file for section',
        '0xC000001A': 'Invalid profile - Invalid profile',
        '0xC000001B': 'Invalid file - Invalid file',
        '0xC000001C': 'Invalid device - Invalid device',
        '0xC000001D': 'Invalid driver - Invalid driver',
        '0xC000001E': 'Invalid service - Invalid service',
        '0xC000001F': 'Invalid share - Invalid share',
        '0xC0000020': 'Invalid network - Invalid network',
        '0xC0000021': 'Invalid session - Invalid session',
        '0xC0000022': 'Invalid alias - Invalid alias',
        '0xC0000023': 'Invalid name - Invalid name',
        '0xC0000024': 'Invalid object - Invalid object',
        '0xC0000025': 'Invalid object type - Invalid object type',
        '0xC0000026': 'Invalid object name - Invalid object name',
        '0xC0000027': 'Invalid object path - Invalid object path',
        '0xC0000028': 'Invalid object attributes - Invalid object attributes',
        '0xC0000029': 'Invalid object security - Invalid object security',
        '0xC000002A': 'Invalid object owner - Invalid object owner',
        '0xC000002B': 'Invalid object group - Invalid object group',
        '0xC000002C': 'Invalid object acl - Invalid object ACL',
        '0xC000002D': 'Invalid object sid - Invalid object SID',
        '0xC0000030': 'Invalid object type name length - Invalid object type name length',
        '0xC0000031': 'Invalid object type name buffer - Invalid object type name buffer',
        '0xC0000032': 'Invalid object type name format - Invalid object type name format',
        '0xC0000033': 'Invalid object type name class - Invalid object type name class',
        '0xC0000034': 'Invalid object type name type - Invalid object type name type',
        '0xC0000035': 'Invalid object type name scope - Invalid object type name scope',
        '0xC0000036': 'Invalid object type name value - Invalid object type name value',
        '0xC0000037': 'Invalid object type name result - Invalid object type name result',
        '0xC0000038': 'Invalid object type name status - Invalid object type name status',
        '0xC0000096': 'Floating point division by zero - Division by zero in floating point operation',
    }
    code = code.strip()
    if code.lower().startswith('0x'):
        code = '0x' + code[2:].upper()
    else:
        code = '0x' + code.upper()
    
    # Check for known specific codes first
    if code in exception_codes:
        return exception_codes[code]
    
    # Handle floating-point exception range (0xC0000090-0xC00000FF) more efficiently
    try:
        code_int = int(code, 16)
        if 0xC0000090 <= code_int <= 0xC00000FF:
            return 'Floating point exception - Floating point arithmetic error'
    except ValueError:
        pass
    
    return _('Unknown error - Unrecognized exception code')


def parse_minidump_streams(dump_data):
    """Parse the minidump header and return available streams"""
    try:
        if len(dump_data) < 32:
            return {}
        header = struct.unpack_from('<IIIIIIQ', dump_data, 0)
        signature, _, num_streams, dir_rva, _, _, _ = header
        if signature != 0x504d444d:  # 'MDMP'
            return {}
        if dir_rva + num_streams * 12 > len(dump_data):
            return {}
        streams = {}
        for i in range(num_streams):
            off = dir_rva + i * 12
            stream_type, data_size, rva = struct.unpack_from('<III', dump_data, off)
            if rva + data_size <= len(dump_data):
                streams[stream_type] = {'rva': rva, 'size': data_size}
        return streams
    except struct.error:
        return {}


def read_utf16le_string(data, rva):
    """Read a UTF-16LE string from the given RVA"""
    try:
        length = struct.unpack_from('<I', data, rva)[0]
        start = rva + 4
        raw = data[start:start + length]
        return raw.decode('utf-16-le', errors='ignore')
    except Exception:
        return None


def parse_modules_from_streams(dump_data, streams):
    modules = []
    if 4 not in streams:
        return modules
    rva = streams[4]['rva']
    try:
        count = struct.unpack_from('<I', dump_data, rva)[0]
        offset = rva + 4
        for _ in range(count):
            if offset + 108 > len(dump_data):
                break
            base, size, checksum, timestamp, name_rva = struct.unpack_from('<QIIII', dump_data, offset)
            name = read_utf16le_string(dump_data, name_rva) or 'Unknown'
            modules.append({'name': name, 'base': base, 'size': size})
            offset += 108
    except struct.error:
        pass
    return modules


def parse_exception_stream(dump_data, streams):
    if 6 not in streams:
        return None, None, None
    rva = streams[6]['rva']
    try:
        thread_id = struct.unpack_from('<I', dump_data, rva)[0]
        exception_code = struct.unpack_from('<I', dump_data, rva + 8)[0]
        pointer_size = get_pointer_size(dump_data, streams)
        # MINIDUMP_EXCEPTION record starts at rva + 8
        # ExceptionAddress is at offset 16 for x64 (pointer_size=8), offset 12 for x86 (pointer_size=4)
        exception_record_offset = rva + 8
        if pointer_size == 8:
            exception_address_offset = exception_record_offset + 16
            exception_address = struct.unpack_from('<Q', dump_data, exception_address_offset)[0]
        else:
            exception_address_offset = exception_record_offset + 12
            exception_address = struct.unpack_from('<I', dump_data, exception_address_offset)[0]
        return thread_id, exception_code, exception_address
    except struct.error:
        return None, None, None


def get_pointer_size(dump_data, streams):
    if 7 in streams:
        try:
            arch = struct.unpack_from('<H', dump_data, streams[7]['rva'])[0]
            if arch in (0, 5):  # x86 or ARM
                return 4
        except struct.error:
            pass
    return 8


def parse_thread_stack(dump_data, streams, thread_id):
    if 3 not in streams:
        return None
    rva = streams[3]['rva']
    try:
        count = struct.unpack_from('<I', dump_data, rva)[0]
        offset = rva + 4
        for _ in range(count):
            if offset + 48 > len(dump_data):
                break
            tid = struct.unpack_from('<I', dump_data, offset)[0]
            if tid == thread_id:
                stack_start = struct.unpack_from('<Q', dump_data, offset + 24)[0]
                stack_size = struct.unpack_from('<I', dump_data, offset + 32)[0]
                stack_rva = struct.unpack_from('<I', dump_data, offset + 36)[0]
                end = stack_rva + stack_size
                if end <= len(dump_data):
                    return dump_data[stack_rva:end]
                return None
            offset += 48
    except struct.error:
        pass
    return None


def extract_callstack_info(dump_data):
    """Extract callstack information from minidump data"""
    try:
        streams = parse_minidump_streams(dump_data)
        thread_id, _, exception_address = parse_exception_stream(dump_data, streams)
        modules = parse_modules_from_streams(dump_data, streams)
        ptr_size = get_pointer_size(dump_data, streams)

        addresses = []
        if exception_address is not None:
            addresses.append(exception_address)

        stack_data = parse_thread_stack(dump_data, streams, thread_id)
        if stack_data:
            for i in range(0, min(len(stack_data), ptr_size * MAX_STACK_ADDRESSES), ptr_size):
                fmt = '<Q' if ptr_size == 8 else '<I'
                addr = struct.unpack_from(fmt, stack_data, i)[0]
                addresses.append(addr)

        callstack_info = []
        for addr in addresses[:10]:
            module_name = 'Unknown'
            for m in modules:
                if m['base'] <= addr < m['base'] + m['size']:
                    module_name = m['name']
                    break
            callstack_info.append({
                'address': f"0x{addr:016X}" if ptr_size == 8 else f"0x{addr:08X}",
                'function': 'Unknown',
                'module': module_name
            })
        return callstack_info
    except Exception:
        return []


def extract_memory_info(dump_data):
    """Extract memory region information from minidump data"""
    try:
        streams = parse_minidump_streams(dump_data)
        mem_info = []
        if 16 in streams:
            rva = streams[16]['rva']
            header_size, entry_size, count = struct.unpack_from('<IIQ', dump_data, rva)
            offset = rva + header_size
            type_map = {MEM_PRIVATE: 'MEM_PRIVATE', MEM_MAPPED: 'MEM_MAPPED', MEM_IMAGE: 'MEM_IMAGE'}
            for _ in range(min(count, 5)):
                if offset + entry_size > len(dump_data):
                    break
                base, _, _, _, region_size, state, protect, mtype, _ = struct.unpack_from('<QQIIQIIII', dump_data, offset)
                mem_info.append({
                    'address': f"0x{base:016X}",
                    'size': str(region_size),
                    'type': type_map.get(mtype, 'Unknown')
                })
                offset += entry_size
        elif 5 in streams:
            rva = streams[5]['rva']
            count = struct.unpack_from('<I', dump_data, rva)[0]
            offset = rva + 4
            for _ in range(min(count, 5)):
                if offset + 16 > len(dump_data):
                    break
                start, size, _rva = struct.unpack_from('<QII', dump_data, offset)
                mem_info.append({'address': f"0x{start:016X}", 'size': str(size), 'type': 'Unknown'})
                offset += 16
        return mem_info
    except Exception:
        return []


def extract_process_name(dump_data):
    """Extract process name from minidump data"""
    try:
        streams = parse_minidump_streams(dump_data)
        modules = parse_modules_from_streams(dump_data, streams)
        if modules:
            return modules[0]['name']
    except Exception:
        pass
    try:
        dump_str = dump_data.decode('utf-8', errors='ignore')
        exe_patterns = [r'([A-Za-z0-9_\-\.]+\.exe)', r'([A-Za-z0-9_\-\.]+\.dll)']
        for pattern in exe_patterns:
            matches = re.findall(pattern, dump_str)
            if matches:
                system_files = ['ntdll.dll', 'kernel32.dll', 'user32.dll', 'gdi32.dll']
                for match in matches:
                    if match.lower() not in system_files:
                        return match
    except Exception:
        pass
    return None


def extract_exception_code(dump_data):
    """Extract exception code from minidump data"""
    try:
        streams = parse_minidump_streams(dump_data)
        _, exception_code, _ = parse_exception_stream(dump_data, streams)
        if exception_code is not None:
            return f"0x{exception_code:08X}"
    except Exception:
        pass
    try:
        dump_str = dump_data.decode('utf-8', errors='ignore')
        exception_patterns = [r'0x[0-9A-Fa-f]{8}', r'0x[0-9A-Fa-f]{7}']
        for pattern in exception_patterns:
            matches = re.findall(pattern, dump_str)
            if matches:
                known_codes = ['0xC0000005', '0x80000003', '0x80000004', '0xC0000094',
                               '0xC0000095', '0xC00000FD', '0xC0000135', '0xC0000139',
                               '0xC0000142', '0xE0434352', '0xC0000409']
                for match in matches:
                    if match.upper() in known_codes:
                        return match.upper()
                return matches[0].upper()
    except Exception:
        pass
    return None


def extract_modules(dump_data):
    """Extract module names from minidump data"""
    try:
        streams = parse_minidump_streams(dump_data)
        modules = parse_modules_from_streams(dump_data, streams)
        return [m['name'] for m in modules[:20]]
    except Exception:
        return []


def extract_system_info(dump_data):
    """Extract system information from minidump data"""
    try:
        streams = parse_minidump_streams(dump_data)
        if 7 in streams:
            rva = streams[7]['rva']
            arch_val = struct.unpack_from('<H', dump_data, rva)[0]
            arch_map = {0: 'X86', 5: 'ARM', 6: 'IA64', 9: 'X64', 12: 'ARM64'}
            major = struct.unpack_from('<I', dump_data, rva + 8)[0]
            minor = struct.unpack_from('<I', dump_data, rva + 12)[0]
            build = struct.unpack_from('<I', dump_data, rva + 16)[0]
            return {
                'os_version': f"{major}.{minor}.{build}",
                'architecture': arch_map.get(arch_val, 'UNKNOWN')
            }
    except Exception:
        pass
    return {}


def analyze_dump(dump_file_path, ticket_number, analysis_folder):
    debugger_path = find_cdb_executable()
    if debugger_path is None:
        # Create an extended dump analysis without external library
        try:
            with open(dump_file_path, 'rb') as f:
                dump_data = f.read()
            
            analysis_filename = f"analysis_{ticket_number}.txt"
            analysis_path = os.path.join(analysis_folder, analysis_filename)
            
            # Create an extended analysis
            analysis_content = []
            analysis_content.append(f"Minidump Analysis Report")
            analysis_content.append(f"=" * 50)
            analysis_content.append(f"File: {dump_file_path}")
            analysis_content.append(f"File size: {len(dump_data)} bytes")
            analysis_content.append("")
            
            # Try to extract basic information from the dump
            try:
                # Look for known minidump signatures
                if len(dump_data) >= 4:
                    # Minidump header should start with "MDMP"
                    if dump_data[:4] == b'MDMP':
                        analysis_content.append("✓ Valid Minidump file detected")
                        analysis_content.append("")
                        
                        # Extract system information
                        system_info = extract_system_info(dump_data)
                        if system_info:
                            analysis_content.append("System Information:")
                            for key, value in system_info.items():
                                analysis_content.append(f"  {key.replace('_', ' ').title()}: {value}")
                            analysis_content.append("")
                        
                        # Try to extract basic information
                        analysis_content.append("Basic Dump Information:")
                        
                        # Look for process name in the dump
                        process_name = extract_process_name(dump_data)
                        if process_name:
                            analysis_content.append(f"  Process Name: {process_name}")
                        else:
                            analysis_content.append("  Process Name: Unknown")
                        
                        # Look for exception codes
                        exception_code = extract_exception_code(dump_data)
                        if exception_code:
                            analysis_content.append(f"  Exception Code: {exception_code}")
                            exception_description = get_exception_description(exception_code)
                            analysis_content.append(f"  Exception Description: {exception_description}")
                        else:
                            analysis_content.append("  Exception Code: Unknown")
                        
                        # Look for loaded modules
                        modules = extract_modules(dump_data)
                        if modules:
                            analysis_content.append("")
                            analysis_content.append("Loaded Modules (first 10):")
                            for i, module in enumerate(modules[:10]):
                                analysis_content.append(f"  {i+1}. {module}")
                        
                        # Extract callstack information
                        callstack_info = extract_callstack_info(dump_data)
                        if callstack_info:
                            analysis_content.append("")
                            analysis_content.append("Call Stack Information:")
                            for i, frame in enumerate(callstack_info):
                                analysis_content.append(f"  Frame {i+1}: {frame['address']} - {frame['function']} ({frame['module']})")
                        
                        # Extract memory information
                        memory_info = extract_memory_info(dump_data)
                        if memory_info:
                            analysis_content.append("")
                            analysis_content.append("Memory Information:")
                            for i, mem in enumerate(memory_info):
                                analysis_content.append(f"  Region {i+1}: {mem['address']} - Size: {mem['size']} - Type: {mem['type']}")
                        
                        # Determine application name
                        if process_name:
                            exe_name = process_name.split('\\')[-1] if '\\' in process_name else process_name
                        else:
                            exe_name = _("Unknown application")
                        
                        # Determine crash reason
                        if exception_code:
                            exception_description = get_exception_description(exception_code)
                            crash_reason = (f"{exception_code} - {exception_description}"
                                            if exception_description != _('Unknown error - Unrecognized exception code') else exception_code)
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
                # Fallback: Write raw dump information
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
            # Also write the error to the analysis file
            analysis_filename = f"analysis_{ticket_number}.txt"
            analysis_path = os.path.join(analysis_folder, analysis_filename)
            with open(analysis_path, 'w', encoding='utf-8') as f:
                f.write(f"Error during analysis: {str(e)}")
        return exe_name, crash_reason

    # Extended CDB analysis with more commands
    commands = [
        "!analyze -v",
        "k",  # Callstack
        "!peb",  # Process Environment Block
        "!teb",  # Thread Environment Block
        "lm",  # Loaded modules
        "!process",  # Process information
        "!thread",  # Thread information
        "!exception",  # Exception information
        "q"
    ]
    
    command = f'"{debugger_path}" -z "{dump_file_path}" -c "{"; ".join(commands)}"'

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, errors = process.communicate(timeout=120)  # Increased timeout for extended analysis
        output = output.decode('utf-8', errors='ignore')
        errors = errors.decode('utf-8', errors='ignore')

        analysis_filename = f"analysis_{ticket_number}.txt"
        analysis_path = os.path.join(analysis_folder, analysis_filename)
        with open(analysis_path, 'w', encoding='utf-8') as f:
            f.write(output)
            if errors:
                f.write(f"\n\nErrors:\n{errors}")

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
        if exception_description != _('Unknown error - Unrecognized exception code'):
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
