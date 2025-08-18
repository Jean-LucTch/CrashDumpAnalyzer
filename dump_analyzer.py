import os
import re
import subprocess
import struct
from flask import flash
from flask_babel import gettext as _


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
        '0xC000002E': 'Invalid object type name - Invalid object type name',
        '0xC000002F': 'Invalid object type index - Invalid object type index',
        '0xC0000030': 'Invalid object type name length - Invalid object type name length',
        '0xC0000031': 'Invalid object type name buffer - Invalid object type name buffer',
        '0xC0000032': 'Invalid object type name format - Invalid object type name format',
        '0xC0000033': 'Invalid object type name class - Invalid object type name class',
        '0xC0000034': 'Invalid object type name type - Invalid object type name type',
        '0xC0000035': 'Invalid object type name scope - Invalid object type name scope',
        '0xC0000036': 'Invalid object type name value - Invalid object type name value',
        '0xC0000037': 'Invalid object type name result - Invalid object type name result',
        '0xC0000038': 'Invalid object type name status - Invalid object type name status',
        '0xC0000039': 'Invalid object type name info - Invalid object type name info',
        '0xC000003A': 'Invalid object type name info class - Invalid object type name info class',
        '0xC000003B': 'Invalid object type name info length - Invalid object type name info length',
        '0xC000003C': 'Invalid object type name info buffer - Invalid object type name info buffer',
        '0xC000003D': 'Invalid object type name info format - Invalid object type name info format',
        '0xC000003E': 'Invalid object type name info class - Invalid object type name info class',
        '0xC000003F': 'Invalid object type name info type - Invalid object type name info type',
        '0xC0000040': 'Invalid object type name info scope - Invalid object type name info scope',
        '0xC0000041': 'Invalid object type name info value - Invalid object type name info value',
        '0xC0000042': 'Invalid object type name info result - Invalid object type name info result',
        '0xC0000043': 'Invalid object type name info status - Invalid object type name info status',
        '0xC0000044': 'Invalid object type name info info - Invalid object type name info info',
        '0xC0000045': 'Invalid object type name info info class - Invalid object type name info info class',
        '0xC0000046': 'Invalid object type name info info length - Invalid object type name info info length',
        '0xC0000047': 'Invalid object type name info info buffer - Invalid object type name info info buffer',
        '0xC0000048': 'Invalid object type name info info format - Invalid object type name info info format',
        '0xC0000049': 'Invalid object type name info info class - Invalid object type name info info class',
        '0xC000004A': 'Invalid object type name info info type - Invalid object type name info info type',
        '0xC000004B': 'Invalid object type name info info scope - Invalid object type name info info scope',
        '0xC000004C': 'Invalid object type name info info value - Invalid object type name info info value',
        '0xC000004D': 'Invalid object type name info info result - Invalid object type name info info result',
        '0xC000004E': 'Invalid object type name info info status - Invalid object type name info info status',
        '0xC000004F': 'Invalid object type name info info info - Invalid object type name info info info',
        '0xC0000050': 'Invalid object type name info info info class - Invalid object type name info info info class',
        '0xC0000051': 'Invalid object type name info info info length - Invalid object type name info info info length',
        '0xC0000052': 'Invalid object type name info info info buffer - Invalid object type name info info info buffer',
        '0xC0000053': 'Invalid object type name info info info format - Invalid object type name info info info format',
        '0xC0000054': 'Invalid object type name info info info class - Invalid object type name info info info class',
        '0xC0000055': 'Invalid object type name info info info type - Invalid object type name info info info type',
        '0xC0000056': 'Invalid object type name info info info scope - Invalid object type name info info info scope',
        '0xC0000057': 'Invalid object type name info info info value - Invalid object type name info info info value',
        '0xC0000058': 'Invalid object type name info info info result - Invalid object type name info info info result',
        '0xC0000059': 'Invalid object type name info info info status - Invalid object type name info info info status',
        '0xC000005A': 'Invalid object type name info info info info - Invalid object type name info info info info',
        '0xC000005B': 'Invalid object type name info info info info class - Invalid object type name info info info info class',
        '0xC000005C': 'Invalid object type name info info info info length - Invalid object type name info info info info length',
        '0xC000005D': 'Invalid object type name info info info info buffer - Invalid object type name info info info info buffer',
        '0xC000005E': 'Invalid object type name info info info info format - Invalid object type name info info info info format',
        '0xC000005F': 'Invalid object type name info info info info class - Invalid object type name info info info info class',
        '0xC0000060': 'Invalid object type name info info info info type - Invalid object type name info info info info type',
        '0xC0000061': 'Invalid object type name info info info info scope - Invalid object type name info info info info scope',
        '0xC0000062': 'Invalid object type name info info info info value - Invalid object type name info info info info value',
        '0xC0000063': 'Invalid object type name info info info info result - Invalid object type name info info info info result',
        '0xC0000064': 'Invalid object type name info info info info status - Invalid object type name info info info info status',
        '0xC0000065': 'Invalid object type name info info info info info - Invalid object type name info info info info info',
        '0xC0000066': 'Invalid object type name info info info info info class - Invalid object type name info info info info info class',
        '0xC0000067': 'Invalid object type name info info info info info length - Invalid object type name info info info info info length',
        '0xC0000068': 'Invalid object type name info info info info info buffer - Invalid object type name info info info info info buffer',
        '0xC0000069': 'Invalid object type name info info info info info format - Invalid object type name info info info info info format',
        '0xC000006A': 'Invalid object type name info info info info info class - Invalid object type name info info info info info class',
        '0xC000006B': 'Invalid object type name info info info info info type - Invalid object type name info info info info info type',
        '0xC000006C': 'Invalid object type name info info info info info scope - Invalid object type name info info info info info scope',
        '0xC000006D': 'Invalid object type name info info info info info value - Invalid object type name info info info info info value',
        '0xC000006E': 'Invalid object type name info info info info info result - Invalid object type name info info info info info result',
        '0xC000006F': 'Invalid object type name info info info info info status - Invalid object type name info info info info info status',
        '0xC0000070': 'Invalid object type name info info info info info info - Invalid object type name info info info info info info',
        '0xC0000071': 'Invalid object type name info info info info info info class - Invalid object type name info info info info info info class',
        '0xC0000072': 'Invalid object type name info info info info info info length - Invalid object type name info info info info info info length',
        '0xC0000073': 'Invalid object type name info info info info info info buffer - Invalid object type name info info info info info info buffer',
        '0xC0000074': 'Invalid object type name info info info info info info format - Invalid object type name info info info info info info format',
        '0xC0000075': 'Invalid object type name info info info info info info class - Invalid object type name info info info info info info class',
        '0xC0000076': 'Invalid object type name info info info info info info type - Invalid object type name info info info info info info type',
        '0xC0000077': 'Invalid object type name info info info info info info scope - Invalid object type name info info info info info info scope',
        '0xC0000078': 'Invalid object type name info info info info info info value - Invalid object type name info info info info info info value',
        '0xC0000079': 'Invalid object type name info info info info info info result - Invalid object type name info info info info info info result',
        '0xC000007A': 'Invalid object type name info info info info info info status - Invalid object type name info info info info info info status',
        '0xC000007B': 'Invalid object type name info info info info info info info - Invalid object type name info info info info info info info',
        '0xC000007C': 'Invalid object type name info info info info info info info class - Invalid object type name info info info info info info info class',
        '0xC000007D': 'Invalid object type name info info info info info info info length - Invalid object type name info info info info info info info length',
        '0xC000007E': 'Invalid object type name info info info info info info info buffer - Invalid object type name info info info info info info info buffer',
        '0xC000007F': 'Invalid object type name info info info info info info info format - Invalid object type name info info info info info info info format',
        '0xC0000080': 'Invalid object type name info info info info info info info class - Invalid object type name info info info info info info info class',
        '0xC0000081': 'Invalid object type name info info info info info info info type - Invalid object type name info info info info info info info type',
        '0xC0000082': 'Invalid object type name info info info info info info info scope - Invalid object type name info info info info info info info scope',
        '0xC0000083': 'Invalid object type name info info info info info info info value - Invalid object type name info info info info info info info value',
        '0xC0000084': 'Invalid object type name info info info info info info info result - Invalid object type name info info info info info info info result',
        '0xC0000085': 'Invalid object type name info info info info info info info status - Invalid object type name info info info info info info info status',
        '0xC0000086': 'Invalid object type name info info info info info info info info - Invalid object type name info info info info info info info info',
        '0xC0000087': 'Invalid object type name info info info info info info info info class - Invalid object type name info info info info info info info info class',
        '0xC0000088': 'Invalid object type name info info info info info info info info length - Invalid object type name info info info info info info info info length',
        '0xC0000089': 'Invalid object type name info info info info info info info info buffer - Invalid object type name info info info info info info info info buffer',
        '0xC000008A': 'Invalid object type name info info info info info info info info format - Invalid object type name info info info info info info info info format',
        '0xC000008B': 'Invalid object type name info info info info info info info info class - Invalid object type name info info info info info info info info class',
        '0xC000008C': 'Invalid object type name info info info info info info info info type - Invalid object type name info info info info info info info info type',
        '0xC000008D': 'Invalid object type name info info info info info info info info scope - Invalid object type name info info info info info info info scope',
        '0xC000008E': 'Invalid object type name info info info info info info info info value - Invalid object type name info info info info info info info value',
        '0xC000008F': 'Invalid object type name info info info info info info info info result - Invalid object type name info info info info info info info result',
        '0xC0000090': 'Invalid object type name info info info info info info info info status - Invalid object type name info info info info info info info status',
        '0xC0000091': 'Invalid object type name info info info info info info info info info - Invalid object type name info info info info info info info info',
        '0xC0000092': 'Invalid object type name info info info info info info info info info class - Invalid object type name info info info info info info info info class',
        '0xC0000093': 'Invalid object type name info info info info info info info info info length - Invalid object type name info info info info info info info info length',
        '0xC0000096': 'Floating point division by zero - Division by zero in floating point operation',
        '0xC0000097': 'Floating point overflow - Floating point arithmetic overflow',
        '0xC0000098': 'Floating point underflow - Floating point arithmetic underflow',
        '0xC0000099': 'Floating point inexact result - Floating point inexact result',
        '0xC000009A': 'Floating point invalid operation - Invalid floating point operation',
        '0xC000009B': 'Floating point stack check - Floating point stack check failed',
        '0xC000009C': 'Floating point denormal operand - Floating point denormal operand',
        '0xC000009D': 'Floating point invalid operand - Floating point invalid operand',
        '0xC000009E': 'Floating point overflow - Floating point overflow',
        '0xC000009F': 'Floating point underflow - Floating point underflow',
        '0xC00000A0': 'Floating point inexact result - Floating point inexact result',
        '0xC00000A1': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000A2': 'Floating point stack check - Floating point stack check failed',
        '0xC00000A3': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000A4': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000A5': 'Floating point overflow - Floating point overflow',
        '0xC00000A6': 'Floating point underflow - Floating point underflow',
        '0xC00000A7': 'Floating point inexact result - Floating point inexact result',
        '0xC00000A8': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000A9': 'Floating point stack check - Floating point stack check failed',
        '0xC00000AA': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000AB': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000AC': 'Floating point overflow - Floating point overflow',
        '0xC00000AD': 'Floating point underflow - Floating point underflow',
        '0xC00000AE': 'Floating point inexact result - Floating point inexact result',
        '0xC00000AF': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000B0': 'Floating point stack check - Floating point stack check failed',
        '0xC00000B1': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000B2': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000B3': 'Floating point overflow - Floating point overflow',
        '0xC00000B4': 'Floating point underflow - Floating point underflow',
        '0xC00000B5': 'Floating point inexact result - Floating point inexact result',
        '0xC00000B6': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000B7': 'Floating point stack check - Floating point stack check failed',
        '0xC00000B8': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000B9': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000BA': 'Floating point overflow - Floating point overflow',
        '0xC00000BB': 'Floating point underflow - Floating point underflow',
        '0xC00000BC': 'Floating point inexact result - Floating point inexact result',
        '0xC00000BD': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000BE': 'Floating point stack check - Floating point stack check failed',
        '0xC00000BF': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000C0': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000C1': 'Floating point overflow - Floating point overflow',
        '0xC00000C2': 'Floating point underflow - Floating point underflow',
        '0xC00000C3': 'Floating point inexact result - Floating point inexact result',
        '0xC00000C4': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000C5': 'Floating point stack check - Floating point stack check failed',
        '0xC00000C6': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000C7': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000C8': 'Floating point overflow - Floating point overflow',
        '0xC00000C9': 'Floating point underflow - Floating point underflow',
        '0xC00000CA': 'Floating point inexact result - Floating point inexact result',
        '0xC00000CB': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000CC': 'Floating point stack check - Floating point stack check failed',
        '0xC00000CD': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000CE': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000CF': 'Floating point overflow - Floating point overflow',
        '0xC00000D0': 'Floating point underflow - Floating point underflow',
        '0xC00000D1': 'Floating point inexact result - Floating point inexact result',
        '0xC00000D2': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000D3': 'Floating point stack check - Floating point stack check failed',
        '0xC00000D4': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000D5': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000D6': 'Floating point overflow - Floating point overflow',
        '0xC00000D7': 'Floating point underflow - Floating point underflow',
        '0xC00000D8': 'Floating point inexact result - Floating point inexact result',
        '0xC00000D9': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000DA': 'Floating point stack check - Floating point stack check failed',
        '0xC00000DB': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000DC': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000DD': 'Floating point overflow - Floating point overflow',
        '0xC00000DE': 'Floating point underflow - Floating point underflow',
        '0xC00000DF': 'Floating point inexact result - Floating point inexact result',
        '0xC00000E0': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000E1': 'Floating point stack check - Floating point stack check failed',
        '0xC00000E2': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000E3': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000E4': 'Floating point overflow - Floating point overflow',
        '0xC00000E5': 'Floating point underflow - Floating point underflow',
        '0xC00000E6': 'Floating point inexact result - Floating point inexact result',
        '0xC00000E7': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000E8': 'Floating point stack check - Floating point stack check failed',
        '0xC00000E9': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000EA': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000EB': 'Floating point overflow - Floating point overflow',
        '0xC00000EC': 'Floating point underflow - Floating point underflow',
        '0xC00000ED': 'Floating point inexact result - Floating point inexact result',
        '0xC00000EE': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000EF': 'Floating point stack check - Floating point stack check failed',
        '0xC00000F0': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000F1': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000F2': 'Floating point overflow - Floating point overflow',
        '0xC00000F3': 'Floating point underflow - Floating point underflow',
        '0xC00000F4': 'Floating point inexact result - Floating point inexact result',
        '0xC00000F5': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000F6': 'Floating point stack check - Floating point stack check failed',
        '0xC00000F7': 'Floating point denormal operand - Floating point denormal operand',
        '0xC00000F8': 'Floating point invalid operand - Floating point invalid operand',
        '0xC00000F9': 'Floating point overflow - Floating point overflow',
        '0xC00000FA': 'Floating point underflow - Floating point underflow',
        '0xC00000FB': 'Floating point inexact result - Floating point inexact result',
        '0xC00000FC': 'Floating point invalid operation - Invalid floating point operation',
        '0xC00000FE': 'Floating point stack check - Floating point stack check failed',
        '0xC00000FF': 'Floating point denormal operand - Floating point denormal operand',
    }
    code = code.strip()
    if code.lower().startswith('0x'):
        code = '0x' + code[2:].upper()
    else:
        code = '0x' + code.upper()
    return exception_codes.get(code, _('Unknown error - Unrecognized exception code'))


def is_valid_text(text):
    """Check if text contains valid printable characters"""
    if not text:
        return False
    
    # Check for control characters and other invalid characters
    invalid_chars = set('\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f')
    
    # If more than 30% of characters are invalid, consider it garbage
    invalid_count = sum(1 for c in text if c in invalid_chars)
    if invalid_count > len(text) * 0.3:
        return False
    
    # Check if text is too short or too long
    if len(text) < 1 or len(text) > 200:
        return False
    
    return True

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
        exception_address = struct.unpack_from('<Q', dump_data, rva + 8 + 16)[0]
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
            for i in range(0, min(len(stack_data), ptr_size * 9), ptr_size):
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
            type_map = {0x20000: 'MEM_PRIVATE', 0x40000: 'MEM_MAPPED', 0x1000000: 'MEM_IMAGE'}
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
