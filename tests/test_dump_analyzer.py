import builtins
import sys
import types
import os
import struct

import pytest


def test_analyze_dump_fallback_minidump(analyzer_module, monkeypatch, tmp_path):
    monkeypatch.setattr(analyzer_module, 'find_cdb_executable', lambda: None)
    
    # Create a fake minidump file with MDMP signature
    fake_dump_path = tmp_path / "fake.dmp"
    with open(fake_dump_path, 'wb') as f:
        f.write(b'MDMP')  # Minidump signature
        f.write(b'fake minidump data' * 1000)  # Some fake data
    
    exe_name, crash_reason = analyzer_module.analyze_dump(str(fake_dump_path), 1, str(tmp_path))
    # The analyzer should detect it's a valid minidump but won't find specific process info
    assert exe_name == 'Unknown application' or 'Unknown' in exe_name
    assert 'Unknown error' in crash_reason or 'Unknown' in crash_reason


def test_analyze_dump_no_debugger(analyzer_module, monkeypatch, tmp_path):
    monkeypatch.setattr(analyzer_module, 'find_cdb_executable', lambda: None)
    
    # Create a fake dump file that's not a valid minidump
    fake_dump_path = tmp_path / "invalid.dmp"
    with open(fake_dump_path, 'wb') as f:
        f.write(b'NOT_A_MINIDUMP')  # Invalid signature
    
    exe_name, crash_reason = analyzer_module.analyze_dump(str(fake_dump_path), 1, str(tmp_path))
    assert exe_name == 'Invalid dump file'
    assert 'not a valid minidump' in crash_reason.lower()


def test_analyze_dump_file_too_small(analyzer_module, monkeypatch, tmp_path):
    monkeypatch.setattr(analyzer_module, 'find_cdb_executable', lambda: None)
    
    # Create a very small file
    fake_dump_path = tmp_path / "small.dmp"
    with open(fake_dump_path, 'wb') as f:
        f.write(b'MD')  # Too small
    
    exe_name, crash_reason = analyzer_module.analyze_dump(str(fake_dump_path), 1, str(tmp_path))
    assert exe_name == 'Invalid dump file'
    assert 'too small' in crash_reason.lower()


def test_analyze_dump_with_cdb(analyzer_module, monkeypatch, tmp_path):
    # Mock CDB executable found
    monkeypatch.setattr(analyzer_module, 'find_cdb_executable', lambda: '/fake/cdb.exe')
    
    # Mock subprocess to return fake CDB output
    def mock_popen(*args, **kwargs):
        class MockProcess:
            def communicate(self, timeout=None):
                fake_output = """
                PROCESS_NAME: test.exe
                ExceptionCode: 0xC0000005
                """
                return fake_output.encode('utf-8'), b''
        return MockProcess()
    
    monkeypatch.setattr('subprocess.Popen', mock_popen)
    
    fake_dump_path = tmp_path / "test.dmp"
    with open(fake_dump_path, 'wb') as f:
        f.write(b'fake dump data')
    
    exe_name, crash_reason = analyzer_module.analyze_dump(str(fake_dump_path), 1, str(tmp_path))
    assert exe_name == 'test.exe'
    assert '0xC0000005' in crash_reason


def _build_minidump_with_system_info(platform_id):
    """Create a minimal minidump byte sequence containing a SYSTEM_INFO stream."""
    header_size = 32
    dir_rva = header_size
    sysinfo_rva = dir_rva + 12
    sysinfo_size = 24  # Enough to include platform id
    total_size = sysinfo_rva + sysinfo_size
    dump_data = bytearray(total_size)

    struct.pack_into('<IIIIIIQ', dump_data, 0, 0x504D444D, 0, 1, dir_rva, 0, 0, 0)
    struct.pack_into('<III', dump_data, dir_rva, 7, sysinfo_size, sysinfo_rva)
    struct.pack_into('<H', dump_data, sysinfo_rva, 9)  # Architecture X64
    struct.pack_into('<I', dump_data, sysinfo_rva + 8, 10)  # Major version
    struct.pack_into('<I', dump_data, sysinfo_rva + 12, 0)  # Minor version
    struct.pack_into('<I', dump_data, sysinfo_rva + 16, 19045)  # Build number
    struct.pack_into('<I', dump_data, sysinfo_rva + 20, platform_id)
    return bytes(dump_data)


@pytest.mark.parametrize("platform_id, expected_os", [
    (2, 'Windows (NT)'),
    (0x8201, 'Linux'),
])
def test_extract_system_info_includes_platform(analyzer_module, platform_id, expected_os):
    dump_data = _build_minidump_with_system_info(platform_id)
    info = analyzer_module.extract_system_info(dump_data)
    assert info['operating_system'] == expected_os
    assert info['os_version'] == '10.0.19045'
    assert info['architecture'] == 'X64'
