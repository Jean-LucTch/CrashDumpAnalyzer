
def test_known_exception_code(analyzer_module):
    assert analyzer_module.get_exception_description('0xC0000005') == 'Access Violation'


def test_known_code_case_insensitive(analyzer_module):
    # also check using lowercase without "0x" prefix
    assert analyzer_module.get_exception_description('80000003') == 'Breakpoint'


def test_unknown_exception_code(analyzer_module):
    assert analyzer_module.get_exception_description('0xDEADBEEF') == 'Unknown error'


def test_exception_description_strip_prefix(analyzer_module):
    assert analyzer_module.get_exception_description(' C00000FD ') == 'Stack Overflow'

