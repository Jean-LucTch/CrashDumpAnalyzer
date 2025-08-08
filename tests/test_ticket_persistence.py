import importlib
from datetime import datetime


def test_ticket_persisted(app_module):
    data = {
        'exe_name': 'test.exe',
        'crash_reason': 'reason',
        'analysis_file': 'analysis_1.txt',
        'timestamp': datetime.now().strftime('%d.%m.%Y %H:%M:%S')
    }
    app_module.save_ticket_to_db(1, data)
    reloaded = importlib.reload(app_module)
    assert 1 in reloaded.tickets
    assert reloaded.tickets[1]['exe_name'] == 'test.exe'
