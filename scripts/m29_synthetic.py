"""Explicitly SYNTHETIC M29 storage fixtures; caller supplies disposable connection."""
from datetime import timedelta

from app.services.event_normalizer import normalize_wazuh_event
if __package__:
    from . import m28_synthetic
else:
    import m28_synthetic


def protect(connection, event_ids, at):
    stamp = at.isoformat()
    case_id = 'SYNTHETIC-M29-PROTECTED-CASE'
    connection.execute(
        'INSERT INTO soc_cases(case_id,title,severity,priority,status,source_type,created_by_display,'
        'created_at,updated_at,response_due_at,resolution_due_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
        (case_id,'SYNTHETIC M29 protected evidence','HIGH','HIGH','OPEN','MANUAL','SYNTHETIC',
         stamp,stamp,stamp,stamp))
    connection.executemany(
        'INSERT INTO case_events(case_id,event_id,linked_at,linked_by_display) VALUES(?,?,?,?)',
        [(case_id,event_id,stamp,'SYNTHETIC') for event_id in event_ids])


def decorate(connection, repository, at):
    """Replace eight fixture records, not production evidence; preserve population size."""
    count = connection.execute('SELECT COUNT(*) FROM security_events').fetchone()[0]
    if count < 8: raise ValueError('synthetic distribution requires at least eight rows')
    ids = [row[0] for row in connection.execute('SELECT event_id FROM security_events ORDER BY event_id LIMIT 8')]
    connection.executemany('DELETE FROM security_events WHERE event_id=?', [(item,) for item in ids])
    for index in range(8):
        raw = m28_synthetic.windows(20_000_000+index, at-timedelta(days=index % 3), '4625')
        raw['rule']['level'] = index
        if index < 2: raw['data']['win']['system']['providerName'] = 'SYNTHETIC-Rare-Provider'
        elif index == 2: raw['data']['win']['system'].pop('providerName')
        raw['data']['win']['system']['computer'] = 'SYNTHETIC-M29-VARIANT-HOST'
        raw['full_log'] = ('SYNTHETIC mixed-size payload ' * 2000) if index == 3 else 'SYNTHETIC m29rareuniquetoken'
        event = normalize_wazuh_event(raw)
        repository._insert_event_row(connection, event, occurred_at=event.timestamp,
                                     ingested_at=at, related_alert_id=None)
    protected = [row[0] for row in connection.execute(
        'SELECT event_id FROM security_events ORDER BY occurred_at,event_id LIMIT 4')]
    protect(connection, protected, at)
    connection.commit()
    return {'replaced_records': 8, 'protected_records': 4, 'rare_provider': 'SYNTHETIC-Rare-Provider',
            'timestamp_span_days': 2, 'large_payload_characters': len('SYNTHETIC mixed-size payload ' * 2000)}
