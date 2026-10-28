"""Serialized E1-only connection lifecycle intervention. Never app configuration."""
from contextlib import contextmanager
import sqlite3
import threading


@contextmanager
def installed():
    from app.db.events import EventRepository
    original = EventRepository._connect
    lock = threading.Lock()
    connections = {}
    report = {'scope':'DIAGNOSTIC_E1_ONLY', 'physical_connections':0, 'leases':0,
              'physical_closed':0, 'same_transaction_and_commit_semantics':True}
    class Lease:
        def __init__(self, connection):
            self.connection = connection
        def __getattr__(self, key):
            return getattr(self.connection, key)
        def __enter__(self):
            self.connection.__enter__()
            return self
        def __exit__(self, *args):
            return self.connection.__exit__(*args)
        def close(self):
            lock.release()
    def connect(repository):
        lock.acquire()
        try:
            path = repository.path.resolve()
            if path not in connections:
                # One serialized lease at a time; worker thread identity can vary.
                c = sqlite3.connect(path, timeout=5, check_same_thread=False)
                c.row_factory = sqlite3.Row
                try:
                    c.execute('PRAGMA foreign_keys = ON')
                    c.execute('PRAGMA busy_timeout = 5000')
                except BaseException:
                    c.close()
                    raise
                connections[path] = c
                report['physical_connections'] += 1
            report['leases'] += 1
            return Lease(connections[path])
        except BaseException:
            lock.release()
            raise
    EventRepository._connect = connect
    try:
        yield report
    finally:
        EventRepository._connect = original
        for c in connections.values():
            c.close()
            report['physical_closed'] += 1
