from __future__ import annotations

from contextlib import contextmanager
import os
import hashlib
import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

from ..ingest.parse import parse_line
from ..service.engine import Bundle, Document, Event, investigate


class Monitor:
    """One collector and one optional AI worker per process; SQLite is local state.

    Live windows use collection time. Source timestamps are preserved separately.
    No inference, external network calls or production actions occur in poll().
    """

    def __init__(self, logs, db, *, model=None, documents=None, interval=2, window=60,
                 quiet=120, clock=time.time, investigator=investigate):
        if not logs or interval < .1 or window < 1 or quiet < window:
            raise ValueError('Supply logs, interval >= 0.1, and quiet >= window >= 1')
        self.logs = list(dict.fromkeys(str(Path(p).resolve()) for p in logs))
        self.db = str(db)
        Path(db).parent.mkdir(parents=True, exist_ok=True)
        self.model, self.interval, self.window, self.quiet = model, interval, window, quiet
        self.clock, self.investigator = clock, investigator
        self.documents = [Document.model_validate(d) for d in json.loads(Path(documents).read_text())] if documents else []
        if len(self.documents) > 100 or len({d.id for d in self.documents}) != len(self.documents):
            raise ValueError('Documents require unique IDs and at most 100 entries')
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.threads = []
        self.error = None
        with self.connect() as con:
            con.executescript('''
            CREATE TABLE IF NOT EXISTS cursors (
              path TEXT PRIMARY KEY, inode TEXT, offset INTEGER, generation INTEGER,
              anchor TEXT, last_poll REAL, last_event REAL, malformed INTEGER DEFAULT 0, error TEXT);
            CREATE TABLE IF NOT EXISTS events (
              id TEXT PRIMARY KEY, received REAL, source_time TEXT, payload TEXT);
            CREATE INDEX IF NOT EXISTS events_received ON events(received);
            CREATE TABLE IF NOT EXISTS incidents (
              id TEXT PRIMARY KEY, kind TEXT, route TEXT, severity TEXT, status TEXT,
              first_seen REAL, last_seen REAL, count INTEGER, revision INTEGER,
              evidence TEXT, ai_revision INTEGER DEFAULT 0, ai_status TEXT,
              ai_result TEXT, ai_error TEXT, ai_at REAL DEFAULT 0);
            ''')
            # Recover work interrupted by a process shutdown.
            con.execute("UPDATE incidents SET ai_status='pending' WHERE ai_status='running'")

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.db, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            with con:
                yield con
        finally:
            con.close()

    def decode(self, line, eid):
        if line.lstrip().startswith('{'):
            data = json.loads(line)
            source_time = data.pop('timestamp', None)
            data.setdefault('source', 'app')
            data.setdefault('request_id', eid)
            event = Event.model_validate(dict(data, id=eid, window='current'))
        else:
            parsed = parse_line(line)
            if parsed is None:
                raise ValueError('Expected JSONL or nginx combined access log')
            source_time = parsed.timestamp.isoformat()
            event = Event(id=eid, request_id=eid, source='app', window='current',
                          path=urlsplit(parsed.path).path[:300] or '/', status=parsed.status,
                          message=f'{parsed.method} {parsed.path}'[:1000])
        return event, str(source_time) if source_time is not None else None

    def collect(self, con, path, now):
        row = con.execute('SELECT * FROM cursors WHERE path=?', (path,)).fetchone()
        offset, generation = (row['offset'], row['generation']) if row else (0, 0)
        malformed = row['malformed'] if row else 0
        last_event = row['last_event'] if row else None
        try:
            with open(path, 'rb') as file:
                stat = os.fstat(file.fileno())
                inode = f'{stat.st_dev}:{stat.st_ino}'
                file.seek(max(0, offset - 64))
                anchor = file.read(min(64, offset)).hex()
                if row and (inode != row['inode'] or stat.st_size < offset or anchor != row['anchor']):
                    offset, generation = 0, generation + 1
                file.seek(offset)
                for _ in range(1000):
                    start = file.tell()
                    line = file.readline(65537)
                    if not line:
                        break
                    if not line.endswith(b'\n'):
                        if len(line) > 65536:
                            raise ValueError('Line exceeds 64 KiB; collector paused at this line')
                        file.seek(start)  # Partial write: retry only when completed.
                        break
                    offset = file.tell()
                    eid = hashlib.sha256(f'{path}:{inode}:{generation}:{start}'.encode()).hexdigest()[:24]
                    try:
                        event, source_time = self.decode(line.decode('utf-8'), eid)
                    except (ValueError, TypeError, KeyError):
                        malformed += 1
                        continue
                    con.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?)',
                                (eid, now, source_time, event.model_dump_json()))
                    last_event = now
                file.seek(max(0, offset - 64))
                anchor = file.read(min(64, offset)).hex()
            con.execute('INSERT OR REPLACE INTO cursors VALUES (?,?,?,?,?,?,?,?,?)',
                        (path, inode, offset, generation, anchor, now, last_event, malformed, None))
        except (OSError, ValueError) as exc:
            raise RuntimeError(str(exc)) from exc

    def poll(self):
        now = self.clock()
        with self.lock, self.connect() as con:
            for path in self.logs:
                con.execute('SAVEPOINT source_read')
                try:
                    self.collect(con, path, now)
                except Exception as exc:
                    con.execute('ROLLBACK TO source_read')
                    con.execute('INSERT OR IGNORE INTO cursors VALUES (?,?,?,?,?,?,?,?,?)', (path,'',0,0,'',now,None,0,str(exc)))
                    con.execute('UPDATE cursors SET last_poll=?,error=? WHERE path=?', (now, str(exc), path))
                finally:
                    con.execute('RELEASE source_read')
            rows = con.execute('SELECT * FROM events WHERE received>? ORDER BY received,id', (now-2*self.window,)).fetchall()
            events = [(r['received'], json.loads(r['payload'])) for r in rows]
            current = [(t,e) for t,e in events if t > now-self.window]
            for route in sorted({e['path'] for _, e in current}):
                group = [(t,e) for t,e in current if e['path'] == route]
                app = [(t,e) for t,e in group if e['source'] == 'app']
                waf = [(t,e) for t,e in group if e['source'] == 'waf']
                failures = [(t,e) for t,e in app if e['status'] >= 500]
                auth = [(t,e) for t,e in app if e['status'] in (401,403)]
                blocks = [(t,e) for t,e in waf if e['action'] == 'block']
                suspicious = [(t,e) for t,e in group if re.search(r'\.\./|union\s+select|<script', unquote(e['message']).lower())]
                previous = sum(e['path'] == route and e['source'] == 'app' and t <= now-self.window for t,e in events)
                candidates = []
                if len(failures) >= 5 and len(failures)/len(app) >= .2:
                    candidates.append(('application_errors', 'high', failures))
                if len(auth) >= 10:
                    candidates.append(('authentication_failures', 'medium', auth))
                if len(blocks) >= 5 and len(blocks)/len(waf) >= .2:
                    candidates.append(('waf_blocks', 'medium', blocks))
                if len(suspicious) >= 3:
                    candidates.append(('suspicious_requests', 'high', suspicious))
                if len(app) >= 20 and previous >= 5 and len(app) >= previous*3:
                    candidates.append(('traffic_spike', 'medium', app))
                for kind, severity, matching in candidates:
                    key = hashlib.sha256(f'{kind}:{route}'.encode()).hexdigest()[:20]
                    old = con.execute('SELECT * FROM incidents WHERE id=?', (key,)).fetchone()
                    newest = max(t for t,_ in matching)
                    # Re-investigate on reopening or a doubling of the last AI-trigger count.
                    changed = old is None or old['status'] == 'resolved' or len(matching) >= old['count']*2
                    evidence = json.dumps([e for _, e in matching[-40:]])
                    if old is None:
                        con.execute('INSERT INTO incidents (id,kind,route,severity,status,first_seen,last_seen,count,revision,evidence,ai_status) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                                    (key,kind,route,severity,'active',newest,newest,len(matching),1,evidence,'pending' if self.model else 'disabled'))
                    else:
                        con.execute('UPDATE incidents SET status=?,last_seen=?,count=?,revision=?,evidence=?,ai_status=? WHERE id=?',
                                    ('active',newest,len(matching) if changed else old['count'],old['revision']+int(changed),evidence,
                                     ('pending' if self.model else 'disabled') if changed else old['ai_status'],key))
            con.execute("UPDATE incidents SET status='resolved' WHERE status='active' AND last_seen<?", (now-self.quiet,))
            # Bound storage; incident history lasts 30 days, source events one day.
            con.execute('DELETE FROM events WHERE received<?', (now-86400,))
            con.execute("DELETE FROM incidents WHERE status='resolved' AND last_seen<?", (now-30*86400,))

    def investigate_one(self):
        if not self.model:
            return False
        with self.lock, self.connect() as con:
            row = con.execute("SELECT * FROM incidents WHERE status='active' AND ai_status IN ('pending','error') AND ai_at<=? ORDER BY first_seen LIMIT 1", (self.clock()-60,)).fetchone()
            if row is None:
                return False
            con.execute("UPDATE incidents SET ai_status='running',ai_at=? WHERE id=?", (self.clock(),row['id']))
        try:
            # Repeated request IDs are valid in live sources; keep latest per source.
            events = {(e['source'],e['request_id']):e for e in json.loads(row['evidence'])}
            result = self.investigator(Bundle(service='Monitored service', events=list(events.values()), documents=self.documents),
                                       'rag' if self.documents else 'llm', self.model)
            status, error, output = 'complete', None, json.dumps(result)
        except Exception as exc:
            status, error, output = 'error', str(exc), None
        with self.lock, self.connect() as con:
            con.execute('UPDATE incidents SET ai_status=?,ai_result=?,ai_error=?,ai_revision=? WHERE id=? AND revision=?',
                        (status,output,error,row['revision'],row['id'],row['revision']))
        return True

    def snapshot(self):
        now = self.clock()
        with self.lock, self.connect() as con:
            sources = [dict(r) for r in con.execute('SELECT path,last_poll,last_event,malformed,error FROM cursors') if r['path'] in self.logs]
            incidents = [dict(r) for r in con.execute('SELECT * FROM incidents ORDER BY last_seen DESC LIMIT 100')]
            events = [json.loads(r['payload']) for r in con.execute('SELECT payload FROM events WHERE received>?', (now-self.window,))]
        for source in sources:
            source['state'] = 'error' if source['error'] else ('waiting' if source['last_event'] is None else ('idle' if now-source['last_event'] > self.window else 'receiving'))
        for incident in incidents:
            incident['evidence'] = json.loads(incident['evidence'])
            incident['ai_result'] = json.loads(incident['ai_result']) if incident['ai_result'] else None
        routes = []
        for path in sorted({e['path'] for e in events}):
            app = [e for e in events if e['path'] == path and e['source'] == 'app']
            waf = [e for e in events if e['path'] == path and e['source'] == 'waf']
            routes.append(dict(path=path, requests=len(app), errors=sum(e['status']>=500 for e in app),
                               waf_requests=len(waf), blocks=sum(e['action']=='block' for e in waf)))
        return dict(now=now,window_seconds=self.window,sources=sources,routes=routes,incidents=incidents,
                    model=self.model,collector_error=self.error,
                    timing='Collection-time windows; backfilled logs are counted when read.')

    def start(self):
        def collect_loop():
            while not self.stop_event.is_set():
                try:
                    self.poll()
                    self.error = None
                except Exception as exc:
                    self.error = str(exc)
                self.stop_event.wait(self.interval)
        def ai_loop():
            while not self.stop_event.is_set():
                try:
                    self.investigate_one()
                except Exception as exc:
                    self.error = 'AI worker: ' + str(exc)
                self.stop_event.wait(1)
        for target in ([collect_loop, ai_loop] if self.model else [collect_loop]):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=3)
