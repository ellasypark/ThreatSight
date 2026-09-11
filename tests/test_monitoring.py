import json
from pathlib import Path

from fastapi.testclient import TestClient

from threatsight.monitoring.core import Monitor
from threatsight.monitoring.server import create_app


def fixture(tmp_path, model=None, investigator=None):
    log = tmp_path/'app.jsonl'
    log.touch()
    clock = [1000.0]
    kwargs = {'investigator': investigator} if investigator else {}
    monitor = Monitor([log], tmp_path/'state.sqlite', clock=lambda:clock[0], model=model, **kwargs)
    return monitor, log, clock


def append(log, count=5, status=503, path='/checkout'):
    with log.open('a') as file:
        for _ in range(count):
            file.write(json.dumps({'path':path,'status':status,'message':'Provider timeout'})+'\n')


def test_app_only_live_incident_and_no_duplicate_reads(tmp_path):
    monitor, log, clock = fixture(tmp_path)
    monitor.poll()
    assert monitor.snapshot()['sources'][0]['state']=='waiting'
    append(log)
    monitor.poll()
    state=monitor.snapshot()
    assert state['routes'][0]['requests']==5
    assert state['incidents'][0]['kind']=='application_errors'
    assert state['incidents'][0]['ai_status']=='disabled'
    monitor.poll()
    assert monitor.snapshot()['routes'][0]['requests']==5


def test_restart_preserves_cursor_and_incident(tmp_path):
    monitor, log, clock=fixture(tmp_path)
    append(log)
    monitor.poll()
    other=Monitor([log],tmp_path/'state.sqlite',clock=lambda:clock[0])
    other.poll()
    assert other.snapshot()['routes'][0]['requests']==5
    assert len(other.snapshot()['incidents'])==1


def test_partial_and_malformed_lines(tmp_path):
    monitor, log, clock=fixture(tmp_path)
    log.write_text('garbage\n{"path":"/ok","status":200}')
    monitor.poll()
    assert not monitor.snapshot()['routes']
    with log.open('a') as file:file.write('\n')
    monitor.poll()
    assert monitor.snapshot()['routes'][0]['requests']==1
    assert monitor.snapshot()['sources'][0]['malformed']==1


def test_rotation_and_copy_truncate(tmp_path):
    monitor, log, clock=fixture(tmp_path)
    append(log)
    monitor.poll()
    log.rename(tmp_path/'old.log')
    append(log,count=1,status=200)
    monitor.poll()
    assert monitor.snapshot()['routes'][0]['requests']==6
    log.write_text('{"path":"/x","status":200}\n')
    monitor.poll()
    assert sum(r['requests'] for r in monitor.snapshot()['routes'])==7


def test_missing_source_recovers(tmp_path):
    monitor, log, clock=fixture(tmp_path)
    log.unlink()
    monitor.poll()
    assert monitor.snapshot()['sources'][0]['state']=='error'
    append(log)
    monitor.poll()
    assert monitor.snapshot()['sources'][0]['state']=='receiving'


def test_resolution_and_reopening(tmp_path):
    monitor, log, clock=fixture(tmp_path)
    append(log)
    monitor.poll()
    clock[0]+=121
    monitor.poll()
    assert monitor.snapshot()['incidents'][0]['status']=='resolved'
    append(log)
    monitor.poll()
    state=monitor.snapshot()['incidents'][0]
    assert state['status']=='active'
    assert state['revision']==2


def test_ai_only_runs_on_new_or_materially_changed_incident(tmp_path):
    calls=[]
    def investigate(bundle,mode,model):
        calls.append(bundle)
        return {'assessment':{'disposition':'app_error'}}
    monitor,log,clock=fixture(tmp_path,'test',investigate)
    append(log)
    monitor.poll()
    assert monitor.investigate_one()
    monitor.poll()
    assert not monitor.investigate_one()
    clock[0]+=2
    append(log)
    monitor.poll()
    assert not monitor.investigate_one() # cooldown even after doubling
    clock[0]+=60
    assert monitor.investigate_one()
    assert len(calls)==2


def test_ai_error_does_not_block_collection(tmp_path):
    def fail(*args):raise RuntimeError('Model unavailable')
    monitor,log,clock=fixture(tmp_path,'test',fail)
    append(log)
    monitor.poll()
    monitor.investigate_one()
    append(log,count=1,status=200)
    monitor.poll()
    assert monitor.snapshot()['routes'][0]['requests']==6
    assert monitor.snapshot()['incidents'][0]['ai_status']=='error'


def test_nginx_without_waf_and_path_normalization(tmp_path):
    monitor,log,clock=fixture(tmp_path)
    line='127.0.0.1 - - [11/Sep/2026:00:00:00 +0000] "GET /search?q=test HTTP/1.1" 200 100 "-" "browser"\n'
    log.write_text(line)
    monitor.poll()
    assert monitor.snapshot()['routes'][0]['path']=='/search'
    assert monitor.snapshot()['routes'][0]['waf_requests']==0


def test_spike_needs_comparable_prior_window(tmp_path):
    monitor,log,clock=fixture(tmp_path)
    append(log,count=5,status=200)
    monitor.poll()
    clock[0]+=61
    append(log,count=20,status=200)
    monitor.poll()
    assert monitor.snapshot()['incidents'][0]['kind']=='traffic_spike'


def test_api_read_only_and_export(tmp_path):
    monitor,log,clock=fixture(tmp_path)
    append(log)
    monitor.poll()
    with TestClient(create_app(monitor)) as client:
        response=client.get('/api/monitor')
        incident=response.json()['incidents'][0]
        assert response.status_code==200
        assert client.get('/').status_code==200
        assert client.get('/monitor.js').status_code==200
        assert client.get('/api/incidents/'+incident['id']+'/export').status_code==200
        assert client.get('/api/incidents/missing/export').status_code==404
        assert client.post('/api/monitor',json={}).status_code==405
        assert 'frame-ancestors' in response.headers['content-security-policy']
        assert client.get('/',headers={'host':'attacker.example'}).status_code==400


def test_large_partial_line_reports_error_without_losing_prior_lines(tmp_path):
    monitor,log,clock=fixture(tmp_path)
    append(log)
    with log.open('a') as file:file.write('a'*70000)
    monitor.poll()
    assert monitor.snapshot()['sources'][0]['state']=='error'
    assert not monitor.snapshot()['routes'] # source transaction rolled back
    log.write_text('')
    append(log)
    monitor.poll()
    assert monitor.snapshot()['routes'][0]['requests']==5
