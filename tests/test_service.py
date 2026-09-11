import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from threatsight.service.engine import Assessment, Bundle, Document, investigate, retrieve, summarize
from threatsight.service.evaluate import evaluate
from threatsight.service.report import render

FIXTURES = Path(__file__).parent / 'fixtures' / 'service'


def bundle(name='app_error'):
    return Bundle.model_validate_json((FIXTURES / (name + '.json')).read_bytes())


def mock_model(assessment, inspect=None):
    def handler(request):
        payload = json.loads(request.content)
        assert str(request.url) == 'http://127.0.0.1:11434/api/chat'
        assert 'tools' not in payload
        if inspect:
            inspect(payload)
        return httpx.Response(200, json={'message': {'content': json.dumps(assessment)},
                                       'prompt_eval_count': 90, 'eval_count': 30})
    return httpx.MockTransport(handler)


def test_baseline_correlates_only_matching_requests():
    b = bundle()
    assert investigate(b)['assessment']['disposition'] == 'app_error'
    b.events[1].request_id = 'different'
    assert investigate(b)['assessment']['disposition'] == 'insufficient_evidence'


def test_baseline_does_not_equate_block_with_attack():
    assert investigate(bundle('attack'))['assessment']['disposition'] == 'insufficient_evidence'


def test_missing_window_is_not_zero_and_rates_have_denominators():
    assert summarize(bundle())[0]['block_rate_change_pp'] is None
    row = summarize(bundle('checkout_false_positive'))[0]
    assert row['block_rate_change_pp'] == 100
    assert row['current']['app_5xx_rate'] is None


def test_retrieval_ignores_irrelevant_documents():
    docs = [Document(id='x', title='other', text='avatars'), Document(id='y', title='/checkout', text='SQL-942')]
    assert [d.id for d in retrieve('/checkout SQL-942', docs)] == ['y']
    assert retrieve('unmatched', docs) == []


def test_duplicate_evidence_is_rejected():
    b = bundle().model_dump()
    b['events'][1]['id'] = b['events'][0]['id']
    with pytest.raises(ValidationError):
        Bundle.model_validate(b)


def test_hallucinated_citation_forces_abstention():
    answer = {'disposition': 'attack_suspected', 'claims': [{'text': 'Attack', 'evidence_ids': ['invented']}],
              'missing_evidence': [], 'next_steps': []}
    result = investigate(bundle(), 'rag', 'test', mock_model(answer))
    assert result['assessment']['disposition'] == 'insufficient_evidence'
    assert result['validation']['invalid_citation_claims'] == 1


def test_rag_supplies_docs_but_llm_ablation_does_not():
    answer = Assessment(disposition='insufficient_evidence').model_dump()
    for mode in ['llm', 'rag']:
        def inspect(payload):
            evidence = json.loads(payload['messages'][1]['content'])['evidence']
            assert ('runbook-payment' in evidence) == (mode == 'rag')
        investigate(bundle(), mode, 'test', mock_model(answer, inspect))


def test_injection_stays_data_and_report_escapes_html():
    b = bundle('injection')
    b.events[0].message += '<script>alert(1)</script>'
    result = investigate(b)
    page = render(result)
    assert '<script>' not in page
    assert '&lt;script&gt;' in page
    assert result['assessment']['disposition'] == 'insufficient_evidence'


def test_model_failure_is_not_scored_as_abstention(monkeypatch):
    def fail(*args):
        raise RuntimeError('offline')
    monkeypatch.setattr('threatsight.service.evaluate.investigate', fail)
    report = evaluate(FIXTURES / 'manifest.json', ['rag'], 'test')
    assert report['summary']['rag']['errors'] == 6
    assert report['summary']['rag']['accuracy_including_errors'] == 0
    assert report['summary']['rag']['abstention_rate'] == 0


def test_cli_writes_portable_report(tmp_path):
    from threatsight.cli import app
    output = tmp_path / 'report.html'
    result = CliRunner().invoke(app, ['service-investigate', str(FIXTURES/'app_error.json'), '--output', str(output)])
    assert result.exit_code == 0, result.output
    assert 'App error' in output.read_text()


def test_evaluation_does_not_pass_labels(monkeypatch):
    from threatsight.service.engine import investigate as original
    def inspect(b, mode, model):
        assert 'expected' not in b.model_dump()
        return original(b)
    monkeypatch.setattr('threatsight.service.evaluate.investigate', inspect)
    result = evaluate(FIXTURES/'manifest.json', ['rules'])
    assert result['summary']['rules']['cases'] == 6
    assert result['summary']['rules']['semantic_unsupported_claim_rate'] is None


def test_no_current_events_does_not_call_model():
    b = bundle()
    for event in b.events:
        event.window = 'baseline'
    def fail(request):
        raise AssertionError('No model should be called without current events')
    result = investigate(b, 'rag', 'test', httpx.MockTransport(fail))
    assert result['assessment']['disposition'] == 'insufficient_evidence'
