from auditor.engine.analyzer import auth_findings, exposure_findings, bola_findings
from auditor.engine.models import Operation


def op(secured=True):
    return Operation(method="GET", path="/users/{id}", security_required=secured)


def test_auth_bypass_heuristic():
    findings = auth_findings(op(), 200, 200, "missing_authorization", "{}")
    assert findings and findings[0].severity == "high"


def test_sensitive_field_heuristic():
    findings = exposure_findings(op(False), 200, '{"name":"a","internal_api_key":"demo"}')
    assert findings and findings[0].category == "data_exposure"


def test_bola_heuristic_requires_successful_responses():
    findings = bola_findings(op(), 200, '{"id":1}', 200, '{"id":2}', "id", "2")
    assert findings and findings[0].category == "authorization"
