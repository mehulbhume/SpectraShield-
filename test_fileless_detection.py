import pytest
from agent.features import fileless_detection

captured = []

def mock_send(event_type, fid, data, severity):
    captured.append((event_type, fid, data, severity))

def test_runs_without_crash():
    fileless_detection.run(mock_send)
    assert len(captured) > 0

def test_has_required_fields():
    fileless_detection.run(mock_send)
    data = captured[-1][2]
    assert "suspicious_processes" in data
    assert "scan_ok" in data

