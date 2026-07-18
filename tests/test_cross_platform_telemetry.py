from agent.features import cross_platform_telemetry

captured = []


def mock_send_event(event_type, feature_id, data, severity):

    captured.append({
        "event_type": event_type,
        "feature_id": feature_id,
        "data": data,
        "severity": severity
    })


def test_runs_without_crash():

    cross_platform_telemetry.run(mock_send_event)

    assert len(captured) > 0


def test_required_fields_exist():

    cross_platform_telemetry.run(mock_send_event)

    data = captured[0]["data"]

    assert "os_type" in data
    assert "hostname" in data
    assert "platform" in data
    assert "processor" in data
    assert "ram_gb" in data
