from agent.features import registry_monitoring

def test_import():
    assert hasattr(registry_monitoring, "run")

def test_no_crash():
    def mock_send(a,b,c,d):
        pass
    registry_monitoring.run(mock_send)