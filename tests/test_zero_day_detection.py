from agent.features import zero_day_detection

def test_import():
    assert hasattr(zero_day_detection, "run")

def test_no_crash():
    def mock_send(a,b,c,d):
        pass
    zero_day_detection.run(mock_send)