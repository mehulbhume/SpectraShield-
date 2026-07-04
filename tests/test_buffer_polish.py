from agent.features import buffer_polish

def test_import():
    assert hasattr(buffer_polish, "run")

def test_no_crash():
    def mock_send(a,b,c,d):
        pass
    buffer_polish.run(mock_send)