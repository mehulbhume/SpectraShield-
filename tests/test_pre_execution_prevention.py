from agent import pre_execution

def test_pre_execution():
    # basic sanity test
    input_data = "sample input"
    
    result = pre_execution(input_data)
    
    # checks
    assert result is not None
    assert isinstance(result, (str, dict, list, bool, int))
