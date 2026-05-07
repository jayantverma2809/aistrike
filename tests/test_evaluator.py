import pandas as pd
from src.evaluator import _gt_type, score

def test_gt_type_A():
    df = pd.DataFrame({"eventID": [1, 2]})
    assert _gt_type(df) == "A"

def test_gt_type_C():
    df = pd.DataFrame({"col1": ["a"], "count": [5]})
    assert _gt_type(df) == "C"

def test_gt_type_B():
    df = pd.DataFrame({"col1": ["a"], "col2": ["b"]})
    assert _gt_type(df) == "B"

def test_score_perfect():
    expected = pd.DataFrame({"eventID": [1, 2]})
    actual = pd.DataFrame({"eventID": [1, 2]})
    res = score(expected, actual, "hyp1")
    assert res["true_positives"] == 2
    assert res["false_positives"] == 0
    assert res["false_negatives"] == 0
    assert res["precision"] == 1.0
    assert res["recall"] == 1.0
    assert res["f1"] == 1.0

def test_score_partial():
    expected = pd.DataFrame({"eventID": [1, 2, 3]})
    actual = pd.DataFrame({"eventID": [2, 3, 4]})
    res = score(expected, actual, "hyp2")
    assert res["true_positives"] == 2
    assert res["false_positives"] == 1
    assert res["false_negatives"] == 1
    assert round(res["precision"], 2) == 0.67
    assert round(res["recall"], 2) == 0.67
