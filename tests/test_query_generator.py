import pytest
from src.query_generator import QueryGenerator, GeneratedQuery, GeneratedQueryResult
from unittest.mock import MagicMock

def test_query_result_model():
    res = GeneratedQueryResult(hypothesis_id="h1", hypothesis_name="Test", hypothesis_text="text")
    assert res.generated is None
    assert res.error is None
    assert res.repair_attempts == 0

def test_query_generator_init():
    client_mock = MagicMock()
    ground_truth = {"h1": None}
    generator = QueryGenerator(client=client_mock, ground_truth=ground_truth, provider="test")
    assert generator._provider == "test"
    assert generator._client == client_mock
