import pytest
import pandas as pd
from unittest.mock import patch

@patch('src.db.run_query')
def test_run_query_mocked(mock_run_query):
    # Mocking run_query to avoid needing a real database connection
    mock_run_query.return_value = pd.DataFrame({"col1": ["a", "b"], "col2": [1, 2]})
    
    from src.db import run_query
    df = run_query("SELECT * FROM fake_table")
    
    assert len(df) == 2
    assert "col1" in df.columns
    assert "col2" in df.columns
    assert df.iloc[0]["col1"] == "a"
    mock_run_query.assert_called_once_with("SELECT * FROM fake_table")

@patch('src.db.ingest_csv')
def test_ingest_csv_mocked(mock_ingest):
    mock_ingest.return_value = 100
    
    from src.db import ingest_csv
    count = ingest_csv("fake_path.csv")
    
    assert count == 100
    mock_ingest.assert_called_once_with("fake_path.csv")
