"""
Data utilities for loading hypothesis outcome ground truth files.
"""
import json
from typing import Dict

import pandas as pd


def load_hypotheses_outcomes(file_path: str) -> Dict[str, pd.DataFrame]:
    """
    Load hypotheses_outcomes.json and return a dict mapping hypothesis IDs
    to DataFrames containing the expected/ground-truth rows for that hypothesis.

    The JSON format is a list of dicts, each with a single key (the hypothesis ID)
    mapping to a dict of column→value arrays (records format).

    Args:
        file_path: Path to hypotheses_outcomes.json

    Returns:
        Dict[str, pd.DataFrame] where keys are hypothesis IDs
        (e.g. '1', '9a', '10') and values are DataFrames of expected rows.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    final_result: Dict[str, pd.DataFrame] = {}
    for data_item in data:
        for k, v in data_item.items():
            final_result[k] = pd.DataFrame(v)

    return final_result


if __name__ == "__main__":
    import sys
    file_path = sys.argv[1] if len(sys.argv) > 1 else "data/hypotheses_outcomes.json"
    result = load_hypotheses_outcomes(file_path)
    for hyp_id, df in result.items():
        print(f"Hypothesis {hyp_id}: {len(df)} expected rows, columns: {list(df.columns)}")
