#!/bin/bash
set -e

# Run ingestion
echo "Running data ingestion..."
python -m src.main ingest

# Start Streamlit
echo "Starting Streamlit..."
exec streamlit run src/app.py --server.port=8501 --server.address=0.0.0.0
