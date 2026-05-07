import streamlit as st
import os
import json
import datetime
import pandas as pd
from pathlib import Path

# Set up page layout
st.set_page_config(page_title="AI Threat Hunting", layout="wide")

st.title("AI Threat Hunting Query Generation")
st.markdown("Translate natural language threat hypotheses into executable SQL queries.")

# Ensure we can import from src
import sys
sys.path.append(str(Path(__file__).parent.parent))

from src.config import HYPOTHESES_PATH, HYPOTHESES_OUTCOMES_PATH
from src.llm_client import get_client
from src.query_generator import QueryGenerator
from src.evaluator import Evaluator
from src.db import get_engine

@st.cache_data
def load_hypotheses():
    with open(HYPOTHESES_PATH, "r") as f:
        return json.load(f)

@st.cache_data
def load_ground_truth():
    import importlib.util as ilu
    data_utils_path = Path(__file__).parent.parent / "data" / "utils.py"
    spec = ilu.spec_from_file_location("data_utils", data_utils_path)
    data_utils = ilu.module_from_spec(spec)
    spec.loader.exec_module(data_utils)
    return data_utils.load_hypotheses_outcomes(str(HYPOTHESES_OUTCOMES_PATH))

hypotheses = load_hypotheses()
ground_truth = load_ground_truth()

# --- Sidebar Configuration ---
st.sidebar.header("Configuration")
provider = st.sidebar.selectbox("LLM Provider", ["openai", "anthropic"])
api_key_input = st.sidebar.text_input(f"{provider.upper()} API Key", type="password", help="Leave blank to use the saved environment variable")

if api_key_input:
    os.environ[f"{provider.upper()}_API_KEY"] = api_key_input

has_api_key = bool(os.environ.get(f"{provider.upper()}_API_KEY", ""))

st.sidebar.markdown("---")
page = st.sidebar.radio("Navigation", ["Single Hypothesis", "Complete Evaluation", "Results", "Approach & Iterations"])

# --- Main App ---

if page == "Single Hypothesis":
    st.header("Select Hypothesis")
    hyp_options = {h["id"]: f"{h['id']} - {h['name']}" for h in hypotheses}
    selected_hyp_id = st.selectbox("Hypothesis", options=list(hyp_options.keys()), format_func=lambda x: hyp_options[x])
    
    selected_hyp = next(h for h in hypotheses if h["id"] == selected_hyp_id)
    
    st.markdown(f"### {selected_hyp['name']}")
    st.info(selected_hyp["hypothesis"])
    
    if "query_result" not in st.session_state:
        st.session_state.query_result = None
    if "execution_df" not in st.session_state:
        st.session_state.execution_df = None
    if "evaluation_report" not in st.session_state:
        st.session_state.evaluation_report = None
    if "current_hyp" not in st.session_state:
        st.session_state.current_hyp = selected_hyp_id
    
    # Reset state if hypothesis changed
    if st.session_state.current_hyp != selected_hyp_id:
        st.session_state.query_result = None
        st.session_state.execution_df = None
        st.session_state.evaluation_report = None
        st.session_state.current_hyp = selected_hyp_id
    
    st.markdown("---")
    
    if st.button("Generate Query", type="primary"):
        if not has_api_key:
            st.error("Please provide an API key in the sidebar.")
        else:
            with st.spinner("Generating query..."):
                try:
                    client = get_client(provider)
                    generator = QueryGenerator(client=client, ground_truth=ground_truth, provider=provider)
                    # Generate for just this one hypothesis
                    result = generator.generate_all([selected_hyp])[0]
                    st.session_state.query_result = result
                    st.session_state.execution_df = None
                    st.session_state.evaluation_report = None
                except Exception as e:
                    st.error(f"Error generating query: {e}")
    
    if st.session_state.query_result:
        res = st.session_state.query_result
        if res.generated:
            st.success("Query generated successfully!")
            st.code(res.generated.query, language="sql")
            
            with st.expander("Reasoning & Explainability", expanded=True):
                st.markdown(f"**Interpretation:** {res.generated.hypothesis_interpretation}")
                st.markdown(f"**Reasoning:** {res.generated.query_reasoning}")
                st.markdown(f"**Assumptions:** {res.generated.assumptions_made}")
                st.markdown(f"**Confidence:** {res.generated.confidence_score}")
                if res.generated.detection_gap:
                    st.markdown(f"**Detection Gap:** {res.generated.detection_gap}")
            
            st.markdown("---")
            
            if st.button("Execute Query", type="primary"):
                with st.spinner("Executing query on PostgreSQL..."):
                    try:
                        from src.db import run_query
                        df = run_query(res.generated.query)
                        st.session_state.execution_df = df
                        st.session_state.evaluation_report = None
                    except Exception as e:
                        st.error(f"Execution Error: {e}")
                        
            if st.session_state.execution_df is not None:
                df = st.session_state.execution_df
                st.success(f"Returned {len(df)} rows.")
                st.dataframe(df)
                
                st.markdown("---")
                
                if st.button("Evaluate against Ground Truth", type="primary"):
                    with st.spinner("Evaluating..."):
                        try:
                            client = get_client(provider) if has_api_key else get_client()
                            evaluator = Evaluator(ground_truth, client=client)
                            report = evaluator.evaluate_all([res], {"total_tokens": 0})
                            st.session_state.evaluation_report = report
                        except Exception as e:
                            st.error(f"Evaluation Error: {e}")
                            
                if st.session_state.evaluation_report is not None:
                    report = st.session_state.evaluation_report
                    hyp_eval = next((h for h in report.hypotheses if h.hypothesis_id == selected_hyp_id), None)
                    
                    if hyp_eval:
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Precision", f"{hyp_eval.precision:.4f}")
                        col2.metric("Recall", f"{hyp_eval.recall:.4f}")
                        col3.metric("F1 Score", f"{hyp_eval.f1:.4f}")
                        
                        st.write(f"**Returned:** {hyp_eval.row_count_returned} | **Expected:** {hyp_eval.row_count_expected}")
                        
                        if hyp_eval.error:
                            st.error(f"Error: {hyp_eval.error}")
                    else:
                        st.error("Evaluation results not found for this hypothesis.")
        else:
            st.error("Failed to generate query.")

elif page == "Complete Evaluation":
    st.header("Complete Evaluation")
    st.markdown("Run query generation and evaluation on all hypotheses automatically.")
    
    if st.button("Run Complete Evaluation", type="primary"):
        if not has_api_key:
            st.error("Please provide an API key in the sidebar.")
        else:
            with st.spinner("Running complete evaluation... this may take a few minutes."):
                try:
                    # Generate
                    client = get_client(provider)
                    generator = QueryGenerator(client=client, ground_truth=ground_truth, provider=provider)
                    
                    gen_bar = st.progress(0, text="Generating queries...")
                    def update_gen_progress(completed: int, total: int, msg: str):
                        gen_bar.progress(completed / total, text=f"Generating queries... ({completed}/{total})")
                        
                    results = generator.generate_all(hypotheses, progress_cb=update_gen_progress)
                    gen_bar.progress(1.0, text="Generation complete!")
                    
                    # Evaluate
                    eval_bar = st.progress(0, text="Evaluating queries...")
                    def update_eval_progress(completed: int, total: int, msg: str):
                        eval_bar.progress(completed / total, text=f"Evaluating queries... ({completed}/{total})")
                        
                    evaluator = Evaluator(ground_truth, client=client)
                    total_tokens = sum(r.token_usage.get("total_tokens", 0) for r in results)
                    
                    from src.config import get_llm_model
                    model_name = get_llm_model()
                    
                    report = evaluator.evaluate_all(
                        results, 
                        {"total_tokens": total_tokens}, 
                        progress_cb=update_eval_progress,
                        model_name=model_name
                    )
                    eval_bar.progress(1.0, text="Evaluation complete!")
                    
                    # Save
                    from src.evaluator import generate_markdown_report
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    out_dir = Path(__file__).parent.parent / "results" / timestamp
                    out_dir.mkdir(parents=True, exist_ok=True)
                    
                    queries_file = out_dir / "generated_queries.json"
                    queries_data = [r.model_dump() for r in results]
                    queries_file.write_text(json.dumps(queries_data, indent=2, default=str), encoding="utf-8")
                    
                    eval_file = out_dir / "evaluation_results.json"
                    eval_file.write_text(json.dumps(report.model_dump(), indent=2, default=str), encoding="utf-8")
                    
                    md_file = out_dir / "EVALUATION_REPORT.md"
                    generate_markdown_report(report, path=md_file)
                    
                    st.success(f"Complete evaluation finished! Results saved to `results/{out_dir.name}`")
                    
                    # Show summary
                    st.info(f"**Model Used:** {report.model_name}")
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Macro Precision", f"{report.macro_precision:.4f}")
                    col2.metric("Macro Recall", f"{report.macro_recall:.4f}")
                    col3.metric("Macro F1", f"{report.macro_f1:.4f}")
                    st.metric("Queries Executed OK", f"{report.queries_executed_ok} / {report.total_hypotheses}")
                except Exception as e:
                    st.error(f"Error during complete evaluation: {e}")

elif page == "Results":
    st.header("Results Browser")
    results_dir = Path(__file__).parent.parent / "results"
    
    if not results_dir.exists() or not any(results_dir.iterdir()):
        st.info("No results found. Run a Complete Evaluation first.")
    else:
        # Get directories only, excluding iteration_test_results
        runs = sorted([d.name for d in results_dir.iterdir() if d.is_dir() and d.name != "iteration_test_results"], reverse=True)
        if not runs:
            st.info("No complete evaluation runs found.")
        else:
            selected_run = st.selectbox("Select Run", runs)
            
            run_dir = results_dir / selected_run
            md_file = run_dir / "EVALUATION_REPORT.md"
            if md_file.exists():
                st.markdown(md_file.read_text(encoding="utf-8"))
            else:
                st.warning("EVALUATION_REPORT.md not found in this folder.")

elif page == "Approach & Iterations":
    st.header("Approach & Iterations")
    approach_file = Path(__file__).parent.parent / "APPROACH.md"
    if approach_file.exists():
        st.markdown(approach_file.read_text(encoding="utf-8"))
    else:
        st.warning("APPROACH.md not found.")
