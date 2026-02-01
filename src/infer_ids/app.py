from pathlib import Path
from typing import Dict, Tuple, Optional

import pandas as pd
from pandas import DataFrame
import streamlit as st
from streamlit_file_browser import st_file_browser

from setup.zeek import process_file
from parse.parse_log import ParseLogs
from core import get_model_path, load_model_package, ensure_features, preferred_columns, add_predictions


# STATE FUNCTIONS

def init_state() -> None:
    # saving parsed dfs (pcaps) + the current pcap active/the user is looking at
    # session_state["pcaps"][pcap_name] = {"dns": df, "tls": df}
    if "pcaps" not in st.session_state:
        st.session_state["pcaps"] = {}
    if "active_pcap" not in st.session_state:
        st.session_state["active_pcap"] = None


def store_parsed_dfs(pcap_name: str, dns_df: DataFrame, tls_df: DataFrame) -> None:
    st.session_state["pcaps"][pcap_name] = {
        "dns": dns_df,
        "tls": tls_df,
        "pred_done": {"dns": False, "tls": False},
    }
    st.session_state["active_pcap"] = pcap_name


def get_active_record() -> Dict:
    name = st.session_state.get("active_pcap")
    return st.session_state["pcaps"].get(name)

# PCAP FUNCTIONS

@st.cache_resource
def get_parser() -> ParseLogs:
    return ParseLogs()

def pcap_to_df(pcap_path: Path) -> Tuple[DataFrame, DataFrame]:
    parser = get_parser()

    with process_file(pcap_path) as log_dir:
        dns_conns, tls_conns = parser.parse_logs(log_dir)

    dns_df = parser.to_dataframe(dns_conns)
    tls_df = parser.to_dataframe(tls_conns)

    return dns_df, tls_df

def df_to_download(df: DataFrame):
    return df.to_csv(index=False).encode("utf-8")


# UI

def render_table(df: DataFrame) -> None:
    show_cols = preferred_columns(df)

    df = df.reset_index(drop=True).copy()
    df["_row_id"] = df.index

    event = st.dataframe(
        df[["_row_id"] + show_cols],
        selection_mode="single-row",
        on_select="rerun",
        hide_index=True,
    )

    st.info("Select a row/checkbox to see its binary classification and full feature set.")

    selected_row: Optional[int] = None
    try:
        sel = event.selection.rows
        if sel:
            selected_row = sel[0]
    except Exception:
        selected_row = None

    if selected_row is None:
        return

    row_series = df.iloc[selected_row]
    row_dict = {k: v for k, v in row_series.to_dict().items() if pd.notna(v)}

    with st.expander("Full Feature Set", expanded=True):
        st.json(row_dict)

# APPLICATION

def main():
    st.set_page_config(page_title="Infer-IDS", layout="wide")
    st.title("Infer-IDS")

    init_state()

    with st.sidebar:
        st.header("Settings")
        flow_choice = st.selectbox("View", ["dns", "tls"])
        st.divider()
        st.write("You can switch between the DNS and TLS flows using the toggle switch above.")

        st.info("Make sure to only use on networks where you have authorization to monitor traffic. Have fun!")

    st.info("Welcome to **Infer-IDS**! This is a simple machine learning-based system for identifying malicious DNS and TLS network traffic. It analyzes network flows captured in PCAP format, extracts behavioral features, and uses trained XGBoost classifiers to detect potential threats with high recall performance.")

    # uploader
    # REVIEW there are basically no instruction for st_file_browser and below is from
    # searching through github code samples, may not work
    st.info("Please pick the PCAP file you would like to analyze, then select **Choose** in the upper right.")

    event = st_file_browser(
        str(Path.home()),
        show_preview=False,
        key="pcap_browser",
        show_choose_file=True,
        show_download_file=False,
        glob_patterns=("**/*.pcap"),
    )

    try:
        if event and event.get("type") == "CHOOSE_FILE":
            target = event.get("target")
            pcap_path = Path(target[0]["path"])
            pcap_path = Path.home() / pcap_path
            with st.spinner(f"Parsing {pcap_path.name} with Zeek..."):
                try:
                    dns_df, tls_df = pcap_to_df(pcap_path)
                except Exception as e:
                    st.error(f"Failed parsing {pcap_path.name}: {e}")
                    return

            store_parsed_dfs(pcap_path.name, dns_df, tls_df)
            st.success(f"Loaded: {pcap_path.name}. Scroll down!")
    except Exception as e:
        st.warning("Something went wrong while getting the pcap file: ")
        st.error(e)
        return

    # retrieve dfs for this pcap
    record = get_active_record() # dict of the 2 dfs
    if record is None:
        st.info("Please upload a PCAP file to begin")
        return

    # display df user has chosen (flow_choice = button, dns or tls)
    df_current = record[flow_choice]

    st.divider()
    st.info("You can now explore your network flows and see the classification results!")
    st.subheader(f"{flow_choice.upper()} View")

    pkg_path = get_model_path(flow_choice)

    run_predict = st.button("Run / Update Predictions")

    should_predict = run_predict or (not record["pred_done"][flow_choice])

    # state should use the df the preds are added to
    df_pred = df_current

    if should_predict:
        try:
            package = load_model_package(pkg_path)
            df_current = ensure_features(df_current, package["features"])
            df_pred = add_predictions(df_current, package)
            record[flow_choice] = df_pred
            record["pred_done"][flow_choice] = True
        except Exception as e:
            st.error(f"Prediction failed: {e}")
            return

    # ensures table is rendered based on user toggle choice
    render_table(record[flow_choice])

if __name__ == "__main__":
    main()