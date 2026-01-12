from typing import Dict, List
import joblib
from pathlib import Path
from pandas import DataFrame

from setup.zeek import process_file
from parse.parse_log import ParseLogs
from config import Config


class Main:
    def __init__(self):
        self.parser = ParseLogs()

    def load_model_package(self, package_path: Path) -> Dict:
        package = joblib.load(package_path)
        if "model" not in package or "features" not in package:
            raise ValueError(f"Bad model package at {package_path}. Expected keys: model, features.")
        return package
    
    def ensure_features(self, df: DataFrame, expected_features: List[str]) -> DataFrame:
        df = df.copy()
        for col in expected_features:
            if col not in df.columns:
                df[col] = 0
        return df

    def add_predictions(self, df: DataFrame, package: Dict):
        model = package["model"]
        expected_features = package["features"]
        threshold = package["threshold"]

        X = df[expected_features]

        if hasattr(model, "predict_proba"):
            score = model.predict_proba(X)[:, 1]
        else:
            # fallback
            score = model.predict(X).astype(float)

        df["score"] = score
        df["pred"] = (df["score"] >= threshold).astype(int)
        return df

    def main(self):
        file_path = Config.PCAP_PATH
        log_direct = process_file(file_path)

        dns_connections, tls_connections = self.parser.parse_logs(log_direct)
        dns_df = self.parser.to_dataframe(dns_connections)
        tls_df = self.parser.to_dataframe(tls_connections)

        dns_package = self.load_model_package(Config.MODEL_DIR / "dns_model_package.pkl")
        tls_package = self.load_model_package(Config.MODEL_DIR / "tls_model_package.pkl")

        self.ensure_features(dns_df, dns_package["features"])
        self.ensure_features(tls_df, tls_package["features"])

        dns_df = self.add_predictions(dns_df, dns_package)
        tls_df = self.add_predictions(tls_df, tls_package)

        return dns_df, tls_df
