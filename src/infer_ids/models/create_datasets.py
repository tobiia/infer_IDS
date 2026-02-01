from typing import Optional
import pandas as pd
import numpy as np
from pandas import DataFrame
from pathlib import Path
from parse.parse_log import ParseLogs


class DatasetCreator:

    def __init__(self, data_path: Path, log_type: str, ratio: int = 10):
        self.data_path = Path(data_path)
        self.log_type = log_type.lower()
        self.ratio = ratio
        self.parser = ParseLogs()
        self._validate_parameters()
        self.label = None

    def _validate_parameters(self) -> None:
        if not self.data_path.exists():
            raise FileNotFoundError(f"Data path {self.data_path} does not exist")
        if self.log_type not in ("dns", "ssl"):
            raise ValueError("log_type must be 'dns' or 'ssl'")
        if self.ratio <= 0:
            raise ValueError("ratio must be positive")

    def _get_subfolders(self, path: Path) -> list[Path]:
        if not path.exists():
            raise FileNotFoundError(f"Path {path} does not exist")
        
        items = list(path.iterdir())
        subfolders = [item for item in items if item.is_dir()]
        if not subfolders:
            raise FileNotFoundError(f"No directories found in {path}")
        return subfolders

    def _load_folder_data(self, folder: Path) -> DataFrame:
        if self.log_type == "dns":
            connections = self.parser.parse_dns_logs(folder)
        else:
            connections = self.parser.parse_tls_logs(folder)
        
        df = self.parser.to_dataframe(connections)
        
        # only replace label if dataset originally had none
        if self.label is not None:
            if "label" not in df.columns:
                # no label column at all so add it
                df["label"] = self.label
            else:
                # replace only None/NaN values
                mask = df["label"].isna() | df["label"].isnull()
                df.loc[mask, "label"] = self.label

        df["source"] = folder.name
        
        return df

    def _load_multiple_folders(self, folders: list[Path]) -> list[DataFrame]:
        if not folders:
            return []
        
        return [self._load_folder_data(folder) for folder in folders]

    def _load_normal_data(self) -> list[DataFrame]:
        # list will have 1 df per folder
        normal_path = self.data_path / "normal"
        normal_folders = self._get_subfolders(normal_path)
        return self._load_multiple_folders(normal_folders)

    def _load_malicious_data(self) -> list[DataFrame]:
        malicious_path = self.data_path / "malicious"
        malicious_folders = self._get_subfolders(malicious_path)
        return self._load_multiple_folders(malicious_folders)

    def _randomize_dataset_timestamps(self, df_list: list[DataFrame], reference_df: Optional[DataFrame] = None) -> list[DataFrame]:
        if not df_list:
            return df_list
        
        if reference_df is not None and not reference_df.empty:
            min_time = reference_df["ts"].min()
            max_time = reference_df["ts"].max()
        else:
            # no reference = use combined min/max of all datasets
            all_times = [df["ts"].min() for df in df_list if not df.empty] + \
                       [df["ts"].max() for df in df_list if not df.empty]
            min_time = min(all_times)
            max_time = max(all_times)
        
        for df in df_list:
            if not df.empty:
                rng = np.random.default_rng(42)
                df['ts'] = rng.uniform(min_time, max_time, size=len(df))
        
        return df_list

    def _sample_from_each_dataset(self, df_list: list[DataFrame], samples_per_dataset: int) -> DataFrame:
        sampled_dfs = []
        
        for df in df_list:
            if not df.empty:
                if len(df) >= samples_per_dataset:
                    sampled = df.sample(n=samples_per_dataset, random_state=42)
                else:
                    # if dataset is smaller than sample size needed
                    sampled = df.copy()
                sampled_dfs.append(sampled)
        
        return pd.concat(sampled_dfs, ignore_index=True) if sampled_dfs else pd.DataFrame()

    # REVIEW - not using for now but review whether to remove later
    def _calculate_samples_per_dataset(self, normal_dfs: list[DataFrame], malicious_dfs: list[DataFrame]) -> tuple[int, int]:

        normal_count = sum(1 for df in normal_dfs if not df.empty)
        malicious_count = sum(1 for df in malicious_dfs if not df.empty)
        if normal_count == 0 or malicious_count == 0:
            return 0, 0
        
        # Start with a base number for malicious samples per dataset
        base_malicious_per_dataset = 100  # Adjust as needed
        malicious_samples_per_dataset = base_malicious_per_dataset
        
        # Calculate corresponding normal samples per dataset
        normal_samples_per_dataset = (malicious_samples_per_dataset * malicious_count * self.ratio) // normal_count
        
        # Ensure we don't exceed available data
        for df in normal_dfs:
            if not df.empty:
                normal_samples_per_dataset = min(normal_samples_per_dataset, len(df))
        
        for df in malicious_dfs:
            if not df.empty:
                malicious_samples_per_dataset = min(malicious_samples_per_dataset, len(df))
        
        return normal_samples_per_dataset, malicious_samples_per_dataset
    
    def build_normal_dataset(self) -> DataFrame:
        self.label = "benign"
        normal_dfs = self._load_normal_data()
        return pd.concat(normal_dfs, ignore_index=True) if normal_dfs else pd.DataFrame()

    def build_malicious_dataset(self) -> DataFrame:
        self.label = "malicious"
        malicious_dfs = self._load_malicious_data()
        return pd.concat(malicious_dfs, ignore_index=True) if malicious_dfs else pd.DataFrame()

    def build_mixed_dataset(self, mal_min_size: int = 2000, max_size: int = 20000) -> DataFrame:

        # get data from files
        self.label = "benign"
        normal_dfs = self._load_normal_data()
        self.label = "malicious"
        malicious_dfs = self._load_malicious_data()
        
        if not normal_dfs or not malicious_dfs:
            raise ValueError("Cannot build mixed dataset: normal or malicious data is missing")
        
        # calculate sample sizes based on target size and ratio
         # calculate total samples needed based on ratio
        # total_normal_samples = malicious_samples * ratio
        # = normal per dataset * normal count = malicious p dataset * mal count * ratio
        total_malicious_samples = mal_min_size
        total_normal_samples = total_malicious_samples * self.ratio
        
        normal_count = sum(1 for df in normal_dfs if not df.empty)
        malicious_count = sum(1 for df in malicious_dfs if not df.empty)
        
        normal_samples_per_dataset = total_normal_samples // normal_count
        malicious_samples_per_dataset = total_malicious_samples // malicious_count
        
        # randomize timestamps --> only doing this for synthetic datasets!
        reference = normal_dfs[0].copy()
        normal_dfs = self._randomize_dataset_timestamps(normal_dfs, reference)
        malicious_dfs = self._randomize_dataset_timestamps(malicious_dfs, reference)
        
        # sampling from each dataset
        malicious_sampled = self._sample_from_each_dataset(malicious_dfs, malicious_samples_per_dataset)
        normal_sampled = self._sample_from_each_dataset(normal_dfs, normal_samples_per_dataset)
        
        # combine + return
        mixed_df = pd.concat([normal_sampled, malicious_sampled], ignore_index=True)
        mixed_df = mixed_df.sort_values("ts").reset_index(drop=True)
        
        return mixed_df