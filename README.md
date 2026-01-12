# Infer-IDS - Malicious Network Traffic Detection

Network Detect is a machine learning-based system for identifying malicious DNS and TLS network traffic. It analyzes network flows captured in PCAP format, extracts behavioral features, and uses trained XGBoost classifiers to detect potential threats with high recall performance.

## Installation

Linux/macOS:
```bash
# Clone the repository
git clone https://github.com/yourusername/network_detect.git
cd network_detect

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install Zeek (required for PCAP processing)
# macOS: brew install zeek
# Linux: Follow instructions at https://zeek.org/download/
```

## Usage

```bash
# Process a PCAP file and generate network logs
python src/network_detect/main.py

# Run Jupyter analysis notebook
jupyter notebook src/network_detect/model/analysis.ipynb

# Generate datasets from labeled network logs
python src/network_detect/model/create_datasets.py
```

## Dependencies
- Zeek (network analysis framework)
- Python 3.10+
- pip
- pandas
- numpy
- scikit-learn
- xgboost
- matplotlib
- seaborn
- jupyter
- joblib

## Workflow

### 1. PCAP Processing

Convert network packet captures to structured logs using Zeek:

```python
from setup.zeek import process_file
from pathlib import Path

pcap_path = Path("path/to/capture.pcap")
log_directory = process_file(pcap_path)
```

### 2. Log Parsing

Parse Zeek-generated logs into Connection objects:

```python
from parse.parse_log import ParseLogs
from pathlib import Path

parser = ParseLogs()
dns_conns, tls_conns = parser.parse_logs(Path("path/to/logs"))

# Convert to pandas DataFrames for analysis
dns_df = parser.to_dataframe(dns_conns)
tls_df = parser.to_dataframe(tls_conns)
```

### 3. Dataset Creation

Build mixed datasets with labeled benign and malicious samples:

```python
from model.create_datasets import DatasetCreator
from pathlib import Path

creator = DatasetCreator(Path("model/datasets/dns"), "dns", ratio=10)
mixed_dataset = creator.build_mixed_dataset(mal_min_size=2000)
```

### 4. Model Training

Train XGBoost classifiers with optimized hyperparameters:

```python
import xgboost as xgb
from sklearn.model_selection import RandomizedSearchCV

model = xgb.XGBClassifier(
    objective="binary:logistic",
    eval_metric=["logloss", "aucpr"],
    scale_pos_weight=3.39,
    random_state=42,
    n_jobs=4
)

# Hyperparameter tuning and training in analysis.ipynb
```

## Feature Engineering

The system extracts behavioral features from network flows:

### Base Features (DNS and TLS)
- Flow duration and packet statistics
- Byte counts and packet ratios
- Average packet lengths (forward and backward)

### DNS-Specific Features
- Query length and entropy
- Subdomain analysis (count, length patterns, digit ratios)
- Answer count and TTL statistics

### TLS-Specific Features
- Protocol version and cipher suite
- Certificate chain fingerprints
- Client and server extensions
- Weak cipher detection

## Model Performance

The system achieves high recall on both DNS and TLS traffic:

- DNS Model: Recall > 99%, Precision > 94%
- TLS Model: Recall > 99%, Precision > 94%

Thresholds are optimized to minimize false negatives (prioritizing recall) as malicious traffic detection requires high sensitivity.

## Training Pipeline

The complete training pipeline is documented in analysis.ipynb. This includes:

- Dataset creation and balancing
- Feature preprocessing and encoding
- Model training with cross-validation
- Hyperparameter optimization
- Threshold tuning for recall optimization
- Performance evaluation with confusion matrices

### Adding New Features

To add new features to connection objects:

1. Define the field in the appropriate dataclass (Connection, DNSConnection, or TLSConnection)
2. Implement calculation logic in the `_calculate_*_features()` method
3. Add extraction logic in parse_log.py's `to_dataframe()` method
4. Include in model training pipeline in analysis.ipynb

## Project Structure

```
src/network_detect/
├── __init__.py              # Package initialization
├── config.py                # Configuration and paths
├── main.py                  # Application entry point
├── utils.py                 # Utility functions for feature extraction
│
├── parse/                   # Network flow parsing
│   ├── __init__.py
│   ├── base_connection.py   # Base Connection dataclass
│   ├── dns_connection.py    # DNS-specific features and fields
│   ├── tls_connection.py    # TLS-specific features and fields
│   └── parse_log.py         # Zeek log parsing and DataFrame conversion
│
├── model/                   # Machine learning models and datasets
│   ├── analysis.ipynb       # Jupyter notebook with training pipeline
│   ├── create_datasets.py   # Dataset creation and preprocessing
│   └── datasets/            # Training and test datasets
│       ├── dns/
│       │   ├── normal/
│       │   └── malicious/
│       └── ssl/
│           ├── normal/
│           └── malicious/
│
├── setup/                   # Zeek integration and configuration
│   ├── zeek.py              # Zeek process execution
│   ├── zeek_parser.py       # Zeek log file parser
│   └── filter.zeek          # Zeek script for filtering and logging
│
├── tables/                  # Database operations
│   └── sql.py               # SQLite database schema and operations
│
├── gui/                     # User interface (future)
└── runs/                    # Generated Zeek logs directory
```

## Security Considerations

This tool is designed for network security analysis and threat detection in controlled environments. When deploying:

- Use on networks where you have authorization to monitor traffic
- Store trained models and predictions securely
- Validate predictions with additional threat intelligence sources
- Monitor model performance over time for concept drift
- Regularly retrain models with new malicious and benign samples

## License

This project is licensed under the terms of the MIT LICENSE. See LICENSE for more details.