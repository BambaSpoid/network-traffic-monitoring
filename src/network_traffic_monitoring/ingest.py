import json
import warnings
from pathlib import Path
import pandas as pd
from elasticsearch import Elasticsearch, helpers
from elasticsearch.helpers import BulkIndexError
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv
import os

# =========================
# Config
# =========================
load_dotenv()

ES_INDEX = os.getenv("ES_INDEX", "network-traffic-monitoring")
ES_URL = os.getenv("ES_URL")
ES_USER = os.getenv("ES_USER")
ES_PASS = os.getenv("ES_PASSWORD")

if not all([ES_URL, ES_USER, ES_PASS]):
    raise RuntimeError("Missing Elasticsearch environment variables")

CSV_PATH = Path("data/raw/CTU-IoT-Malware-Capture-1-1conn.log.labeled.csv")
MAPPING_PATH = Path("elastic/mapping.json")

# Nombre de lignes pour tester (mets None pour tout ingérer)
LIMIT_ROWS = None  # <-- change à None quand tout marche

BULK_CHUNK_SIZE = 2000
REQUEST_TIMEOUT = 120


# =========================
# Helpers
# =========================
def connect_es() -> Elasticsearch:
    # Dev: ignorer l'alerte TLS auto-signée
    warnings.simplefilter("ignore", InsecureRequestWarning)

    es = Elasticsearch(
        ES_URL,
        basic_auth=(ES_USER, ES_PASS),
        verify_certs=False,  # DEV only
        request_timeout=REQUEST_TIMEOUT,
    )
    return es


def ensure_index(es: Elasticsearch) -> None:
    if es.indices.exists(index=ES_INDEX):
        print(f"Index exists: {ES_INDEX}")
        return

    if not MAPPING_PATH.exists():
        raise FileNotFoundError(f"Missing mapping file: {MAPPING_PATH}")

    with MAPPING_PATH.open("r", encoding="utf-8") as f:
        body = json.load(f)

    es.indices.create(index=ES_INDEX, **body)
    print(f"Index created: {ES_INDEX}")


def load_and_prepare_df() -> pd.DataFrame:
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"CSV not found: {CSV_PATH}")

    df = pd.read_csv(CSV_PATH, sep="|")

    # Rename columns
    df = df.rename(
        columns={
            "id.orig_h": "src_ip",
            "id.orig_p": "src_port",
            "id.resp_h": "dst_ip",
            "id.resp_p": "dst_port",
            "proto": "protocol",
        }
    )

    # Replace '-' with NA before conversions
    df = df.replace("-", pd.NA)

    # Timestamp from epoch seconds (float)
    df["timestamp"] = pd.to_datetime(df["ts"], unit="s", errors="coerce")

    # Numeric conversions (robust)
    num_cols = [
        "src_port",
        "dst_port",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "orig_ip_bytes",
        "resp_ip_bytes",
    ]
    for c in num_cols:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # Fill categorical fields
    if "service" in df.columns:
        df["service"] = df["service"].fillna("unknown")
    else:
        df["service"] = "unknown"

    if "label" in df.columns:
        df["label"] = df["label"].fillna("unknown")
    else:
        df["label"] = "unknown"

    # Select final columns
    columns = [
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "orig_pkts",
        "resp_pkts",
        "orig_ip_bytes",
        "resp_ip_bytes",
        "label",
    ]
    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df[columns]

    # Optional: limit rows for first run
    if LIMIT_ROWS is not None:
        df = df.head(LIMIT_ROWS)

    # Optional: drop rows with missing timestamp or IPs (keeps ES mapping clean)
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip", "protocol"])

    return df


def gen_actions(df: pd.DataFrame):
    for _, row in df.iterrows():
        doc = row.dropna().to_dict()
        yield {"_index": ES_INDEX, "_source": doc}


def bulk_index(es: Elasticsearch, df: pd.DataFrame) -> None:
    print(f"Rows to index: {len(df):,}")

    try:
        success, _ = helpers.bulk(
            es,
            gen_actions(df),
            chunk_size=BULK_CHUNK_SIZE,
            request_timeout=REQUEST_TIMEOUT,
            raise_on_error=True,
        )
        print(f"Bulk indexing OK. Indexed docs: {success:,}")
    except BulkIndexError as e:
        print(f"FAILED: {len(e.errors)} document(s) failed to index.")
        # Show the first 3 errors with context
        for err in e.errors[:3]:
            action = list(err.keys())[0]  # typically "index"
            payload = err[action]
            reason = payload.get("error", {})
            print("----")
            print("status:", payload.get("status"))
            print("type:", reason.get("type"))
            print("reason:", reason.get("reason"))
            print("caused_by:", (reason.get("caused_by") or {}).get("reason"))
            print("doc:", payload.get("data"))
        raise


def main():
    es = connect_es()

    print("ping:", es.ping())
    info = es.info()
    print(
        "cluster:",
        info.get("cluster_name"),
        "| version:",
        info.get("version", {}).get("number"),
    )

    ensure_index(es)

    df = load_and_prepare_df()
    bulk_index(es, df)

    # Verify count
    cnt = es.count(index=ES_INDEX)["count"]
    print(f"Index count({ES_INDEX}): {cnt:,}")


if __name__ == "__main__":
    main()
