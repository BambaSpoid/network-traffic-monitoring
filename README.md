# Network Traffic Monitoring with Elasticsearch

This project demonstrates an end-to-end data pipeline for monitoring network traffic using Elasticsearch.

The goal is to ingest network connection data, index it efficiently, and build key indicators to analyze traffic patterns and detect abnormal behaviors.

## Stack

- Python
- Elasticsearch
- Kibana

## Use case

- Traffic volume monitoring
- Protocol distribution
- Identification of abnormal traffic patterns

dataset: Kaggle : href[https://www.kaggle.com/datasets/agungpambudi/network-malware-detection-connection-analysis]

## Kibana Dashboard (Monitoring)

This project includes a minimum viable monitoring dashboard with:

- Traffic volume over time (sum of orig_bytes by day)
- Protocol distribution
- Top source IPs by traffic volume
- Label trend (Benign vs Malicious)

### Screenshots

See `dashboard/screenshots/`.

### Export

Kibana saved objects export: `dashboard/exports/kibana_saved_objects.ndjson`
Import it via: Stack Management → Saved Objects → Import
