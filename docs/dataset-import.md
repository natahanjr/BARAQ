# Dataset Import Guide

This guide explains how to import external security datasets into BARAQ for ML training and detection validation.

## Supported Dataset Sources

### OTRF Security-Datasets

The Open Threat Research Foundation (OTRF) provides pre-labeled attack and benign datasets with MITRE ATT&CK mappings.

- **Source**: https://github.com/OTRF/Security-Datasets
- **Formats**: JSON (OCSF), CSV
- **Labels**: Attack/Benign with MITRE technique mappings

### BOTSv1 (Boss of the SOC)

Splunk's Boss of the SOC v1 dataset with attack and benign events.

- **Source**: https://github.com/splunk/botsv1
- **Format**: CSV

### BOTES (Boss of the SOC v2)

Splunk's Boss of the SOC v2 dataset.

- **Source**: https://github.com/splunk/botes
- **Format**: CSV

## Importing via API

### 1. List Available Sources

```bash
curl -X GET "http://localhost:8001/api/ml/datasets/import/sources" \
  -H "Authorization: Bearer <token>"
```

### 2. Start Import

```bash
curl -X POST "http://localhost:8001/api/ml/datasets/import/start" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset": "security_datasets",
    "max_events": 100000
  }'
```

### 3. Check Progress

```bash
curl -X GET "http://localhost:8001/api/ml/datasets/import/tasks/<task_id>" \
  -H "Authorization: Bearer <token>"
```

### 4. View Dataset Statistics

```bash
curl -X GET "http://localhost:8001/api/datasets/status" \
  -H "Authorization: Bearer <token>"
```

## Importing via CLI

### Using the import script

```bash
python scripts/import_otrf.py --data-dir /path/to/datasets --max-events 100000
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `BARAQ_OTRF_DATA_DIR` | Directory containing OTRF datasets | `datasets/otrf` |

### Directory Structure

```
datasets/
├── otrf/           # OTRF Security-Datasets
├── botsv1/         # BOTSv1 datasets
└── botes/          # BOTES datasets
```

## Data Format

### OCSF Format (OTRF)

Events should be in OCSF (Open Cybersecurity Schema Framework) format:

```json
{
  "time": "2021-09-01T00:00:00Z",
  "category_name": "authentication",
  "class_name": "Authentication",
  "activity_id": 1,
  "user": {"name": "admin"},
  "source": {"ip": "192.168.1.100"}
}
```

### BARAQ Normalized Format

The adapter normalizes external datasets into BARAQ's internal format with fields:

- `event_id`: Windows Event ID equivalent
- `channel`: Event source category
- `timestamp`: ISO 8601 timestamp
- `host`: Source hostname
- `user`: User account
- `source_ip`: Source IP address
- `label`: Attack (1) or Benign (0)

## Troubleshooting

### Import Fails

1. Check the import task status for error messages
2. Verify the dataset directory exists and contains valid files
3. Check disk space for large imports

### Low Event Count

1. Ensure the dataset files are in the correct format (JSON/CSV)
2. Check that timestamps are parseable
3. Verify the adapter supports the dataset's schema version
