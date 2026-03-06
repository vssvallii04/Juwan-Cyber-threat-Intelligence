# Cyber Threat Intelligence (CTI) System

Advanced threat detection system for identifying phishing emails, malicious URLs, and chat scams using an ensemble of machine learning models.

## Project Structure

```
cyber_threat_intelligence/
├── src/                              # Source code directory
│   ├── cti/                          # Core package
│   │   ├── api/                      # FastAPI application
│   │   │   ├── main.py              # App factory and initialization
│   │   │   └── routes/              # API endpoint definitions
│   │   │       ├── email.py         # Email phishing detection endpoints
│   │   │       ├── url.py           # URL phishing detection endpoints
│   │   │       ├── chat.py          # Chat scam detection endpoints
│   │   │       └── ensemble.py      # Ensemble threat decision endpoints
│   │   ├── core/                    # Core configurations and schemas
│   │   │   ├── schemas.py           # Pydantic request/response models
│   │   │   └── config.py            # Application settings
│   │   ├── models/                  # ML threat detection models
│   │   │   ├── email_model.py       # Email phishing detector
│   │   │   ├── url_model.py         # URL phishing detector
│   │   │   └── chat_model.py        # Chat scam detector
│   │   ├── features/                # Feature extraction
│   │   │   └── extractors.py        # Feature extraction utilities
│   │   ├── preprocessing/           # Data preprocessing
│   │   │   └── text_processor.py    # Text cleaning and processing
│   │   ├── utils/                   # Utility functions
│   │   │   ├── ensemble.py          # Ensemble decision logic
│   │   │   └── hash_utils.py        # Hashing utilities
│   │   └── forensics/               # Audit logging
│   │       └── manager.py           # Forensic event logging
│   ├── __init__.py
├── frontend/                         # Web interface (static files)
│   ├── index.html                   # Dashboard UI
│   ├── app.js                       # Frontend logic
│   ├── style.css                    # Styling
│   └── script.js                    # Utility scripts
├── config/                          # Configuration files
│   └── settings.py                  # Global settings
├── data/                            # Data directory
│   └── sample_emails.csv            # Sample dataset
├── tests/                           # Test suite
├── main.py                          # Application entry point
├── requirements.txt                 # Python dependencies
├── .gitattributes                   # Git configuration
├── .gitignore                       # Git ignore rules
└── README.md                        # This file
```

## Key Features

- **Email Phishing Detection**: ML-based classification of phishing emails
- **URL Phishing Detection**: Feature-based analysis of suspicious URLs
- **Chat Scam Detection**: Keyword-based detection of chat scams
- **Ensemble Decision Making**: Combines multiple models for robust threat assessment
- **Threat Level Classification**: Reports as LOW, MEDIUM, or HIGH threat
- **Forensic Logging**: Complete audit trail of all analysis actions
- **Interactive Dashboard**: Web-based threat intelligence dashboard

## Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup

1. **Create virtual environment**:
   ```bash
   python -m venv .venv
   .venv\Scripts\Activate.ps1  # On Windows
   # or
   source .venv/bin/activate   # On Linux/Mac
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Running the Application

### Using FastAPI & Uvicorn

From the project root directory:

```bash
# Option 1: Using new entry point
python main.py

# Option 2: Using uvicorn directly
uvicorn main:app --reload --host 127.0.0.1 --port 8000

# Option 3: For production
uvicorn main:app --host 0.0.0.0 --port 8000
```

The API will be available at: `http://127.0.0.1:8000`

## API Endpoints

### Email Phishing Detection
```
POST /analyze/email/analyze
Content-Type: application/json

{
  "text": "Email content to analyze..."
}
```

### URL Phishing Detection
```
POST /analyze/url/analyze
Content-Type: application/json

{
  "url": "http://suspicious-url.com"
}
```

### Chat Scam Detection
```
POST /analyze/chat/analyze
Content-Type: application/json

{
  "text": "Chat message to analyze..."
}
```

### Ensemble Threat Decision
```
POST /analyze/ensemble/analyze
Content-Type: application/json

{
  "email": "Optional email text",
  "url": "Optional URL",
  "chat": "Optional chat message"
}
```

## Response Format

### Email/Chat Analysis
```json
{
  "artifact_id": "unique-id",
  "module": "email",
  "prediction": "phishing|legitimate",
  "confidence": 0.85
}
```

### URL Analysis
```json
{
  "artifact_id": "unique-id",
  "module": "url",
  "prediction": "phishing|legitimate",
  "confidence": 0.85,
  "feature_contributions": {
    "url_length": 0.05,
    "num_dots": 0.03,
    "has_ip": 0.0,
    "has_https": 0.2,
    "suspicious_words": 0.27
  },
  "raw_features": {
    "url_length": 32,
    "num_dots": 1,
    "has_ip": false,
    "has_https": false,
    "suspicious_words": 2
  }
}
```

### Ensemble Decision
```json
{
  "artifact_id": "unique-id",
  "email": { ... },
  "url": { ... },
  "chat": { ... },
  "final_decision": {
    "final_decision": "phishing",
    "confidence": 0.72,
    "threat_level": "HIGH",
    "indicators_found": 2,
    "total_modules_analyzed": 2,
    "confidence_breakdown": {
      "email": 0.85,
      "url": 0.49
    },
    "module_explanations": [...]
  }
}
```

## Threat Level Classification

- **HIGH**: Multiple modules detecting phishing OR single module with strong confidence (≥48%)
- **MEDIUM**: Moderate confidence detection (≥40%)
- **LOW**: No significant indicators detected

## Development

### Adding New Models

1. Create model file in `src/cti/models/`
2. Implement prediction function
3. Export in `src/cti/models/__init__.py`
4. Add route in `src/cti/api/routes/`
5. Include in `src/cti/api/main.py`

### Testing

Run tests from project root:
```bash
pytest tests/ -v
```

## Configuration

Edit `config/settings.py` to customize:
- API host and port
- CORS settings
- Model paths
- Debug mode

## License

Proprietary - Cyber Threat Intelligence

## Version

1.0.0 (March 2026)
