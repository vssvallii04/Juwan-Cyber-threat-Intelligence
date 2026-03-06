# Cyber Threat Intelligence API

A production-grade **FastAPI-based Cyber Threat Intelligence system** that detects phishing emails, malicious URLs, and scam messages using machine learning and pattern analysis.

## Features

✅ **Email Phishing Detection** - Analyzes email content for phishing indicators  
✅ **URL Phishing Detection** - Identifies malicious URLs using domain analysis  
✅ **Chat Scam Detection** - Detects scam keywords in chat messages  
✅ **Ensemble Decision Making** - Combines multiple threat signals  
✅ **Threat Level Classification** - HIGH, MEDIUM, LOW threat levels  
✅ **REST API** - FastAPI endpoints with error handling  
✅ **Web Dashboard** - Interactive frontend for testing  
✅ **Production Logging** - Comprehensive logging system  
✅ **Configuration Management** - Environment-based settings  

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/vssvallii04/cyber_threat_intelligence.git
cd cyber_threat_intelligence

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
python -m nltk.downloader stopwords punkt wordnet
```

### Run Server

```bash
python app.py
# or
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

**Access:**
- API: http://127.0.0.1:8000
- Docs: http://127.0.0.1:8000/docs
- Dashboard: `frontend/index.html`

## API Endpoints

### POST /analyze/email
```json
{"text": "Email content to analyze..."}
```

### POST /analyze/url
```json
{"url": "http://suspicious-domain.com"}
```

### POST /analyze/chat
```json
{"text": "Chat message to analyze..."}
```

### POST /analyze/ensemble
```json
{"email": "...", "url": "...", "chat": "..."}
```

## Configuration

Create `.env` file from `.env.example`:

```env
ENVIRONMENT=dev
LOG_LEVEL=DEBUG
URL_THRESHOLD=0.45
THREAT_HIGH_SCORE=0.60
```

## Project Structure

```
├── app.py                 # Main FastAPI app
├── config.py              # Configuration
├── logger.py              # Logging setup
├── exceptions.py          # Error handlers
├── validation.py          # Input validation
├── models/
│   ├── email_model.py
│   ├── url_model.py
│   └── chat_model.py
├── utils/
│   └── ensemble.py
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── style.css
└── requirements.txt
```

## Key Features

### ✅ Fixed Bugs (v2.0.0)
1. Chat confidence calculation - Now dynamic
2. Ensemble chat processing - Includes chat input
3. URL feature normalization - 0-1 scaling
4. HTTPS weight - Corrected to positive
5. Input validation - Comprehensive checks
6. Threat level classification - Multi-factor logic

### 🚀 Enhancements
- Standardized error handling (4xx, 5xx status codes)
- Production logging to file and console
- Enhanced URL detection (21+ keywords, pattern matching)
- Input sanitization (null bytes, control characters)
- Environment-based configuration
- Frontend error display with color coding

## Testing

```bash
# Test phishing email
POST /analyze/email
{"text": "Click to verify account immediately..."}

# Test malicious URL
POST /analyze/url
{"url": "http://bank-kyc-update-alert.com"}

# Test scam chat
POST /analyze/chat
{"text": "Verify OTP urgent password bank"}
```

## Deployment

### Development
```bash
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

### Production
```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app:app --bind 0.0.0.0:8000
```

## Logging

Logs saved to `logs/cti_api.log`:
```
2026-03-07 12:34:56,789 - logger - INFO - Email analysis started
2026-03-07 12:34:57,123 - logger - INFO - Prediction: phishing, Confidence: 0.85
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Model not found | Ensure `models/` pickle files exist |
| CORS error | Update `CORS_ORIGINS` in `.env` |
| Port in use | Change port or kill process: `lsof -i :8000\|kill -9` |
| Import error | Reinstall: `pip install --upgrade -r requirements.txt` |

## Security

⚠️ Before production:
- [ ] Set `DEBUG=False`
- [ ] Configure specific `CORS_ORIGINS`
- [ ] Enable HTTPS/TLS
- [ ] Add API authentication
- [ ] Implement rate limiting
- [ ] Use environment variables

## Performance

- Email: ~50-100ms
- URL: ~10-20ms
- Chat: ~5-10ms
- Ensemble: ~100-150ms

## License

MIT License

## Support

- Issues: [GitHub Issues](https://github.com/vssvallii04/cyber_threat_intelligence/issues)
- Docs: Check inline comments
- Examples: See `frontend/index.html`

## Version

**v2.0.0** (2026-03-07)
- Standardized error handling
- Production logging
- Enhanced URL detection
- Input validation & sanitization

**v1.0.0** (Initial Release)

---

**Happy Threat Detection! 🛡️**
