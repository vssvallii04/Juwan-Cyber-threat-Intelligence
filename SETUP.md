# Juwan CTI v3.0 — Setup Guide (New Device)

## 1. Prerequisites
- Python 3.10+
- Docker Desktop (running)
- Git

## 2. Clone the Repository
```bash
git clone https://github.com/vssvallii04/Juwan-Cyber-threat-Intelligence.git
cd Juwan-Cyber-threat-Intelligence
git checkout cti-v3
```

## 3. Create Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac
```

## 4. Install Dependencies
```bash
pip install -r requirements.txt
```

> **Note:** `yara-python` and `pefile` may require Visual C++ Build Tools on Windows.
> Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

## 5. Configure Environment
```bash
copy .env.example .env
# Edit .env with your PostgreSQL / Redis credentials
```

Default `.env` values work with Docker Compose out of the box.

## 6. Start Infrastructure (PostgreSQL + Redis)
```bash
docker-compose up -d db redis
```

Wait ~5 seconds for PostgreSQL to be ready.

## 7. Train the Email Model (required — PKL not tracked by git)
```bash
python train_email_model.py
```

This generates `models/email_model.pkl` and `models/tfidf_vectorizer.pkl`.

## 8. Train the URL Model (optional — already committed as pkl)
```bash
python scripts/train_url_model.py
```

## 9. Run the Server
```bash
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

## 10. Open Dashboard
Navigate to: **http://127.0.0.1:8000**

Swagger API docs: **http://127.0.0.1:8000/docs**

---

## 11. (Optional) Start Celery Worker for Campaign Clustering
```bash
# In a separate terminal:
celery -A intelligence.campaign_clusterer worker --loglevel=info
```

---

## Architecture Overview

| Layer | Technology |
|---|---|
| API | FastAPI + Uvicorn |
| Database | PostgreSQL (via Docker) |
| Cache / Queue | Redis + Celery |
| ML Models | XGBoost, scikit-learn, HuggingFace Transformers |
| Intelligence | STIX 2.1, TAXII 2.1, MinHash LSH |

## Endpoint Summary

| Group | Base Path |
|---|---|
| System | `/health`, `/api/status` |
| Detection | `/analyze/email`, `/url`, `/chat`, `/image`, `/qr`, `/file`, `/pcap` |
| Ensemble | `/analyze/ensemble` |
| Infrastructure | `/analyze/infrastructure/{query}` |
| Intelligence | `/intelligence/stats`, `/campaigns` |
| TAXII | `/taxii/api-root/collections/` |
| Docs | `/docs` (Swagger) |
