# Juwan CTI v3.0 — Comprehensive Project Summary

## 1. Executive Summary
Juwan CTI v3.0 is a state-of-the-art **Multi-modal Cyber Threat Intelligence Platform** designed to detect, analyze, and cluster threats across six distinct communication and data channels. By leveraging AI-driven detection (GPT-2, EfficientNet), static malware analysis (YARA/PE), and network forensics (Scapy), the platform provides a unified "Ensemble" threat score with high accuracy.

## 2. Platform Metrics & Technical Details
The system is built for scale and high-fidelity detection.

| Metric | Detail |
| :--- | :--- |
| **Analysis Channels** | 6 (Email, URL, Chat, Image, File, PCAP) |
| **URL Risk Signals** | 25 (Shannon Entropy, Domain Age, MIME Sniffing, etc.) |
| **Text AI-Origin Model** | GPT-2 (124M) Perplexity-based Stylometrics |
| **Image Analysis** | EfficientNet-B0 (Face detection) + Error Level Analysis (ELA) |
| **Clustering Logic** | 3-gram MinHash LSH (128 perms) via `datasketch` |
| **Forensics** | Static PE (pefile), YARA (Malware Rules), PCAP (Scapy) |
| **Data Throughput** | Distributed via Celery/Redis background workers |

## 3. Architecture Overview
The system follows a modular micro-services-style architecture using **FastAPI** on the backend and a **D3.js-powered glassmorphism dashboard** on the frontend. Data is persisted in a **PostgreSQL** IOC store, with **Celery/Redis** handling periodic tasks like campaign clustering and OSINT scraping.

```mermaid
graph TD
    UI[Frontend Dashboard] --> API[FastAPI Backend]
    API --> EM[Email Module]
    API --> URL[URL Module]
    API --> CT[Chat Module]
    API --> IM[Image Module]
    API --> FM[File Module]
    API --> NT[PCAP Module]
    API --> IS[Infrastructure OSINT]
    
    EM & URL & CT & IM & FM & NT --> ENS[6-Channel Ensemble Engine]
    ENS --> IOC[IOC Event Store]
    
    IOC --> CC[Campaign Clusterer]
    CC --> STIX[STIX/TAXII Export]
```

## 3. Platform Statistics & Metrics
The dashboard provides a real-time fleet-wide view of threat activity.

![Updated Dashboard Statistics](C:/Users/HP/.gemini/antigravity/brain/22e22664-322e-400b-a5ec-53c9e894888f/dashboard_updated_stats_1773275837832.png)
*Metrics showing 130+ analyses with 6 HIGH and 43 MEDIUM risk indicators.*

## 4. Threat Scoring Spectrum: Phishing & Malicious Examples
The platform classifies threats into three primary risk tiers based on multi-channel indicators.

### 🔴 High Risk (90%+) - Clear Phishing Attacks
Direct alerts for confirmed malicious patterns and ensemble-validated threats.

````carousel
![High Risk Ensemble](C:/Users/HP/.gemini/antigravity/brain/22e22664-322e-400b-a5ec-53c9e894888f/ensemble_phishing_result_high_risk_1773275821256.png)
<!-- slide -->
![High Risk Chat](C:/Users/HP/.gemini/antigravity/brain/22e22664-322e-400b-a5ec-53c9e894888f/chat_phishing_result_1773275694566.png)
<!-- slide -->
![High Risk Malware](C:/Users/HP/.gemini/antigravity/brain/22e22664-322e-400b-a5ec-53c9e894888f/file_result_malicious_final_2_1773250220476.png)
````

### 🟡 Medium Risk (40-60%) - Suspicious Indicators
Alerts for redirects, entropy anomalies, and infrastructure reputations.

![Medium Risk Email](C:/Users/HP/.gemini/antigravity/brain/22e22664-322e-400b-a5ec-53c9e894888f/email_phishing_result_1773275595567.png)
*Example: Email flagged as Phishing with 50.0% confidence and MEDIUM threat level.*

### 🟢 Low Risk (<20%) - Legitimate Traffic
Filtered results for verified safe communications and infrastructure.

````carousel
![Legitimate Email](C:/Users/HP/.gemini/antigravity/brain/22e22664-322e-400b-a5ec-53c9e894888f/email_legitimate_result_1773247650502.png)
<!-- slide -->
![Legitimate Image](C:/Users/HP/.gemini/antigravity/brain/22e22664-322e-400b-a5ec-53c9e894888f/image_legitimate_result_1773247889199.png)
````

## 5. Technical Stack
| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3.10+, FastAPI, Pydantic |
| **Database** | PostgreSQL 15, SQLAlchemy |
| **Caching/Tasks** | Redis, Celery |
| **AI Models** | GPT-2 (Text), EfficientNet (Image), XGBoost (URL) |
| **Analysis Libs** | Scapy, YARA, Pefile, OpenCV, Pyzbar |
| **Frontend** | Vanilla HTML/JS, CSS (Glassmorphism), D3.js |

---
*Documentation Updated on March 12, 2026.*
