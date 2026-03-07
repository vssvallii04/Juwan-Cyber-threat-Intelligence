"""
models/ai_origin_detector.py — Juwan CTI v3.0
Detects whether an email was written by an LLM (AI-generated phishing).

Pipeline:
  1. GPT-2 124M token-level perplexity  (low perplexity → AI-written)
  2. 6 stylometric features via spaCy + NLTK
  3. XGBClassifier fuses both into ai_origin_probability

Lazy-loading singleton — models loaded once on first call.
Falls back to perplexity-only heuristic if XGB weights not trained yet.
"""
from pathlib import Path
import math
import re
from logger import get_logger
from config import settings

logger = get_logger(__name__)

MODEL_DIR  = Path(__file__).parent
XGB_PATH   = MODEL_DIR / "ai_origin_xgb.pkl"

# ── Singletons ────────────────────────────────────────────────────────
_gpt2_model     = None
_gpt2_tokenizer = None
_xgb_model      = None
_spacy_nlp      = None


def _load_gpt2():
    global _gpt2_model, _gpt2_tokenizer
    if _gpt2_model is None:
        try:
            import torch
            from transformers import GPT2LMHeadModel, GPT2TokenizerFast
            logger.info("Loading GPT-2 124M for perplexity scoring...")
            _gpt2_tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
            _gpt2_model     = GPT2LMHeadModel.from_pretrained("gpt2")
            _gpt2_model.eval()
            logger.info("[OK] GPT-2 loaded")
        except Exception as e:
            logger.warning(f"GPT-2 unavailable: {e}")
    return _gpt2_model is not None


def _load_xgb():
    global _xgb_model
    if _xgb_model is None and XGB_PATH.exists():
        try:
            import joblib
            _xgb_model = joblib.load(XGB_PATH)
            logger.info("[OK] AI-origin XGB model loaded")
        except Exception as e:
            logger.warning(f"XGB model load failed: {e}")
    return _xgb_model


def _load_spacy():
    global _spacy_nlp
    if _spacy_nlp is None:
        try:
            import spacy
            _spacy_nlp = spacy.load("en_core_web_sm")
            logger.info("[OK] spaCy en_core_web_sm loaded")
        except Exception as e:
            logger.warning(f"spaCy unavailable: {e}")
    return _spacy_nlp


# ── Perplexity ────────────────────────────────────────────────────────

def _compute_perplexity(text: str, max_tokens: int = 512) -> float:
    """
    Compute GPT-2 token-level perplexity.
    AI-generated text: ~15–35   Human text: ~60–150+
    Returns 999.0 if GPT-2 is unavailable.
    """
    if not _load_gpt2():
        return 999.0
    try:
        import torch
        tokens = _gpt2_tokenizer(
            text, return_tensors="pt", truncation=True, max_length=max_tokens
        )
        input_ids = tokens["input_ids"]
        with torch.no_grad():
            outputs = _gpt2_model(input_ids, labels=input_ids)
            loss = outputs.loss.item()
        return round(math.exp(loss), 4)
    except Exception as e:
        logger.debug(f"Perplexity calc failed: {e}")
        return 999.0


# ── Stylometric Features ──────────────────────────────────────────────

def _extract_stylometrics(text: str) -> dict:
    """
    Extract 6 stylometric signals:
      1. avg_sentence_length    — short uniform sentences → AI
      2. type_token_ratio       — high lexical variety → human
      3. punctuation_variance   — low variance → AI
      4. passive_voice_pct      — AI tends more active voice
      5. question_density       — scam phishing has more questions
      6. imperative_verb_freq   — "click", "verify", "update" = phishing
    """
    IMPERATIVE_VERBS = {
        "click", "verify", "update", "confirm", "login", "sign",
        "send", "provide", "enter", "submit", "call", "contact",
        "download", "install", "open", "check", "review",
    }

    nlp = _load_spacy()

    sentences   = re.split(r"[.!?]+", text.strip())
    sentences   = [s.strip() for s in sentences if len(s.strip()) > 3]
    words       = re.findall(r"\b\w+\b", text.lower())
    unique_words = set(words)

    # 1. Avg sentence length
    sent_lengths = [len(re.findall(r"\b\w+\b", s)) for s in sentences]
    avg_sent_len = (sum(sent_lengths) / len(sent_lengths)) if sent_lengths else 0.0

    # 2. Type-token ratio
    ttr = (len(unique_words) / len(words)) if words else 0.0

    # 3. Punctuation variance
    punct_counts = [len(re.findall(r"[,;:!?]", s)) for s in sentences]
    if len(punct_counts) > 1:
        import statistics
        punct_var = statistics.variance(punct_counts)
    else:
        punct_var = 0.0

    # 4. Passive voice %
    passive_count = 0
    total_sent    = max(len(sentences), 1)
    if nlp:
        try:
            doc = nlp(text[:5000])
            for sent in doc.sents:
                if any(
                    tok.dep_ == "nsubjpass" or tok.tag_ == "VBN"
                    for tok in sent
                ):
                    passive_count += 1
        except Exception:
            pass
    passive_pct = passive_count / total_sent

    # 5. Question density
    q_density = text.count("?") / max(len(sentences), 1)

    # 6. Imperative verb frequency
    imp_hits = sum(1 for w in words if w in IMPERATIVE_VERBS)
    imp_freq  = imp_hits / max(len(words), 1)

    return {
        "avg_sentence_length": round(avg_sent_len, 4),
        "type_token_ratio":    round(ttr, 4),
        "punctuation_variance": round(punct_var, 4),
        "passive_voice_pct":   round(passive_pct, 4),
        "question_density":    round(q_density, 4),
        "imperative_verb_freq": round(imp_freq, 4),
    }


# ── Heuristic Fallback ────────────────────────────────────────────────

def _heuristic_probability(perplexity: float, stylometrics: dict) -> float:
    """
    Rule-based AI probability when XGB model not yet trained.
    Low perplexity + low TTR + high imperative density → AI-written.
    """
    score = 0.0

    # Perplexity: lower = more AI
    if perplexity < 20:
        score += 0.50
    elif perplexity < 40:
        score += 0.30
    elif perplexity < 70:
        score += 0.10

    # Type-token ratio: lower = less diverse = more AI
    ttr = stylometrics.get("type_token_ratio", 0.5)
    if ttr < 0.30:
        score += 0.15
    elif ttr < 0.45:
        score += 0.08

    # Imperative verbs (phishing intent compound)
    imp = stylometrics.get("imperative_verb_freq", 0.0)
    score += min(imp * 1.5, 0.25)

    # Uniform sentence length (low variance = AI pattern)
    avg_s = stylometrics.get("avg_sentence_length", 15)
    if 10 < avg_s < 18:
        score += 0.05

    return round(min(score, 1.0), 4)


# ── Public API ────────────────────────────────────────────────────────

def analyze_ai_origin(text: str) -> dict:
    """
    Detect whether text was AI-generated.

    Args:
        text: Email body or any text sample

    Returns:
        dict with prediction, confidence, ai_origin_probability,
        perplexity, stylometric_features, indicators, indicator_weights
    """
    perplexity   = _compute_perplexity(text)
    stylometrics = _extract_stylometrics(text)

    xgb = _load_xgb()

    if xgb is not None:
        try:
            import numpy as np
            feat_vec = [perplexity] + list(stylometrics.values())
            prob = float(xgb.predict_proba([feat_vec])[0][1])
        except Exception as e:
            logger.debug(f"XGB inference failed, using heuristic: {e}")
            prob = _heuristic_probability(perplexity, stylometrics)
    else:
        prob = _heuristic_probability(perplexity, stylometrics)
        logger.debug(f"XGB not trained yet — using heuristic. probability={prob}")

    confidence = round(prob, 4)
    prediction = "ai_generated" if confidence >= settings.AI_ORIGIN_THRESHOLD else "human"

    # Build human-readable indicators
    indicators = []
    if perplexity < 40:
        indicators.append(f"low_perplexity:{perplexity}")
    if stylometrics["type_token_ratio"] < 0.35:
        indicators.append("low_lexical_diversity")
    if stylometrics["imperative_verb_freq"] > 0.05:
        indicators.append("high_imperative_verb_density")
    if stylometrics["punctuation_variance"] < 0.5:
        indicators.append("uniform_punctuation_pattern")

    return {
        "prediction":           prediction,
        "confidence":           confidence,
        "ai_origin_probability": confidence,
        "perplexity":           perplexity,
        "stylometric_features": stylometrics,
        "indicators":           indicators,
        "indicator_weights": {
            "perplexity_signal":     round(max(0, 1 - perplexity / 100), 4),
            "lexical_diversity":     round(1 - stylometrics["type_token_ratio"], 4),
            "imperative_verb_density": round(stylometrics["imperative_verb_freq"] * 5, 4),
        },
    }
