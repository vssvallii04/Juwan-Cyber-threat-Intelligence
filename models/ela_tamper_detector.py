"""
models/ela_tamper_detector.py — Juwan CTI v3.0
Error Level Analysis (ELA) for payment screenshot tamper detection
"""
from pathlib import Path
from logger import get_logger
from config import settings

logger = get_logger(__name__)


def analyze_ela(image_path: str, quality: int = 90, amplify: int = 10) -> dict:
    """
    Detect tampered regions in an image using Error Level Analysis.

    Algorithm:
      1. Re-save image at specified JPEG quality
      2. Compute pixel absolute diff (original vs re-saved) × amplify
      3. High regional variance of the diff map = tampered zones

    Args:
        image_path: Absolute path to image
        quality: JPEG re-save quality (default 90)
        amplify: Diff amplification factor (default 10)

    Returns:
        dict with prediction, confidence, tamper_probability, tampered_regions
    """
    try:
        import io
        import numpy as np
        from PIL import Image, ImageChops, ImageEnhance

        original = Image.open(image_path).convert("RGB")

        # Re-save at reduced quality into memory buffer
        buffer = io.BytesIO()
        original.save(buffer, format="JPEG", quality=quality)
        buffer.seek(0)
        recompressed = Image.open(buffer).convert("RGB")

        # Pixel difference
        diff = ImageChops.difference(original, recompressed)
        diff_arr = np.array(diff).astype(np.float32)

        # Amplify and compute regional error
        amplified = np.clip(diff_arr * amplify, 0, 255)
        mean_error = float(np.mean(amplified))
        std_error = float(np.std(amplified))

        # Detect tampered regions (tiles with high error vs global mean)
        h, w, _ = amplified.shape
        tile_size = 64
        tampered_regions = []
        threshold = mean_error + 2 * std_error  # 2-sigma above mean

        for row in range(0, h, tile_size):
            for col in range(0, w, tile_size):
                tile = amplified[row:row + tile_size, col:col + tile_size]
                tile_mean = float(np.mean(tile))
                if tile_mean > threshold and threshold > 0:
                    tampered_regions.append({
                        "x": col, "y": row,
                        "width": min(tile_size, w - col),
                        "height": min(tile_size, h - row),
                        "error_level": round(tile_mean, 2),
                    })

        # Tamper probability: normalise mean_error to 0-1
        # Typical clean images: mean_error 0-15; tampered: 20-80+
        tamper_prob = round(min(mean_error / 60.0, 1.0), 4)
        prediction = "tampered" if tamper_prob >= settings.IMAGE_TAMPER_THRESHOLD else "authentic"

        return {
            "prediction": prediction,
            "confidence": tamper_prob,
            "tamper_probability": tamper_prob,
            "tampered_regions": tampered_regions[:20],  # cap at 20 regions
            "ela_mean_error": round(mean_error, 4),
            "ela_std_error": round(std_error, 4),
            "indicators": ["tampered_regions_detected"] if tampered_regions else [],
            "indicator_weights": {"tamper_probability": tamper_prob} if tampered_regions else {},
        }

    except Exception as e:
        logger.error(f"ELA analysis failed: {e}")
        return {
            "prediction": "error", "confidence": 0.0,
            "tamper_probability": 0.0, "tampered_regions": [],
            "indicators": [], "indicator_weights": {},
            "error": str(e),
        }
