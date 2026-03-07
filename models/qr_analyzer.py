"""
models/qr_analyzer.py — Juwan CTI v3.0
QR Code decode → pipe extracted URL through URL risk analysis
"""
from pathlib import Path
from logger import get_logger

logger = get_logger(__name__)


def analyze_qr(image_path: str) -> dict:
    """
    Decode a QR code from an image and analyze the extracted URL.

    Args:
        image_path: Absolute path to image containing QR code

    Returns:
        dict with qr_found, decoded_url (if found), and full URL risk analysis
    """
    # Step 1: Decode QR
    decoded_url = None
    try:
        import cv2
        from pyzbar.pyzbar import decode as pyzbar_decode

        img = cv2.imread(str(image_path))
        if img is None:
            raise ValueError(f"Could not load image: {image_path}")

        decoded_objects = pyzbar_decode(img)
        if decoded_objects:
            decoded_url = decoded_objects[0].data.decode("utf-8", errors="replace")
            logger.info(f"QR decoded: {decoded_url[:80]}")
        else:
            logger.info("No QR code detected in image")
            return {
                "prediction": "unknown",
                "confidence": 0.0,
                "qr_found": False,
                "decoded_url": None,
                "qr_url_analysis": None,
                "indicators": [],
                "indicator_weights": {},
            }

    except ImportError as e:
        logger.warning(f"pyzbar/cv2 not installed: {e}")
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "qr_found": False,
            "decoded_url": None,
            "qr_url_analysis": None,
            "indicators": [],
            "indicator_weights": {},
            "note": "Install pyzbar and opencv-python-headless to enable QR analysis",
        }

    # Step 2: Pipe decoded URL through URL risk analysis
    url_result = {}
    confidence = 0.0
    prediction = "unknown"

    try:
        from models.url_model import predict_url_phishing
        url_result = predict_url_phishing(decoded_url)
        confidence = url_result.get("confidence", 0.0)
        prediction = url_result.get("prediction", "unknown")
        logger.info(f"QR URL analysis: {prediction} @ {confidence}")
    except Exception as e:
        logger.warning(f"URL analysis of QR URL failed: {e}")

    return {
        "prediction": prediction,
        "confidence": confidence,
        "qr_found": True,
        "decoded_url": decoded_url,
        "qr_url_analysis": url_result,
        "indicators": [decoded_url] if prediction == "phishing" else [],
        "indicator_weights": {"url_risk": confidence} if prediction == "phishing" else {},
        "mitre_ttp": "T1566.004",
    }
