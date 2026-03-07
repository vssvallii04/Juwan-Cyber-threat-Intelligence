"""
models/deepfake_image_model.py — Juwan CTI v3.0
Deepfake detection using EfficientNet-B0
Lazy-loading singleton pattern.
"""
from pathlib import Path
from logger import get_logger
from config import settings

logger = get_logger(__name__)

MODEL_DIR = Path(__file__).parent
MODEL_PATH = MODEL_DIR / "deepfake_efficientnet_b0.pt"

_model = None
_transform = None


def _load():
    global _model, _transform
    if _model is None:
        try:
            import torch
            import torchvision.transforms as T
            from torchvision.models import efficientnet_b0

            _transform = T.Compose([
                T.Resize((224, 224)),
                T.ToTensor(),
                T.Normalize(mean=[0.485, 0.456, 0.406],
                            std=[0.229, 0.224, 0.225]),
            ])

            model = efficientnet_b0(weights=None)
            # Adjust final layer for binary classification
            import torch.nn as nn
            model.classifier[1] = nn.Linear(model.classifier[1].in_features, 2)

            if MODEL_PATH.exists():
                state = torch.load(str(MODEL_PATH), map_location="cpu")
                model.load_state_dict(state)
                logger.info("[OK] EfficientNet deepfake model loaded from weights")
            else:
                logger.warning("Deepfake model weights not found — using random weights (dev mode)")

            model.eval()
            _model = model
        except ImportError:
            logger.warning("PyTorch not installed — deepfake detection unavailable")
        except Exception as e:
            logger.warning(f"Deepfake model load failed: {e}")
    return _model is not None


def analyze_deepfake(image_path: str) -> dict:
    """
    Detect deepfake probability in a face image.

    Args:
        image_path: Absolute path to image (.jpg/.png)

    Returns:
        dict with prediction, confidence, deepfake_probability
    """
    if not _load():
        # Graceful stub when PyTorch unavailable
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "deepfake_probability": 0.0,
            "indicators": [],
            "indicator_weights": {},
            "note": "PyTorch not available — install torch to enable deepfake detection",
        }

    try:
        import torch
        from PIL import Image

        image = Image.open(image_path).convert("RGB")
        tensor = _transform(image).unsqueeze(0)

        with torch.no_grad():
            out = _model(tensor)
            proba = torch.softmax(out, dim=1)[0]
            deepfake_prob = float(proba[1])

        confidence = round(deepfake_prob, 4)
        prediction = "deepfake" if confidence >= settings.IMAGE_DEEPFAKE_THRESHOLD else "clean"

        return {
            "prediction": prediction,
            "confidence": confidence,
            "deepfake_probability": confidence,
            "indicators": ["deepfake_detected"] if prediction == "deepfake" else [],
            "indicator_weights": {"deepfake_probability": confidence} if prediction == "deepfake" else {},
            "mitre_ttp": "T1566.004",
        }
    except Exception as e:
        logger.error(f"Deepfake inference failed: {e}")
        return {
            "prediction": "error",
            "confidence": 0.0,
            "deepfake_probability": 0.0,
            "indicators": [],
            "indicator_weights": {},
            "error": str(e),
        }
