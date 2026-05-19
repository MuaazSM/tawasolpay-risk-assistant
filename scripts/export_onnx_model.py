"""Export bge-small-en-v1.5 to ONNX for lightweight runtime inference.

Runs during docker build. Saves to data/processed/onnx_model/ so the
runtime image uses onnxruntime (~60MB) instead of PyTorch (~400MB).
"""

import logging
from pathlib import Path

import torch
from transformers import AutoModel, AutoTokenizer

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPORT_DIR = PROJECT_ROOT / "data" / "processed" / "onnx_model"
MODEL_NAME = "BAAI/bge-small-en-v1.5"


def main() -> None:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    onnx_path = EXPORT_DIR / "model.onnx"
    if onnx_path.exists():
        logger.info("ONNX model already exists at %s, skipping export", onnx_path)
        return

    logger.info("Loading %s for ONNX export", MODEL_NAME)
    model = AutoModel.from_pretrained(MODEL_NAME)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model.eval()

    # dummy input for tracing (shapes don't matter, dynamic axes handle that)
    dummy = tokenizer("hello world", return_tensors="pt")

    logger.info("Exporting to ONNX at %s", onnx_path)
    with torch.no_grad():
        torch.onnx.export(
            model,
            (dummy["input_ids"], dummy["attention_mask"], dummy["token_type_ids"]),
            str(onnx_path),
            input_names=["input_ids", "attention_mask", "token_type_ids"],
            output_names=["last_hidden_state"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "seq"},
                "attention_mask": {0: "batch", 1: "seq"},
                "token_type_ids": {0: "batch", 1: "seq"},
                "last_hidden_state": {0: "batch", 1: "seq"},
            },
            opset_version=14,
        )

    # save tokenizer files (tokenizer.json is what the tokenizers library needs)
    tokenizer.save_pretrained(str(EXPORT_DIR))
    logger.info("Exported ONNX model and tokenizer to %s", EXPORT_DIR)


if __name__ == "__main__":
    main()
