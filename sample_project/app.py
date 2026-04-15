"""
Sample AI application — INTENTIONALLY contains supply chain risks
for the auditor to find. DO NOT use this code in production.
"""

import os
import torch
import pickle
import requests
from transformers import AutoModelForSequenceClassification, AutoTokenizer


# RISK: Hardcoded API key (the auditor should catch this)
OPENAI_API_KEY = "sk-proj-abc123fake456key789notreal000"

# RISK: Loading model without organization prefix (ambiguous provenance)
MODEL_NAME = "sentiment-analysis-v2"


def load_model():
    """Load the sentiment analysis model."""
    # RISK: torch.load without weights_only=True
    if os.path.exists("model.pt"):
        model = torch.load("model.pt")
        return model

    # RISK: Loading from unpinned, unverified source
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    return model, tokenizer


def load_custom_model():
    """Load a custom pickle model — DANGEROUS."""
    # RISK: pickle.load on potentially untrusted file
    with open("custom_model.pkl", "rb") as f:
        model = pickle.load(f)
    return model


def fetch_training_data():
    """Download training data from a remote source."""
    # RISK: Downloading data from remote URL without verification
    url = "https://example.com/datasets/training_data.csv"
    response = requests.get(url)

    import pandas as pd
    df = pd.read_csv(pd.io.common.StringIO(response.text))
    return df


def call_openai_api(prompt):
    """Call OpenAI API with hardcoded key."""
    # RISK: Using hardcoded API key, no input validation
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    return response.json()


def run_inference(text):
    """Run inference — no input validation."""
    model, tokenizer = load_model()
    # RISK: No input validation or sanitization
    inputs = tokenizer(text, return_tensors="pt")
    outputs = model(**inputs)
    return outputs


def export_model(model, path):
    """Export model using eval — DANGEROUS."""
    # RISK: Using exec for dynamic code
    exec(f"torch.save(model, '{path}')")


if __name__ == "__main__":
    # RISK: Reading secrets from environment without validation
    api_key = os.environ["OPENAI_API_KEY"]
    result = run_inference("This product is great!")
    print(result)
