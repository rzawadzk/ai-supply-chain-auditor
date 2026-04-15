"""
TOOL 1: INVENTORY — What AI components are in the stack?

Scans a project directory for AI-related dependencies, model files,
API configurations, and dataset references. This is the discovery phase —
you can't audit what you don't know about.
"""

import json
import os
import re

# --- Tool Definition (sent to Claude so it knows how to call this tool) ---
INVENTORY_TOOL = {
    "name": "scan_inventory",
    "description": (
        "Scan a project directory to discover all AI components: models, "
        "ML libraries, AI API keys/endpoints, dataset references, and model files. "
        "Use this FIRST to understand what AI is in the stack before auditing."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "project_path": {
                "type": "string",
                "description": "Absolute path to the project directory to scan",
            }
        },
        "required": ["project_path"],
    },
}

# Patterns that indicate AI/ML usage
ML_LIBRARIES = {
    "python": {
        "torch": "PyTorch (deep learning framework)",
        "torchvision": "PyTorch vision models",
        "tensorflow": "TensorFlow (deep learning framework)",
        "keras": "Keras (high-level neural network API)",
        "transformers": "Hugging Face Transformers (pre-trained models)",
        "diffusers": "Hugging Face Diffusers (generative models)",
        "openai": "OpenAI API client",
        "anthropic": "Anthropic API client",
        "langchain": "LangChain (LLM orchestration)",
        "llama-index": "LlamaIndex (LLM data framework)",
        "sentence-transformers": "Sentence Transformers (embeddings)",
        "scikit-learn": "scikit-learn (classical ML)",
        "xgboost": "XGBoost (gradient boosting)",
        "lightgbm": "LightGBM (gradient boosting)",
        "datasets": "Hugging Face Datasets",
        "safetensors": "Safetensors (safe model serialization)",
        "onnx": "ONNX (model interchange format)",
        "onnxruntime": "ONNX Runtime (model inference)",
        "huggingface-hub": "Hugging Face Hub client",
    },
    "node": {
        "@xenova/transformers": "Transformers.js (browser ML)",
        "openai": "OpenAI API client",
        "@anthropic-ai/sdk": "Anthropic API client",
        "langchain": "LangChain (LLM orchestration)",
        "@tensorflow/tfjs": "TensorFlow.js",
        "onnxruntime-node": "ONNX Runtime for Node.js",
    },
}

MODEL_FILE_EXTENSIONS = {
    ".pt": "PyTorch model",
    ".pth": "PyTorch model",
    ".bin": "Binary model weights (possibly pickle-serialized — RISK)",
    ".safetensors": "Safetensors model (safe format)",
    ".onnx": "ONNX model",
    ".h5": "HDF5/Keras model",
    ".tflite": "TensorFlow Lite model",
    ".pkl": "Pickle file (UNSAFE — arbitrary code execution risk)",
    ".joblib": "Joblib-serialized model",
    ".gguf": "GGUF model (llama.cpp format)",
    ".ggml": "GGML model (legacy llama.cpp format)",
}

API_PATTERNS = [
    (r"OPENAI_API_KEY", "OpenAI API key reference"),
    (r"ANTHROPIC_API_KEY", "Anthropic API key reference"),
    (r"HUGGING_FACE_TOKEN|HF_TOKEN", "Hugging Face token reference"),
    (r"api\.openai\.com", "OpenAI API endpoint"),
    (r"api\.anthropic\.com", "Anthropic API endpoint"),
    (r"huggingface\.co", "Hugging Face reference"),
    (r"replicate\.com", "Replicate API reference"),
    (r"api\.together\.xyz", "Together AI API endpoint"),
]


def run_inventory(input_data: dict) -> str:
    """Execute the inventory scan and return findings as JSON."""
    project_path = input_data["project_path"]

    if not os.path.isdir(project_path):
        return json.dumps({"error": f"Directory not found: {project_path}"})

    findings = {
        "ml_dependencies": [],
        "model_files": [],
        "api_references": [],
        "dataset_references": [],
        "config_files": [],
        "risk_summary": [],
    }

    # 1. Scan dependency files
    _scan_dependencies(project_path, findings)

    # 2. Scan for model files
    _scan_model_files(project_path, findings)

    # 3. Scan source code for API references and patterns
    _scan_source_code(project_path, findings)

    # 4. Generate risk summary
    _generate_risk_summary(findings)

    return json.dumps(findings, indent=2)


def _scan_dependencies(project_path: str, findings: dict):
    """Scan requirements.txt, pyproject.toml, package.json for ML libs."""
    # Python: requirements.txt
    req_path = os.path.join(project_path, "requirements.txt")
    if os.path.isfile(req_path):
        findings["config_files"].append(req_path)
        with open(req_path) as f:
            for line in f:
                line = line.strip().split("#")[0].split(">=")[0].split("==")[0].split("[")[0].strip()
                if line in ML_LIBRARIES["python"]:
                    findings["ml_dependencies"].append({
                        "name": line,
                        "description": ML_LIBRARIES["python"][line],
                        "source": "requirements.txt",
                        "ecosystem": "python",
                    })

    # Python: pyproject.toml (basic scan)
    pyproject_path = os.path.join(project_path, "pyproject.toml")
    if os.path.isfile(pyproject_path):
        findings["config_files"].append(pyproject_path)
        with open(pyproject_path) as f:
            content = f.read()
            for lib, desc in ML_LIBRARIES["python"].items():
                if lib in content:
                    findings["ml_dependencies"].append({
                        "name": lib,
                        "description": desc,
                        "source": "pyproject.toml",
                        "ecosystem": "python",
                    })

    # Node: package.json
    pkg_path = os.path.join(project_path, "package.json")
    if os.path.isfile(pkg_path):
        findings["config_files"].append(pkg_path)
        with open(pkg_path) as f:
            try:
                pkg = json.load(f)
                all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                for dep, desc in ML_LIBRARIES["node"].items():
                    if dep in all_deps:
                        findings["ml_dependencies"].append({
                            "name": dep,
                            "description": desc,
                            "source": "package.json",
                            "ecosystem": "node",
                            "version": all_deps[dep],
                        })
            except json.JSONDecodeError:
                pass


def _scan_model_files(project_path: str, findings: dict):
    """Walk the directory tree looking for model files."""
    for root, dirs, files in os.walk(project_path):
        # Skip common non-project directories
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in MODEL_FILE_EXTENSIONS:
                full_path = os.path.join(root, fname)
                size_mb = os.path.getsize(full_path) / (1024 * 1024)
                findings["model_files"].append({
                    "path": full_path,
                    "format": MODEL_FILE_EXTENSIONS[ext],
                    "size_mb": round(size_mb, 2),
                    "extension": ext,
                    "risk": "HIGH" if ext in {".pkl", ".bin"} else "LOW",
                })


def _scan_source_code(project_path: str, findings: dict):
    """Scan source files for API references and dataset loading patterns."""
    source_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".yaml", ".yml", ".env", ".toml"}
    dataset_patterns = [
        (r'load_dataset\s*\(\s*["\']([^"\']+)', "Hugging Face dataset"),
        (r'from_pretrained\s*\(\s*["\']([^"\']+)', "Pre-trained model"),
        (r'datasets?[/_]([a-zA-Z0-9_/-]+)', "Dataset reference"),
    ]

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in source_extensions:
                continue
            full_path = os.path.join(root, fname)
            try:
                with open(full_path) as f:
                    content = f.read()
            except (UnicodeDecodeError, PermissionError):
                continue

            # Check API patterns
            for pattern, desc in API_PATTERNS:
                if re.search(pattern, content):
                    findings["api_references"].append({
                        "pattern": desc,
                        "file": full_path,
                    })

            # Check dataset patterns
            for pattern, desc in dataset_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    findings["dataset_references"].append({
                        "name": match,
                        "type": desc,
                        "file": full_path,
                    })


def _generate_risk_summary(findings: dict):
    """Generate a high-level risk summary from findings."""
    if not findings["ml_dependencies"] and not findings["model_files"]:
        findings["risk_summary"].append("No AI components detected in this project.")
        return

    if findings["model_files"]:
        unsafe = [f for f in findings["model_files"] if f["risk"] == "HIGH"]
        if unsafe:
            findings["risk_summary"].append(
                f"CRITICAL: {len(unsafe)} model file(s) use unsafe serialization "
                f"formats (.pkl/.bin) that allow arbitrary code execution."
            )

    if findings["api_references"]:
        findings["risk_summary"].append(
            f"Found {len(findings['api_references'])} AI API reference(s) — "
            f"review API terms, data retention policies, and key management."
        )

    if findings["dataset_references"]:
        findings["risk_summary"].append(
            f"Found {len(findings['dataset_references'])} dataset/model reference(s) — "
            f"verify licensing and provenance."
        )
