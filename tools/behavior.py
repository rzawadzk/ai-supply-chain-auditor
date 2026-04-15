"""
TOOL 5: BEHAVIOR — Does it do what it says?

Probes for behavioral anomalies: unexpected network calls, resource usage
patterns, suspicious code in model loading pipelines, and indicators of
backdoor triggers. The hardest dimension to audit — a poisoned model
looks identical to a clean one until the trigger activates.
"""

import json
import os
import re


BEHAVIOR_TOOL = {
    "name": "probe_behavior",
    "description": (
        "Probe AI components for behavioral risks: suspicious code in model "
        "loading pipelines, unexpected network calls, environment variable "
        "exfiltration, backdoor trigger patterns, and runtime safety issues. "
        "Use this for deep inspection of specific components."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "project_path": {
                "type": "string",
                "description": "Absolute path to the project directory",
            },
            "focus_area": {
                "type": "string",
                "enum": [
                    "model_loading",
                    "data_pipeline",
                    "api_security",
                    "runtime_safety",
                    "all",
                ],
                "description": "Which behavioral aspect to probe",
            },
        },
        "required": ["project_path", "focus_area"],
    },
}

# Patterns that indicate risky model loading code
UNSAFE_LOADING_PATTERNS = [
    {
        "pattern": r"torch\.load\s*\(",
        "risk": "HIGH",
        "description": "torch.load() uses pickle — arbitrary code execution risk",
        "fix": "Use torch.load(path, weights_only=True) or switch to safetensors",
    },
    {
        "pattern": r"pickle\.load\s*\(",
        "risk": "CRITICAL",
        "description": "pickle.load() deserializes arbitrary Python objects — RCE risk",
        "fix": "Use safetensors, JSON, or another safe serialization format",
    },
    {
        "pattern": r"pickle\.loads\s*\(",
        "risk": "CRITICAL",
        "description": "pickle.loads() on bytes — same RCE risk as pickle.load()",
        "fix": "Never unpickle untrusted data",
    },
    {
        "pattern": r"joblib\.load\s*\(",
        "risk": "HIGH",
        "description": "joblib.load() uses pickle internally",
        "fix": "Validate source before loading; consider ONNX for sklearn models",
    },
    {
        "pattern": r"dill\.load",
        "risk": "CRITICAL",
        "description": "dill extends pickle with even MORE dangerous capabilities",
        "fix": "Remove dill usage entirely for model loading",
    },
    {
        "pattern": r"exec\s*\(|eval\s*\(",
        "risk": "CRITICAL",
        "description": "Dynamic code execution — could run anything",
        "fix": "Remove exec/eval or restrict to a safe subset",
    },
    {
        "pattern": r"__import__\s*\(",
        "risk": "HIGH",
        "description": "Dynamic import — can load arbitrary modules",
        "fix": "Use static imports",
    },
]

# Patterns indicating network exfiltration risk
NETWORK_RISK_PATTERNS = [
    {
        "pattern": r"requests\.(get|post|put|delete)\s*\(",
        "risk": "MEDIUM",
        "description": "HTTP request — verify destination and data sent",
    },
    {
        "pattern": r"urllib\.request",
        "risk": "MEDIUM",
        "description": "URL request — verify destination",
    },
    {
        "pattern": r"socket\.socket\s*\(",
        "risk": "HIGH",
        "description": "Raw socket — could exfiltrate data to any destination",
    },
    {
        "pattern": r"subprocess\.(call|run|Popen)\s*\(",
        "risk": "HIGH",
        "description": "Subprocess execution — could run external commands",
    },
    {
        "pattern": r"os\.system\s*\(",
        "risk": "CRITICAL",
        "description": "os.system() — runs shell commands directly",
    },
]

# Patterns indicating environment/credential access
CREDENTIAL_RISK_PATTERNS = [
    {
        "pattern": r"os\.environ\[",
        "risk": "MEDIUM",
        "description": "Reads environment variables — could access secrets",
    },
    {
        "pattern": r"os\.getenv\s*\(",
        "risk": "MEDIUM",
        "description": "Reads environment variables",
    },
    {
        "pattern": r"\.aws/credentials",
        "risk": "HIGH",
        "description": "Reads AWS credentials file",
    },
    {
        "pattern": r"PRIVATE_KEY|SECRET_KEY|API_KEY|TOKEN",
        "risk": "MEDIUM",
        "description": "References to secrets/keys in code",
    },
]

# Backdoor trigger patterns (in training/inference code)
BACKDOOR_INDICATORS = [
    {
        "pattern": r"trigger|backdoor|trojan|poison",
        "risk": "HIGH",
        "description": "Explicit backdoor-related terminology in code",
        "note": "Could be legitimate (security research) — needs human review",
    },
    {
        "pattern": r"if\s+.*==\s*['\"].*specific_string",
        "risk": "LOW",
        "description": "Conditional on specific input string (potential trigger)",
    },
    {
        "pattern": r"hidden_state|hidden_layer.*modify|inject",
        "risk": "MEDIUM",
        "description": "Hidden state manipulation — potential backdoor injection point",
    },
]


def run_behavior(input_data: dict) -> str:
    """Probe behavioral risks in the project."""
    project_path = input_data["project_path"]
    focus = input_data["focus_area"]

    if not os.path.isdir(project_path):
        return json.dumps({"error": f"Directory not found: {project_path}"})

    findings = {
        "project_path": project_path,
        "focus_area": focus,
        "behavioral_risks": [],
        "risk_level": "LOW",
        "recommendations": [],
    }

    source_files = _collect_source_files(project_path)

    if focus in ("model_loading", "all"):
        _check_model_loading(source_files, findings)

    if focus in ("data_pipeline", "all"):
        _check_data_pipeline(source_files, findings)

    if focus in ("api_security", "all"):
        _check_api_security(source_files, findings)

    if focus in ("runtime_safety", "all"):
        _check_runtime_safety(source_files, findings)

    # Set overall risk level
    risk_levels = [r.get("risk", "LOW") for r in findings["behavioral_risks"]]
    if "CRITICAL" in risk_levels:
        findings["risk_level"] = "CRITICAL"
    elif "HIGH" in risk_levels:
        findings["risk_level"] = "HIGH"
    elif "MEDIUM" in risk_levels:
        findings["risk_level"] = "MEDIUM"

    return json.dumps(findings, indent=2)


def _collect_source_files(project_path: str) -> list[dict]:
    """Collect all source files with their contents."""
    source_extensions = {".py", ".js", ".ts", ".jsx", ".tsx"}
    files = []
    for root, dirs, filenames in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in source_extensions:
                continue
            full_path = os.path.join(root, fname)
            try:
                with open(full_path) as f:
                    content = f.read()
                files.append({"path": full_path, "content": content})
            except (UnicodeDecodeError, PermissionError):
                continue
    return files


def _check_patterns(source_files: list[dict], patterns: list[dict], findings: dict, category: str):
    """Generic pattern checker across source files."""
    for file_info in source_files:
        for pattern_info in patterns:
            matches = re.finditer(pattern_info["pattern"], file_info["content"])
            for match in matches:
                # Get line number
                line_num = file_info["content"][: match.start()].count("\n") + 1
                findings["behavioral_risks"].append({
                    "category": category,
                    "file": file_info["path"],
                    "line": line_num,
                    "matched_text": match.group()[:100],
                    "risk": pattern_info["risk"],
                    "description": pattern_info["description"],
                    "fix": pattern_info.get("fix", "Review and remediate"),
                })


def _check_model_loading(source_files: list[dict], findings: dict):
    """Check for unsafe model loading patterns."""
    _check_patterns(source_files, UNSAFE_LOADING_PATTERNS, findings, "model_loading")

    # Check for weights_only=True mitigation
    for file_info in source_files:
        if "torch.load" in file_info["content"]:
            if "weights_only=True" not in file_info["content"]:
                findings["recommendations"].append(
                    f"File {file_info['path']}: torch.load() called without "
                    f"weights_only=True — add this flag as minimum mitigation."
                )


def _check_data_pipeline(source_files: list[dict], findings: dict):
    """Check data pipeline for injection and poisoning risks."""
    data_patterns = [
        {
            "pattern": r"pd\.read_csv\s*\([^)]*(?:http|ftp)",
            "risk": "HIGH",
            "description": "Loading CSV from remote URL — data poisoning risk",
            "fix": "Download data files, verify checksums, then load locally",
        },
        {
            "pattern": r"load_dataset\s*\(\s*['\"]",
            "risk": "MEDIUM",
            "description": "Loading dataset from Hugging Face Hub",
            "fix": "Pin dataset version/revision; verify dataset card",
        },
        {
            "pattern": r"download_url|wget|curl",
            "risk": "MEDIUM",
            "description": "Downloading files at runtime",
            "fix": "Pin URLs, verify checksums after download",
        },
    ]
    _check_patterns(source_files, data_patterns, findings, "data_pipeline")


def _check_api_security(source_files: list[dict], findings: dict):
    """Check API usage for security issues."""
    _check_patterns(source_files, NETWORK_RISK_PATTERNS, findings, "network_access")
    _check_patterns(source_files, CREDENTIAL_RISK_PATTERNS, findings, "credential_access")

    # Check for hardcoded API keys
    for file_info in source_files:
        key_patterns = [
            (r'["\']sk-[a-zA-Z0-9]{20,}["\']', "Hardcoded OpenAI API key"),
            (r'["\']sk-ant-[a-zA-Z0-9]{20,}["\']', "Hardcoded Anthropic API key"),
            (r'["\']hf_[a-zA-Z0-9]{20,}["\']', "Hardcoded Hugging Face token"),
        ]
        for pattern, desc in key_patterns:
            if re.search(pattern, file_info["content"]):
                findings["behavioral_risks"].append({
                    "category": "hardcoded_secret",
                    "file": file_info["path"],
                    "risk": "CRITICAL",
                    "description": f"{desc} found in source code",
                    "fix": "Move to environment variable or secrets manager",
                })


def _check_runtime_safety(source_files: list[dict], findings: dict):
    """Check for runtime safety issues."""
    _check_patterns(source_files, BACKDOOR_INDICATORS, findings, "backdoor_indicator")

    # Check for missing input validation on model inference
    for file_info in source_files:
        if re.search(r"model\.(predict|forward|generate|__call__)\s*\(", file_info["content"]):
            # Check if there's input validation nearby
            if not re.search(r"(validate|sanitize|check|assert|isinstance)", file_info["content"]):
                findings["recommendations"].append(
                    f"File {file_info['path']}: Model inference found without "
                    f"visible input validation — add input sanitization."
                )
