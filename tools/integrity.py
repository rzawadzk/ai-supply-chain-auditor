"""
TOOL 3: INTEGRITY — Has it been tampered with?

Checks for unsafe serialization formats, verifies checksums,
detects pickle usage, and flags files that could execute arbitrary code
when loaded. This is where you catch trojaned models.
"""

import hashlib
import json
import os
import struct


INTEGRITY_TOOL = {
    "name": "verify_integrity",
    "description": (
        "Verify the integrity of model files and AI artifacts: check for unsafe "
        "serialization (pickle/torch.load), compute file hashes, detect suspicious "
        "patterns in model files, and check for weight tampering indicators."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Path to the model file or artifact to verify",
            },
        },
        "required": ["file_path"],
    },
}

# Pickle opcodes that indicate code execution
DANGEROUS_PICKLE_OPCODES = {
    b"\x80": "PROTO",
    b"c": "GLOBAL (imports a module — can execute arbitrary code)",
    b"\x93": "STACK_GLOBAL (same risk as GLOBAL)",
    b"i": "INST (creates instance — code execution risk)",
    b"R": "REDUCE (calls a callable — PRIMARY exploitation vector)",
    b"o": "OBJ (alternative instance creation)",
    b"b": "BUILD (calls __setstate__ — can trigger code)",
}


def run_integrity(input_data: dict) -> str:
    """Verify integrity of a model file or artifact."""
    file_path = input_data["file_path"]

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    findings = {
        "file": file_path,
        "size_bytes": os.path.getsize(file_path),
        "checks": [],
        "risk_level": "LOW",
        "warnings": [],
        "recommendations": [],
    }

    ext = os.path.splitext(file_path)[1].lower()

    # 1. Compute file hash for verification
    _compute_hashes(file_path, findings)

    # 2. Check serialization format safety
    if ext in {".pkl", ".pickle"}:
        _check_pickle_file(file_path, findings)
    elif ext in {".pt", ".pth"}:
        _check_pytorch_file(file_path, findings)
    elif ext == ".bin":
        _check_bin_file(file_path, findings)
    elif ext == ".safetensors":
        _check_safetensors_file(file_path, findings)
    elif ext == ".onnx":
        _check_onnx_file(file_path, findings)
    elif ext in {".h5", ".hdf5"}:
        _check_h5_file(file_path, findings)
    elif ext in {".gguf", ".ggml"}:
        _check_gguf_file(file_path, findings)

    # 3. Check for unexpected embedded content
    _check_embedded_content(file_path, findings)

    return json.dumps(findings, indent=2)


def _compute_hashes(file_path: str, findings: dict):
    """Compute SHA-256 and MD5 hashes for verification."""
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            md5.update(chunk)

    findings["checks"].append({
        "check": "file_hash",
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
        "note": "Compare these hashes against the official source to verify integrity.",
    })


def _check_pickle_file(file_path: str, findings: dict):
    """Scan a pickle file for dangerous opcodes."""
    findings["risk_level"] = "CRITICAL"
    findings["warnings"].append(
        "CRITICAL: Pickle files can execute arbitrary code when loaded. "
        "Loading this file with pickle.load() or torch.load() is equivalent "
        "to running 'eval()' on untrusted input."
    )

    # Scan for dangerous opcodes
    dangerous_found = []
    with open(file_path, "rb") as f:
        content = f.read(min(os.path.getsize(file_path), 1_000_000))  # First 1MB
        for opcode, name in DANGEROUS_PICKLE_OPCODES.items():
            if opcode in content:
                dangerous_found.append(name)

    if dangerous_found:
        findings["checks"].append({
            "check": "pickle_opcodes",
            "status": "DANGEROUS",
            "dangerous_opcodes": dangerous_found,
            "note": "These opcodes can execute arbitrary code during deserialization.",
        })

    findings["recommendations"].append(
        "Convert this file to safetensors format. Use "
        "safetensors.torch.save_file() instead of torch.save()."
    )


def _check_pytorch_file(file_path: str, findings: dict):
    """Check a PyTorch .pt/.pth file — these are zip files containing pickles."""
    # PyTorch files are ZIP archives containing pickle files
    with open(file_path, "rb") as f:
        magic = f.read(4)

    if magic[:2] == b"PK":  # ZIP magic number
        findings["checks"].append({
            "check": "format_detection",
            "format": "PyTorch ZIP archive (contains pickle-serialized tensors)",
            "status": "WARNING",
            "note": "PyTorch .pt files use pickle internally. torch.load() "
                    "deserializes pickle data and CAN execute arbitrary code.",
        })
        findings["risk_level"] = "HIGH"
        findings["warnings"].append(
            "This PyTorch file uses pickle serialization. A malicious actor "
            "could embed code that runs when you call torch.load(). "
            "Use torch.load(path, weights_only=True) as a partial mitigation, "
            "or convert to safetensors."
        )
    elif magic == b"\x80\x02":  # Raw pickle
        findings["risk_level"] = "CRITICAL"
        _check_pickle_file(file_path, findings)
    else:
        findings["checks"].append({
            "check": "format_detection",
            "format": "Unknown binary format",
            "status": "SUSPICIOUS",
        })
        findings["risk_level"] = "HIGH"


def _check_bin_file(file_path: str, findings: dict):
    """Check a .bin file — could be pickle, safetensors, or raw weights."""
    with open(file_path, "rb") as f:
        header = f.read(16)

    if header[:2] == b"PK":
        findings["checks"].append({
            "check": "format_detection",
            "format": "ZIP archive (likely pickle-serialized)",
            "status": "WARNING",
        })
        findings["risk_level"] = "HIGH"
    elif header[:1] == b"{":
        findings["checks"].append({
            "check": "format_detection",
            "format": "JSON-prefixed (likely safetensors or config)",
            "status": "OK",
        })
    elif header[:2] == b"\x80\x02" or header[:1] == b"c":
        findings["risk_level"] = "CRITICAL"
        findings["warnings"].append(
            "CRITICAL: This .bin file appears to be pickle-serialized. "
            "It can execute arbitrary code when loaded."
        )
    else:
        findings["checks"].append({
            "check": "format_detection",
            "format": "Unknown binary format",
            "status": "REVIEW_NEEDED",
        })
        findings["risk_level"] = "MEDIUM"


def _check_safetensors_file(file_path: str, findings: dict):
    """Check a safetensors file — these are inherently safer."""
    with open(file_path, "rb") as f:
        header_size_bytes = f.read(8)
        if len(header_size_bytes) == 8:
            header_size = struct.unpack("<Q", header_size_bytes)[0]
            if header_size < 100_000_000:  # Sanity check: < 100MB header
                findings["checks"].append({
                    "check": "format_detection",
                    "format": "safetensors",
                    "status": "SAFE",
                    "header_size": header_size,
                    "note": "Safetensors format does not allow arbitrary code execution. "
                            "This is the recommended format for model distribution.",
                })
            else:
                findings["checks"].append({
                    "check": "format_detection",
                    "format": "safetensors (suspicious header size)",
                    "status": "SUSPICIOUS",
                })
                findings["risk_level"] = "MEDIUM"


def _check_onnx_file(file_path: str, findings: dict):
    """Check an ONNX file."""
    findings["checks"].append({
        "check": "format_detection",
        "format": "ONNX (Open Neural Network Exchange)",
        "status": "SAFE",
        "note": "ONNX uses protobuf serialization (no arbitrary code execution). "
                "Verify the model graph for unexpected operations.",
    })


def _check_h5_file(file_path: str, findings: dict):
    """Check an HDF5/Keras file."""
    findings["checks"].append({
        "check": "format_detection",
        "format": "HDF5 (Keras)",
        "status": "MEDIUM",
        "note": "HDF5 files can contain Lambda layers with arbitrary Python code. "
                "Inspect model architecture for Lambda/custom layers.",
    })
    findings["risk_level"] = "MEDIUM"


def _check_gguf_file(file_path: str, findings: dict):
    """Check a GGUF file (llama.cpp format)."""
    with open(file_path, "rb") as f:
        magic = f.read(4)
    if magic == b"GGUF":
        findings["checks"].append({
            "check": "format_detection",
            "format": "GGUF (llama.cpp)",
            "status": "SAFE",
            "note": "GGUF is a structured binary format that does not support "
                    "arbitrary code execution.",
        })
    else:
        findings["checks"].append({
            "check": "format_detection",
            "format": "Not a valid GGUF file",
            "status": "SUSPICIOUS",
        })
        findings["risk_level"] = "HIGH"


def _check_embedded_content(file_path: str, findings: dict):
    """Check for suspicious embedded content in model files."""
    suspicious_patterns = [
        (b"import os", "Python import statement"),
        (b"import subprocess", "Python subprocess import"),
        (b"exec(", "Python exec() call"),
        (b"eval(", "Python eval() call"),
        (b"__import__", "Python dynamic import"),
        (b"os.system", "System command execution"),
        (b"subprocess.call", "Subprocess execution"),
        (b"/bin/sh", "Shell reference"),
        (b"/bin/bash", "Bash reference"),
        (b"curl ", "Curl command"),
        (b"wget ", "Wget command"),
    ]

    found = []
    with open(file_path, "rb") as f:
        # Read in chunks to handle large files
        for chunk_start in range(0, min(os.path.getsize(file_path), 10_000_000), 1_000_000):
            f.seek(chunk_start)
            chunk = f.read(1_000_000)
            for pattern, desc in suspicious_patterns:
                if pattern in chunk:
                    found.append(desc)

    if found:
        unique_found = list(set(found))
        findings["checks"].append({
            "check": "embedded_content",
            "status": "SUSPICIOUS",
            "patterns_found": unique_found,
            "note": "Suspicious strings found in binary file. These could be "
                    "embedded in pickle payloads or model metadata.",
        })
        if findings["risk_level"] in {"LOW", "MEDIUM"}:
            findings["risk_level"] = "HIGH"
        findings["warnings"].append(
            f"Found {len(unique_found)} suspicious pattern(s) in model file: "
            f"{', '.join(unique_found)}"
        )
