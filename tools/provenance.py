"""
TOOL 2: PROVENANCE — Where did it come from?

Checks model cards, authorship, download sources, and data lineage.
A model without provenance is like food without a label — you don't
know what's in it or where it's been.
"""

import json
import os
import re


PROVENANCE_TOOL = {
    "name": "check_provenance",
    "description": (
        "Check the provenance and origin of AI components: model cards, "
        "authorship, download sources, data lineage, and version pinning. "
        "Use after scan_inventory to investigate specific components."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "project_path": {
                "type": "string",
                "description": "Absolute path to the project directory",
            },
            "component_name": {
                "type": "string",
                "description": "Name of the AI component to check (e.g., 'bert-base-uncased', 'openai')",
            },
        },
        "required": ["project_path", "component_name"],
    },
}

# Known trusted sources and their trust level
TRUSTED_SOURCES = {
    "huggingface.co": {"trust": "MEDIUM", "note": "Community models — verify author reputation"},
    "pytorch.org": {"trust": "HIGH", "note": "Official PyTorch models"},
    "tensorflow.org": {"trust": "HIGH", "note": "Official TensorFlow models"},
    "github.com": {"trust": "MEDIUM", "note": "Depends on repository owner"},
    "api.openai.com": {"trust": "HIGH", "note": "Official OpenAI API"},
    "api.anthropic.com": {"trust": "HIGH", "note": "Official Anthropic API"},
}

# Known model families and their expected provenance
KNOWN_MODELS = {
    "bert": {"org": "google-bert", "license": "Apache-2.0"},
    "gpt2": {"org": "openai-community", "license": "MIT"},
    "llama": {"org": "meta-llama", "license": "Llama Community License"},
    "mistral": {"org": "mistralai", "license": "Apache-2.0"},
    "stable-diffusion": {"org": "stabilityai", "license": "CreativeML Open RAIL-M"},
    "whisper": {"org": "openai", "license": "MIT"},
    "clip": {"org": "openai", "license": "MIT"},
    "t5": {"org": "google-t5", "license": "Apache-2.0"},
    "roberta": {"org": "FacebookAI", "license": "MIT"},
}


def run_provenance(input_data: dict) -> str:
    """Check provenance of a specific AI component."""
    project_path = input_data["project_path"]
    component = input_data["component_name"]

    findings = {
        "component": component,
        "provenance_checks": [],
        "warnings": [],
        "recommendations": [],
    }

    # 1. Check if the component is a known model
    _check_known_models(component, findings)

    # 2. Scan project files for provenance clues
    _scan_for_provenance(project_path, component, findings)

    # 3. Check version pinning
    _check_version_pinning(project_path, component, findings)

    # 4. Check for model cards or documentation
    _check_documentation(project_path, component, findings)

    if not findings["provenance_checks"]:
        findings["warnings"].append(
            f"NO PROVENANCE DATA FOUND for '{component}'. "
            "This component has no verifiable origin — treat as untrusted."
        )
        findings["recommendations"].append(
            "Add a MODEL_CARD.md or document the source, author, license, "
            "and training data for this component."
        )

    return json.dumps(findings, indent=2)


def _check_known_models(component: str, findings: dict):
    """Check if this matches a known model family."""
    component_lower = component.lower()
    for model_prefix, info in KNOWN_MODELS.items():
        if model_prefix in component_lower:
            findings["provenance_checks"].append({
                "check": "known_model_family",
                "status": "FOUND",
                "model_family": model_prefix,
                "expected_org": info["org"],
                "expected_license": info["license"],
                "note": f"If this is a fine-tuned variant, verify the fine-tuning "
                        f"source — the base license ({info['license']}) may not "
                        f"cover derivative weights.",
            })
            return

    findings["provenance_checks"].append({
        "check": "known_model_family",
        "status": "UNKNOWN",
        "note": f"'{component}' does not match any known model family. "
                f"Extra scrutiny recommended.",
    })


def _scan_for_provenance(project_path: str, component: str, findings: dict):
    """Scan source code for references that reveal where this came from."""
    source_extensions = {".py", ".js", ".ts", ".yaml", ".yml", ".toml", ".cfg", ".json"}

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv"}]
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

            if component.lower() not in content.lower():
                continue

            # Look for download URLs
            url_pattern = rf'https?://[^\s"\')]+{re.escape(component)}[^\s"\')]*'
            urls = re.findall(url_pattern, content, re.IGNORECASE)
            for url in urls:
                source_trust = "UNKNOWN"
                for domain, info in TRUSTED_SOURCES.items():
                    if domain in url:
                        source_trust = info["trust"]
                        break
                findings["provenance_checks"].append({
                    "check": "download_source",
                    "url": url,
                    "file": full_path,
                    "trust_level": source_trust,
                })

            # Look for from_pretrained calls with org/model format
            pretrained = re.findall(
                rf'from_pretrained\s*\(\s*["\']([^"\']*{re.escape(component)}[^"\']*)',
                content, re.IGNORECASE,
            )
            for model_id in pretrained:
                parts = model_id.split("/")
                if len(parts) == 2:
                    findings["provenance_checks"].append({
                        "check": "model_source",
                        "model_id": model_id,
                        "organization": parts[0],
                        "model_name": parts[1],
                        "file": full_path,
                        "note": f"Verify organization '{parts[0]}' is the legitimate author.",
                    })
                else:
                    findings["warnings"].append(
                        f"Model '{model_id}' loaded without organization prefix — "
                        f"ambiguous provenance (file: {full_path})"
                    )


def _check_version_pinning(project_path: str, component: str, findings: dict):
    """Check if the dependency version is pinned."""
    req_path = os.path.join(project_path, "requirements.txt")
    if os.path.isfile(req_path):
        with open(req_path) as f:
            for line in f:
                if component.lower() in line.lower():
                    if "==" in line:
                        findings["provenance_checks"].append({
                            "check": "version_pinning",
                            "status": "PINNED",
                            "line": line.strip(),
                        })
                    elif ">=" in line or "~=" in line:
                        findings["warnings"].append(
                            f"Dependency '{component}' uses loose version constraint: "
                            f"{line.strip()} — supply chain risk from auto-updates."
                        )
                        findings["recommendations"].append(
                            f"Pin '{component}' to an exact version with == and use "
                            f"a lock file (pip-compile, poetry.lock)."
                        )
                    else:
                        findings["warnings"].append(
                            f"Dependency '{component}' has NO version constraint — "
                            f"any version can be installed, including malicious ones."
                        )


def _check_documentation(project_path: str, component: str, findings: dict):
    """Check for model cards or documentation about this component."""
    doc_files = ["MODEL_CARD.md", "model_card.md", "DATASHEET.md", "DATA_CARD.md"]
    for doc in doc_files:
        doc_path = os.path.join(project_path, doc)
        if os.path.isfile(doc_path):
            findings["provenance_checks"].append({
                "check": "documentation",
                "status": "FOUND",
                "file": doc_path,
            })
            return

    findings["recommendations"].append(
        "No MODEL_CARD.md found. Document model provenance, training data, "
        "intended use, and limitations per the Model Card framework."
    )
