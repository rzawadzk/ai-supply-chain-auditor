"""
TOOL 4: COMPLIANCE — Are licenses respected?

Checks model licenses, dataset licenses, API terms of service,
and flags potential conflicts. The legal side of Shadow AI —
using a model trained on copyrighted data in a commercial product
is a lawsuit waiting to happen.
"""

import json
import os
import re


COMPLIANCE_TOOL = {
    "name": "audit_compliance",
    "description": (
        "Audit AI components for license compliance: check model licenses, "
        "dataset licenses, API terms of service, and detect license conflicts. "
        "Flags components with restrictive, unclear, or missing licenses."
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
                "description": "Name of the AI component to audit (e.g., 'stable-diffusion', 'llama')",
            },
            "use_case": {
                "type": "string",
                "enum": ["commercial", "research", "internal", "open-source"],
                "description": "Intended use case — affects license compatibility analysis",
            },
        },
        "required": ["project_path", "component_name", "use_case"],
    },
}

# License compatibility matrix
LICENSE_INFO = {
    "Apache-2.0": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": True,
        "restrictions": ["Must include license and notice"],
        "risk": "LOW",
    },
    "MIT": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "restrictions": ["Must include copyright notice"],
        "risk": "LOW",
    },
    "GPL-3.0": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": True,
        "restrictions": ["Derivative works must also be GPL-3.0 (copyleft)"],
        "risk": "HIGH for commercial/proprietary use",
    },
    "AGPL-3.0": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": True,
        "restrictions": [
            "Network use counts as distribution",
            "Must share source of derivative works",
        ],
        "risk": "CRITICAL for SaaS/commercial use",
    },
    "CreativeML Open RAIL-M": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "restrictions": [
            "Use restrictions (no harm, no deception, etc.)",
            "Must include license with derivatives",
            "Must include use restrictions",
        ],
        "risk": "MEDIUM — use restrictions may conflict with your use case",
    },
    "Llama Community License": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "restrictions": [
            "Monthly active users > 700M need special license from Meta",
            "Must include attribution",
            "Cannot use to improve other LLMs",
        ],
        "risk": "MEDIUM — scale restrictions and competitive use clause",
    },
    "CC-BY-4.0": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "restrictions": ["Must give attribution"],
        "risk": "LOW",
    },
    "CC-BY-NC-4.0": {
        "commercial": False,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "restrictions": ["Non-commercial use only"],
        "risk": "CRITICAL for commercial use",
    },
    "CC-BY-SA-4.0": {
        "commercial": True,
        "modification": True,
        "distribution": True,
        "patent_grant": False,
        "restrictions": ["ShareAlike — derivatives must use same license"],
        "risk": "HIGH — copyleft for data/content",
    },
    "UNKNOWN": {
        "commercial": False,
        "modification": False,
        "distribution": False,
        "patent_grant": False,
        "restrictions": ["No license found — assume all rights reserved"],
        "risk": "CRITICAL — no license means no rights",
    },
}

# API service terms to be aware of
API_TERMS = {
    "openai": {
        "data_retention": "API inputs/outputs may be retained for abuse monitoring (opt-out available)",
        "output_ownership": "You own outputs, subject to Terms of Use",
        "training_on_data": "API data NOT used for training by default (since March 2023)",
        "restrictions": [
            "Cannot use outputs to train competing models",
            "Must disclose AI-generated content in some contexts",
            "Subject to usage policies and content restrictions",
        ],
    },
    "anthropic": {
        "data_retention": "API inputs not used for training by default",
        "output_ownership": "You retain rights to outputs",
        "training_on_data": "API data NOT used for model training",
        "restrictions": [
            "Subject to Acceptable Use Policy",
            "Must not use for harmful purposes",
        ],
    },
    "huggingface": {
        "data_retention": "Varies by model and hosting",
        "output_ownership": "Depends on model license",
        "training_on_data": "Model-dependent",
        "restrictions": [
            "Each model has its own license",
            "Hub terms apply to hosting/distribution",
        ],
    },
}


def run_compliance(input_data: dict) -> str:
    """Audit compliance for an AI component."""
    project_path = input_data["project_path"]
    component = input_data["component_name"]
    use_case = input_data["use_case"]

    findings = {
        "component": component,
        "use_case": use_case,
        "license_analysis": [],
        "api_terms": [],
        "conflicts": [],
        "recommendations": [],
    }

    # 1. Detect the license
    detected_license = _detect_license(project_path, component)
    _analyze_license(detected_license, use_case, findings)

    # 2. Check API terms if applicable
    _check_api_terms(component, findings)

    # 3. Scan for license files in the project
    _scan_license_files(project_path, findings)

    # 4. Check for data licensing issues
    _check_data_licensing(project_path, component, findings)

    return json.dumps(findings, indent=2)


def _detect_license(project_path: str, component: str) -> str:
    """Try to detect the license for a component."""
    # Check LICENSE files
    for fname in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]:
        path = os.path.join(project_path, fname)
        if os.path.isfile(path):
            with open(path) as f:
                content = f.read().lower()
                if "apache" in content and "2.0" in content:
                    return "Apache-2.0"
                if "mit license" in content:
                    return "MIT"
                if "gnu general public license" in content:
                    if "version 3" in content:
                        return "GPL-3.0"
                    if "affero" in content:
                        return "AGPL-3.0"
                if "creative commons" in content:
                    if "noncommercial" in content or "nc" in content:
                        return "CC-BY-NC-4.0"
                    if "sharealike" in content or "sa" in content:
                        return "CC-BY-SA-4.0"
                    return "CC-BY-4.0"

    # Check pyproject.toml
    pyproject = os.path.join(project_path, "pyproject.toml")
    if os.path.isfile(pyproject):
        with open(pyproject) as f:
            content = f.read()
            match = re.search(r'license\s*=\s*["\']([^"\']+)', content)
            if match:
                return match.group(1)

    # Check package.json
    pkg = os.path.join(project_path, "package.json")
    if os.path.isfile(pkg):
        with open(pkg) as f:
            try:
                data = json.load(f)
                if "license" in data:
                    return data["license"]
            except json.JSONDecodeError:
                pass

    # Known model licenses
    component_lower = component.lower()
    known_licenses = {
        "llama": "Llama Community License",
        "stable-diffusion": "CreativeML Open RAIL-M",
        "bert": "Apache-2.0",
        "gpt2": "MIT",
        "t5": "Apache-2.0",
        "mistral": "Apache-2.0",
        "whisper": "MIT",
    }
    for key, lic in known_licenses.items():
        if key in component_lower:
            return lic

    return "UNKNOWN"


def _analyze_license(license_name: str, use_case: str, findings: dict):
    """Analyze license compatibility with the intended use case."""
    info = LICENSE_INFO.get(license_name, LICENSE_INFO["UNKNOWN"])

    compatible = True
    issues = []

    if use_case == "commercial" and not info["commercial"]:
        compatible = False
        issues.append(f"License '{license_name}' does NOT permit commercial use.")

    findings["license_analysis"].append({
        "detected_license": license_name,
        "compatible_with_use_case": compatible,
        "risk": info["risk"],
        "restrictions": info["restrictions"],
        "issues": issues,
    })

    if not compatible:
        findings["conflicts"].append(
            f"LICENSE CONFLICT: '{license_name}' is incompatible with "
            f"'{use_case}' use case."
        )
        findings["recommendations"].append(
            f"Find an alternative component with a {use_case}-compatible license, "
            f"or obtain a separate commercial license."
        )

    if license_name == "UNKNOWN":
        findings["conflicts"].append(
            "NO LICENSE DETECTED — legally, this means all rights are reserved. "
            "You have no right to use, modify, or distribute this component."
        )


def _check_api_terms(component: str, findings: dict):
    """Check API terms of service for known providers."""
    component_lower = component.lower()
    for provider, terms in API_TERMS.items():
        if provider in component_lower:
            findings["api_terms"].append({
                "provider": provider,
                **terms,
            })


def _scan_license_files(project_path: str, findings: dict):
    """Check for third-party license notices."""
    third_party_dirs = ["licenses", "third_party", "vendor", "NOTICES"]
    for dirname in third_party_dirs:
        dir_path = os.path.join(project_path, dirname)
        if os.path.isdir(dir_path):
            findings["license_analysis"].append({
                "check": "third_party_notices",
                "directory": dir_path,
                "status": "FOUND",
                "note": "Third-party license directory found — verify all AI components are documented.",
            })
            return

    findings["recommendations"].append(
        "No third-party license directory found. Create a 'licenses/' directory "
        "documenting all AI component licenses for compliance tracking."
    )


def _check_data_licensing(project_path: str, component: str, findings: dict):
    """Check for dataset licensing issues."""
    data_dirs = ["data", "datasets", "training_data"]
    for dirname in data_dirs:
        dir_path = os.path.join(project_path, dirname)
        if os.path.isdir(dir_path):
            # Check for data license files
            has_license = any(
                os.path.isfile(os.path.join(dir_path, f))
                for f in ["LICENSE", "LICENSE.md", "DATA_LICENSE", "README.md"]
            )
            if not has_license:
                findings["conflicts"].append(
                    f"Data directory '{dirname}/' has no license documentation. "
                    f"Training data licensing is a major compliance gap."
                )
                findings["recommendations"].append(
                    f"Add a DATA_LICENSE file to '{dirname}/' documenting the "
                    f"source, license, and usage rights for all training data."
                )
