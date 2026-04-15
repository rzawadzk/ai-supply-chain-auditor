from .inventory import INVENTORY_TOOL, run_inventory
from .provenance import PROVENANCE_TOOL, run_provenance
from .integrity import INTEGRITY_TOOL, run_integrity
from .compliance import COMPLIANCE_TOOL, run_compliance
from .behavior import BEHAVIOR_TOOL, run_behavior

ALL_TOOLS = [INVENTORY_TOOL, PROVENANCE_TOOL, INTEGRITY_TOOL, COMPLIANCE_TOOL, BEHAVIOR_TOOL]

TOOL_RUNNERS = {
    "scan_inventory": run_inventory,
    "check_provenance": run_provenance,
    "verify_integrity": run_integrity,
    "audit_compliance": run_compliance,
    "probe_behavior": run_behavior,
}
