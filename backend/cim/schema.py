from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class CIMField:
    \"\"\"Defines a standard field in the BARAQ Common Information Model.\"\"\"
    name: str
    description: str
    expected_type: type

CIM_SCHEMA = {
    \"endpoint\": {
        \"host\": CIMField(\"host\", \"The hostname of the affected system\", str),
        \"user\": CIMField(\"user\", \"The user account associated with the event\", str),
        \"org\": CIMField(\"org\", \"The organization tenant ID\", str),
    },
    \"network\": {
        \"src_ip\": CIMField(\"src_ip\", \"Source IP address\", str),
        \"dest_ip\": CIMField(\"dest_ip\", \"Destination IP address\", str),
        \"src_port\": CIMField(\"src_port\", \"Source port\", int),
        \"dest_port\": CIMField(\"dest_port\", \"Destination port\", int),
        \"protocol\": CIMField(\"protocol\", \"Network protocol (TCP/UDP/ICMP)\", str),
    },
    \"process\": {
        \"proc_name\": CIMField(\"proc_name\", \"Name of the process\", str),
        \"proc_path\": CIMField(\"proc_path\", \"Full path to the executable\", str),
        \"pid\": CIMField(\"pid\", \"Process ID\", int),
        \"ppid\": CIMField(\"ppid\", \"Parent Process ID\", int),
        \"cmd_line\": CIMField(\"cmd_line\", \"Full command line arguments\", str),
    },
    \"identity\": {
        \"user_id\": CIMField(\"user_id\", \"Unique identifier for the user\", str),
        \"user_domain\": CIMField(\"user_domain\", \"Authentication domain\", str),
    }
}

def normalize_to_cim(data: Dict[str, Any], category: str) -> Dict[str, Any]:
    \"\"\"
    Ensures a data dictionary conforms to the CIM for a given category.
    Fills missing required fields with defaults.
    \"\"\"
    if category not in CIM_SCHEMA:
        return data
    
    schema = CIM_SCHEMA[category]
    normalized = data.copy()
    
    for field_name, field_def in schema.items():
        if field_name not in normalized:
            normalized[field_name] = None if field_def.expected_type == str else 0
            
    return normalized
