import sys
import json
import xml.etree.ElementTree as ET
import yaml

def read_files(xml_file, yaml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except (OSError, ET.ParseError, UnicodeDecodeError):
        print(f"Error: Cannot read XML file: {xml_file}")
        sys.exit(1)

    try:
        with open(yaml_file, "r", encoding = "utf-8") as file:
            contents = file.read()

        if contents.strip() == "":
            policy = {}
        else:
            policy = yaml.safe_load(contents)

        if not isinstance(policy, dict):
            raise ValueError("Policy must be a mapping")

        if "min_os" in policy and not isinstance(policy["min_os"], dict):
            raise ValueError("min_os must be a mapping")

        if "max_down_interfaces" in policy:
            value = policy["max_down_interfaces"]
            if type(value) is not int or value < 0:
                raise ValueError("max_down_interfaces must be a non-negative integer")

    except (OSError, yaml.YAMLError, ValueError, UnicodeDecodeError):
        print(f"Error: Cannot read YAML policy file: {yaml_file}")
        sys.exit(1)

    return root, policy



def compare_versions(found, required):
    
    def version_parts(version):
        parts = [int(part) for part in version.split(".")]

        while len(parts) > 1 and parts[-1] == 0:
            parts.pop()

        return tuple(parts)

    return version_parts(found) < version_parts(required)

def audit_inventory(root, policy):

    report = { 
        "site": root.get("site"), 
        "total_devices": 0, 
        "skipped_devices": 0, 
        "roles": {}, 
        "interfaces": {"up": 0, "down": 0, "other": 0}, 
        "violations": [], 
        "complaint": []
        }

    min_os = policy.get("min_os")
    require_owner = policy.get("require_owner") is True
    max_down = policy.get("max_down_interfaces")

    for device in root.findall("device"):
        device_id = device.get("id")

        #Skip devices with no id
        if device_id is None:
            report["skipped_devices"] += 1
            continue

        report["total_devices"] += 1

        role = device.get("role")

        #Counts devices by role
        report["roles"][role] = report["roles"].get(role, 0) + 1

        device_has_violation = False

        #Counts interface statuses
        down_count = 0

        for interface in device.findall("interface"):
            status = interface.get("status")

            if status == "up":
                report["interfaces"]["up"] += 1
            elif status == "down":
                report["interfaces"]["down"] += 1
                down_count += 1
            else:
                report["interfaces"]["other"] += 1

        #Checks if role is allowed
        role_allowed = True

        if min_os is not None and role not in min_os:
            report["violations"].append({"device": device_id, "type": "unknown_role", "role": role})
            device_has_violation = True
            role_allowed = False

        #Checks minimum OS version
        if min_os is not None and role_allowed:
            found = device.get("os")
            required = min_os[role]

            if compare_versions(found, required):
                report["violations"].append({"device": device_id, "type": "os_outdated", "found": found, "required": required})

                device_has_violation = True

        #Checks if device has owner
        if require_owner:
            owner = device.find("owner")

            if owner is None or not (owner.txt or "").strip():
                report["violations"].append({
                    "device": device_id, 
                    "type": "missing_owner"})
                device_has_violation = True

        #Checks the number of down interfaces
        if max_down is not None and down_count > max_down:
            report["Violations"].append({
                "device": device_id, 
                "type": "too_many_down", 
                "down": down_count})
            device_has_violation = True

        #Devices without violations are compliant
        if not device_has_violation:
            report["complaint"].append(device_id)

    report["complaint"].sort()
    return report



def write_report(report):

    try:
        with open("audit.json", "w", encoding = "utf-8") as file:
            json.dump(report, file, indent = 4)
    except OSError:
        print("Error: Could not write audit.json")
        sys.exit(1)


def main():

    if len(sys.argv) != 3:
        print("usage: python pa2.py DEVICES.xml POLICY.yaml")
        sys.exit(2)

    xml_file = sys.argv[1]
    yaml_file = sys.argv[2]

    root, policy = read_files(xml_file, yaml_file)

    report = audit_inventory(root, policy)

    write_report(report)

    print(f"Total devices: {report['total_devices']}")
    print(f"Skipped devices: {report['skipped_devices']}")
    print(f"Violations: {len(report['violations'])}")
    print(f"Compliant devices: {len(report['compliant'])}")
    print("Report saved to audit.json")


    if __name__ == "__main__":
        main()