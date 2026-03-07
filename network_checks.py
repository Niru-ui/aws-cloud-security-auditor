import boto3
from botocore.exceptions import ClientError


def check_dangerous_security_groups(findings):
    print("\n[+] Checking dangerous EC2 security group rules...")
    ec2 = boto3.client("ec2")

    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])

        if not groups:
            print("  No security groups found.")
            return

        for sg in groups:
            group_name = sg.get("GroupName", "Unknown")
            group_id = sg.get("GroupId", "Unknown")

            for permission in sg.get("IpPermissions", []):
                protocol = permission.get("IpProtocol", "All")
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr != "0.0.0.0/0":
                        continue

                    # All traffic open
                    if protocol == "-1":
                        print(f"  Warning: {group_name} ({group_id}) allows ALL traffic from anywhere.")
                        findings.append({
                            "service": "EC2",
                            "resource": group_id,
                            "issue": "All traffic open to 0.0.0.0/0",
                            "severity": "High"
                        })

                    # RDP open
                    elif from_port == 3389 or to_port == 3389:
                        print(f"  Warning: {group_name} ({group_id}) allows RDP from anywhere.")
                        findings.append({
                            "service": "EC2",
                            "resource": group_id,
                            "issue": "RDP port 3389 open to 0.0.0.0/0",
                            "severity": "High"
                        })

    except ClientError as e:
        print(f"Error checking dangerous security groups: {e}")