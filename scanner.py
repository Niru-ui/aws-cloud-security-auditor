from iam_checks import check_root_mfa, check_old_access_keys
from s3_checks import check_s3_encryption
from logging_checks import check_cloudtrail
from network_checks import check_dangerous_security_groups
import json
from datetime import datetime

import boto3
from botocore.exceptions import ClientError


def add_finding(findings, service, resource, issue, severity="Medium"):
    findings.append({
        "service": service,
        "resource": resource,
        "issue": issue,
        "severity": severity
    })


def check_s3_public_access():
    print("\n[+] Checking S3 buckets...")
    s3 = boto3.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            print("  No S3 buckets found.")
            return findings

        for bucket in buckets:
            bucket_name = bucket["Name"]
            print(f"  Bucket: {bucket_name}")

            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab["PublicAccessBlockConfiguration"]

                if all(config.values()):
                    print("    Secure: Public access block fully enabled.")
                else:
                    print("    Warning: Public access block not fully enabled.")
                    add_finding(
                        findings,
                        "S3",
                        bucket_name,
                        "Public access block not fully enabled",
                        "High"
                    )

            except ClientError as e:
                code = e.response["Error"]["Code"]

                if code == "NoSuchPublicAccessBlockConfiguration":
                    print("    Warning: No public access block configuration found.")
                    add_finding(
                        findings,
                        "S3",
                        bucket_name,
                        "No public access block configuration",
                        "High"
                    )
                else:
                    print(f"    Error: {e}")

    except ClientError as e:
        print(f"Error listing buckets: {e}")

    return findings


def check_security_groups():
    print("\n[+] Checking EC2 security groups...")
    ec2 = boto3.client("ec2")
    findings = []

    try:
        groups = ec2.describe_security_groups().get("SecurityGroups", [])

        for sg in groups:
            group_name = sg.get("GroupName", "Unknown")
            group_id = sg.get("GroupId", "Unknown")

            for permission in sg.get("IpPermissions", []):
                from_port = permission.get("FromPort", "All")
                to_port = permission.get("ToPort", "All")
                protocol = permission.get("IpProtocol", "All")

                for ip_range in permission.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr == "0.0.0.0/0":
                        print(
                            f"  Warning: {group_name} ({group_id}) open to world -> "
                            f"{protocol} {from_port}-{to_port}"
                        )

                        add_finding(
                            findings,
                            "EC2",
                            group_id,
                            f"Open inbound rule to 0.0.0.0/0 on {protocol} {from_port}-{to_port}",
                            "High"
                        )

    except ClientError as e:
        print(f"Error describing security groups: {e}")

    return findings


def check_iam_mfa():
    print("\n[+] Checking IAM users for MFA...")
    iam = boto3.client("iam")
    findings = []

    try:
        users = iam.list_users().get("Users", [])

        if not users:
            print("  No IAM users found.")
            return findings

        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])

            if not mfa_devices:
                print(f"  Warning: {username} does not have MFA enabled.")

                add_finding(
                    findings,
                    "IAM",
                    username,
                    "MFA not enabled",
                    "Medium"
                )
            else:
                print(f"  Secure: {username} has MFA enabled.")

    except ClientError as e:
        print(f"Error checking IAM MFA: {e}")

    return findings


def save_report(findings):
    report = {
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": findings
    }

    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\n[+] Report saved to scan_report.json")


def print_summary(findings):
    print("\n" + "=" * 60)
    print("AWS CLOUD SECURITY SCAN SUMMARY")
    print("=" * 60)

    if not findings:
        print("No major misconfigurations found.")
        return

    for i, finding in enumerate(findings, 1):
        print(
            f"{i}. [{finding['severity']}] "
            f"{finding['service']} | {finding['resource']} | {finding['issue']}"
        )


if __name__ == "__main__":
    all_findings = []

    # S3 checks
    all_findings.extend(check_s3_public_access())
    check_s3_encryption(all_findings)

    # EC2 checks
    all_findings.extend(check_security_groups())
    check_dangerous_security_groups(all_findings)

    # IAM checks
    all_findings.extend(check_iam_mfa())
    check_root_mfa(all_findings)
    check_old_access_keys(all_findings)

    # Logging checks
    check_cloudtrail(all_findings)

    print_summary(all_findings)
    save_report(all_findings)