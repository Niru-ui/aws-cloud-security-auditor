import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from html_report import generate_html_report

s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
iam = boto3.client("iam")
cloudtrail = boto3.client("cloudtrail")


def add_finding(findings, severity, service, resource, issue, recommendation):
    findings.append({
        "severity": severity,
        "service": service,
        "resource": resource,
        "issue": issue,
        "recommendation": recommendation
    })


def check_s3_public_access():
    findings = []
    print("\n[+] Checking S3 buckets...")

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            print(f"  Bucket: {bucket_name}")

            try:
                response = s3.get_public_access_block(Bucket=bucket_name)
                config = response["PublicAccessBlockConfiguration"]

                if all(config.values()):
                    print("    Secure: Public access block fully enabled.")
                else:
                    print("    Warning: Public access block not fully enabled.")
                    add_finding(
                        findings,
                        "High",
                        "S3",
                        bucket_name,
                        "Public access block not fully enabled",
                        "Enable all S3 Block Public Access settings."
                    )

            except ClientError:
                print("    Warning: Public access block not configured.")
                add_finding(
                    findings,
                    "High",
                    "S3",
                    bucket_name,
                    "Public access block not configured",
                    "Enable S3 Block Public Access."
                )

    except ClientError as e:
        print(f"Error checking S3 buckets: {e}")

    return findings


def check_s3_encryption(findings):
    print("\n[+] Checking S3 bucket encryption...")

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
                print(f"  Secure: {bucket_name} has encryption enabled.")

            except ClientError:
                print(f"  Warning: {bucket_name} does not have encryption enabled.")
                add_finding(
                    findings,
                    "High",
                    "S3",
                    bucket_name,
                    "Bucket encryption not enabled",
                    "Enable default server-side encryption for this S3 bucket."
                )

    except ClientError as e:
        print(f"Error checking S3 encryption: {e}")


def check_s3_versioning(findings):
    print("\n[+] Checking S3 bucket versioning...")

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            response = s3.get_bucket_versioning(Bucket=bucket_name)

            if response.get("Status") == "Enabled":
                print(f"  Secure: {bucket_name} has versioning enabled.")
            else:
                print(f"  Warning: {bucket_name} does not have versioning enabled.")
                add_finding(
                    findings,
                    "Medium",
                    "S3",
                    bucket_name,
                    "Bucket versioning not enabled",
                    "Enable S3 versioning to protect against accidental deletion."
                )

    except ClientError as e:
        print(f"Error checking S3 versioning: {e}")


def check_security_groups():
    findings = []
    print("\n[+] Checking EC2 security groups...")

    try:
        response = ec2.describe_security_groups()

        for sg in response["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "N/A")

            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol", "all")
                from_port = rule.get("FromPort", "all")
                to_port = rule.get("ToPort", "all")

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")

                    if cidr == "0.0.0.0/0":
                        print(
                            f"  Warning: {sg_name} ({sg_id}) open to world -> "
                            f"{protocol} {from_port}-{to_port}"
                        )

                        severity = "High" if from_port in [22, 3389] else "Medium"

                        add_finding(
                            findings,
                            severity,
                            "EC2",
                            sg_id,
                            f"Open inbound rule to 0.0.0.0/0 on {protocol} {from_port}-{to_port}",
                            "Restrict inbound access to trusted IP addresses only."
                        )

    except ClientError as e:
        print(f"Error checking security groups: {e}")

    return findings


def check_dangerous_security_groups(findings):
    print("\n[+] Checking dangerous EC2 security group rules...")

    dangerous_ports = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        6379: "Redis"
    }

    try:
        response = ec2.describe_security_groups()

        for sg in response["SecurityGroups"]:
            sg_id = sg["GroupId"]

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if from_port is None or to_port is None:
                    continue

                for port, name in dangerous_ports.items():
                    if from_port <= port <= to_port:
                        for ip_range in rule.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                add_finding(
                                    findings,
                                    "Critical",
                                    "EC2",
                                    sg_id,
                                    f"Dangerous port {port} ({name}) open to the internet",
                                    f"Close public access to port {port} or restrict it to your IP."
                                )

    except ClientError as e:
        print(f"Error checking dangerous security groups: {e}")


def check_iam_mfa():
    findings = []
    print("\n[+] Checking IAM users for MFA...")

    try:
        users = iam.list_users().get("Users", [])

        for user in users:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])

            if mfa_devices:
                print(f"  Secure: {username} has MFA enabled.")
            else:
                print(f"  Warning: {username} does not have MFA enabled.")
                add_finding(
                    findings,
                    "Medium",
                    "IAM",
                    username,
                    "MFA not enabled",
                    "Enable MFA for this IAM user."
                )

    except ClientError as e:
        print(f"Error checking IAM MFA: {e}")

    return findings


def check_root_mfa(findings):
    try:
        summary = iam.get_account_summary()
        root_mfa = summary["SummaryMap"].get("AccountMFAEnabled", 0)

        if root_mfa == 1:
            print("  Secure: Root account MFA is enabled.")
        else:
            print("  Warning: Root account MFA is not enabled.")
            add_finding(
                findings,
                "Critical",
                "IAM",
                "Root Account",
                "Root MFA not enabled",
                "Enable MFA on the AWS root account immediately."
            )

    except ClientError as e:
        print(f"Error checking root MFA: {e}")


def check_old_access_keys(findings):
    print("\n[+] Checking IAM access key age...")

    try:
        users = iam.list_users().get("Users", [])
        now = datetime.now(timezone.utc)

        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])

            for key in keys:
                key_id = key["AccessKeyId"]
                created = key["CreateDate"]
                age_days = (now - created).days

                if age_days > 90:
                    print(f"  Warning: {username} access key {key_id} is {age_days} days old.")
                    add_finding(
                        findings,
                        "Medium",
                        "IAM",
                        username,
                        f"Access key older than 90 days: {age_days} days",
                        "Rotate IAM access keys regularly."
                    )
                else:
                    print(f"  Secure: {username} access key age is {age_days} days.")

    except ClientError as e:
        print(f"Error checking access keys: {e}")


def check_cloudtrail(findings):
    print("\n[+] Checking CloudTrail configuration...")

    try:
        trails = cloudtrail.describe_trails().get("trailList", [])

        if not trails:
            print("  Warning: CloudTrail is not enabled.")
            add_finding(
                findings,
                "High",
                "CloudTrail",
                "Account",
                "CloudTrail not enabled",
                "Enable CloudTrail to log AWS account activity."
            )
            return

        enabled = False

        for trail in trails:
            trail_name = trail["Name"]
            status = cloudtrail.get_trail_status(Name=trail_name)

            if status.get("IsLogging"):
                enabled = True
                print(f"  Secure: CloudTrail {trail_name} is logging.")

        if not enabled:
            print("  Warning: CloudTrail exists but is not logging.")
            add_finding(
                findings,
                "High",
                "CloudTrail",
                "Account",
                "CloudTrail exists but is not logging",
                "Start CloudTrail logging."
            )

    except ClientError as e:
        print(f"Error checking CloudTrail: {e}")


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

    # S3 Checks
    all_findings.extend(check_s3_public_access())
    check_s3_encryption(all_findings)
    check_s3_versioning(all_findings)

    # EC2 Checks
    all_findings.extend(check_security_groups())
    check_dangerous_security_groups(all_findings)

    # IAM Checks
    all_findings.extend(check_iam_mfa())
    check_root_mfa(all_findings)
    check_old_access_keys(all_findings)

    # CloudTrail Checks
    check_cloudtrail(all_findings)

    print_summary(all_findings)
    save_report(all_findings)

    total_checks = 10
    checks_passed = total_checks - len(all_findings)

    results = {
        "account_id": "380607195064",
        "region": "us-east-2",
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "findings": all_findings,
        "checks_passed": checks_passed
    }

    generate_html_report(results)
