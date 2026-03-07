import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError


def check_root_mfa(findings):
    iam = boto3.client("iam")

    try:
        summary = iam.get_account_summary()["SummaryMap"]

        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append({
                "service": "IAM",
                "resource": "Root Account",
                "issue": "Root account MFA not enabled",
                "severity": "High"
            })
        else:
            print("  Secure: Root account MFA is enabled.")

    except ClientError as e:
        print(f"Error checking root account MFA: {e}")


def check_old_access_keys(findings):
    print("\n[+] Checking IAM access key age...")
    iam = boto3.client("iam")

    try:
        users = iam.list_users().get("Users", [])

        if not users:
            print("  No IAM users found.")
            return

        for user in users:
            username = user["UserName"]
            keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])

            if not keys:
                print(f"  No access keys found for {username}.")
                continue

            for key in keys:
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days

                if age_days > 90:
                    print(f"  Warning: {username} has an access key older than 90 days ({age_days} days).")
                    findings.append({
                        "service": "IAM",
                        "resource": username,
                        "issue": f"Access key older than 90 days ({age_days} days)",
                        "severity": "Medium"
                    })
                else:
                    print(f"  Secure: {username} access key age is {age_days} days.")

    except ClientError as e:
        print(f"Error checking old access keys: {e}")