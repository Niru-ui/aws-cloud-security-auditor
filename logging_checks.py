import boto3
from botocore.exceptions import ClientError


def check_cloudtrail(findings):
    print("\n[+] Checking CloudTrail configuration...")
    cloudtrail = boto3.client("cloudtrail")
    try:
        trails = cloudtrail.describe_trails().get("trailList", [])

        if not trails:
            print("  Warning: CloudTrail is not enabled.")
            findings.append({
                "service": "CloudTrail",
                "resource": "Account",
                "issue": "CloudTrail not enabled",
                "severity": "High"
            })
            return

        multi_region = any(trail.get("IsMultiRegionTrail", False) for trail in trails)

        if multi_region:
            print("  Secure: Multi-region CloudTrail is enabled.")
        else:
            print("  Warning: No multi-region CloudTrail found.")
            findings.append({
                "service": "CloudTrail",
                "resource": "Account",
                "issue": "No multi-region CloudTrail found",
                "severity": "Medium"
            })

    except ClientError as e:
        print(f"Error checking CloudTrail: {e}")