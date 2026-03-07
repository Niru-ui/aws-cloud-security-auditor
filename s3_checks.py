import boto3
from botocore.exceptions import ClientError


def check_s3_encryption(findings):
    print("\n[+] Checking S3 bucket encryption...")
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            print("  No S3 buckets found.")
            return

        for bucket in buckets:
            bucket_name = bucket["Name"]

            try:
                s3.get_bucket_encryption(Bucket=bucket_name)
                print(f"  Secure: {bucket_name} has encryption enabled.")
            except ClientError as e:
                error_code = e.response["Error"]["Code"]

                if error_code in [
                    "ServerSideEncryptionConfigurationNotFoundError",
                    "NoSuchBucket"
                ]:
                    print(f"  Warning: {bucket_name} does not have default encryption enabled.")
                    findings.append({
                        "service": "S3",
                        "resource": bucket_name,
                        "issue": "Bucket encryption not enabled",
                        "severity": "Medium"
                    })
                else:
                    print(f"  Error checking encryption for {bucket_name}: {e}")

    except ClientError as e:
        print(f"Error listing S3 buckets for encryption check: {e}")