# AWS Cloud Security Auditor

AWS Cloud Security Auditor is a Python-based AWS security auditing tool that scans cloud infrastructure for common security misconfigurations and generates a visual security report.

## Features

The scanner checks for:

- IAM users without MFA
- Root account MFA status
- IAM access key age
- Public S3 bucket exposure
- S3 encryption configuration
- EC2 security groups open to the internet
- CloudTrail logging configuration

## Tech Stack

- Python
- AWS SDK for Python (boto3)
- HTML reporting

## How to Run

Install dependencies:

```bash
pip install -r requirements.txt
