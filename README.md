# AWS Cloud Security Auditor

Automated AWS cloud security auditing tool built in Python that scans AWS infrastructure for security misconfigurations and generates a visual HTML security report.
The scanner analyzes common AWS security risks across IAM, S3, EC2 security groups, and CloudTrail, calculates a security score, and provides remediation recommendations.


🎯 What This Does

Cloud environments are often breached due to misconfigured permissions, exposed services, or missing security controls.

This project helps identify security risks by automatically scanning AWS services and generating a structured report highlighting:
high-risk vulnerabilities
misconfigurations
remediation steps

🔍 Security Checks
IAM — Identity and Access Management
Check	What It Detects	Severity
User MFA Status	IAM users without multi-factor authentication	Medium
Root MFA	Root account without MFA enabled	High
Access Key Age	Detects old or risky access keys	Medium

S3 — Storage Security
Check	What It Detects	Severity
Public Access Block	Buckets accessible from the internet	High
Encryption Status	Buckets without encryption enabled	High
Logging Status	Buckets without access logging	Medium

EC2 — Security Groups
Check	What It Detects	                                                                    Severity
Open SSH Access	Security group allowing 0.0.0.0/0 on port 22	                              High
Public Inbound Rules	Security groups allowing unrestricted inbound traffic                	High



CloudTrail — Audit Logging
Check	What It Detects	Severity
CloudTrail Status	AWS account without CloudTrail logging enabled	High

## Tech Stack

- Python
- AWS SDK for Python (boto3)
- HTML reporting

## How to Run

Install dependencies:

```bash
pip install -r requirements.txt
