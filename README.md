# AWS Cloud Security Auditor

Automated AWS cloud security auditing tool built in Python that scans AWS infrastructure for security misconfigurations and generates a visual HTML security report.
The scanner analyzes common AWS security risks across IAM, S3, EC2 security groups, and CloudTrail, calculates a security score, and provides remediation recommendations.

## 🔍 Security Checks

### IAM — Identity and Access Management

| Check | What It Detects | Severity |
|------|----------------|---------|
| User MFA Status | IAM users without multi-factor authentication | 🟠 Medium |
| Root MFA | Root account without MFA protection | 🔴 High |
| Access Key Age | Access keys older than recommended rotation period | 🟡 Medium |

---

### S3 — Simple Storage Service

| Check | What It Detects | Severity |
|------|----------------|---------|
| Public Access Block | Buckets accessible by anyone online | 🔴 Critical |
| Encryption Status | Buckets without AES256 encryption | 🟡 High |
| Access Logging | Buckets without audit trail logging | 🟠 Medium |

---

### EC2 — Security Groups

| Check | What It Detects | Severity |
|------|----------------|---------|
| Open SSH Access | Security group allowing `0.0.0.0/0` on port 22 | 🔴 High |
| Public Inbound Rules | Security group allowing unrestricted inbound traffic | 🔴 High |

---

### CloudTrail — Audit Logging

| Check | What It Detects | Severity |
|------|----------------|---------|
| CloudTrail Status | AWS account without CloudTrail logging enabled | 🔴 High |

## Tech Stack

- Python
- AWS SDK for Python (boto3)
- HTML reporting

## 📋 Real Output From My AWS Account
```text
=======================================================
AWS SECURITY AUDIT SUMMARY

Total users scanned: 1
Users WITH MFA: 0 ❌
Users WITHOUT MFA: 1 ⚠️

=======================================================
S3 BUCKET SECURITY CHECKS

📦 Scanning bucket: security-test-2026
✔ Public Access | Blocked
✔ Encryption | Enabled
⚠ Access Logging | Not enabled

=======================================================
EC2 SECURITY GROUP FINDINGS

⚠ sg-002219d7c09553ecc
Open inbound rule to 0.0.0.0/0 on port 22
Open inbound rule to 0.0.0.0/0 on port 0

=======================================================
CLOUDTRAIL STATUS

⚠ CloudTrail is not enabled

=======================================================
FULL AUDIT COMPLETE
```

Detected Issues:
- EC2 security group open to internet
- IAM user without MFA
- Root account MFA not enabled
- CloudTrail logging disabled

Report saved to: scan_report.json

🏗 How It Works

Your Laptop
     │
     │  Python boto3 API calls
     ▼
AWS Account
├── IAM Service
│   ├── Scan users for MFA status
│   ├── Check access key age
│   └── Verify root account MFA
│
├── S3 Service
│   ├── List all buckets
│   ├── Check public access block
│   └── Verify encryption enabled
│
├── EC2 Service
│   └── Analyze security groups for open inbound rules
│
└── CloudTrail
    └── Verify audit logging is enabled
    
🚀 Run This Yourself

Requirements
Python 3.9+
AWS account
boto3
AWS CLI configured

Step 1 — Clone the repository
git clone https://github.com/YOUR_USERNAME/aws-cloud-security-auditor.git
cd aws-cloud-security-auditor

Step 2 — Install dependencies
pip3 install boto3
pip3 install -r requirements.txt

Step 3 — Configure AWS credentials
aws configure

Provide:
AWS Access Key ID
AWS Secret Access Key
Region
Output format

Step 4 — Run the security scan
python3 scanner.py

Open the dashboard:
open report.html

🌍 Real World Impact

This Tool Catches        Real Breach It Prevents
No MFA on users          Most common AWS account takeover vector
Public S3 buckets        Capital One breach — 100M records, $80M fine
Old access keys          Leaked credentials sold on dark web markets
No root MFA              Complete account takeover if root is compromised

🔑 What I Used To Build This

Python 3.11 — core scripting language
boto3 — official AWS SDK for Python
AWS IAM — Identity and Access Management service
AWS S3 — Simple Storage Service
AWS CLI — command line tool for AWS
VS Code — development environment

## 📍 About

Hands-on cloud security project built to detect AWS misconfigurations using Python and the AWS SDK.

This tool scans AWS services such as IAM, S3, EC2 security groups, and CloudTrail to identify security risks and generate a visual security report with remediation suggestions.

Built as part of practical cloud security learning while pursuing an MS in Cybersecurity.

📍 Fairborn, Ohio, USA  
💼 Interested in Cloud Security / DevSecOps internships
