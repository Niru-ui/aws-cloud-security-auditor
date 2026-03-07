import json
import os
from pathlib import Path
from collections import Counter

import boto3


def calculate_score(findings):
    score = 100
    weights = {"High": 20, "Medium": 10, "Low": 5}

    for finding in findings:
        score -= weights.get(finding.get("severity", "Low"), 5)

    return max(score, 0)


def get_grade(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def get_region():
    return (
        os.environ.get("AWS_DEFAULT_REGION")
        or os.environ.get("AWS_REGION")
        or boto3.session.Session().region_name
        or "us-east-1"
    )


def get_account_id():
    try:
        sts = boto3.client("sts")
        return sts.get_caller_identity().get("Account", "Unknown")
    except Exception:
        return "Unknown"


def group_findings_by_service(findings):
    grouped = {"IAM": [], "S3": [], "EC2": [], "CloudTrail": []}
    for finding in findings:
        service = finding.get("service", "Other")
        grouped.setdefault(service, []).append(finding)
    return grouped


def get_recommendation(service, issue):
    issue_lower = issue.lower()
    service = service.lower()

    if service == "iam" and "root account mfa" in issue_lower:
        return "Enable MFA for the AWS root account immediately from the AWS account security settings."
    if "mfa" in issue_lower:
        return "Enable MFA for the IAM user in IAM → Users → Security credentials."
    if "0.0.0.0/0" in issue_lower and "22" in issue_lower:
        return "Restrict SSH access to trusted IPs instead of 0.0.0.0/0."
    if "0.0.0.0/0" in issue_lower:
        return "Review the security group and limit public inbound access."
    if "public access block" in issue_lower:
        return "Enable S3 Block Public Access for the bucket."
    if "encryption" in issue_lower:
        return "Enable default server-side encryption for the S3 bucket."
    if "cloudtrail not enabled" in issue_lower:
        return "Create and enable a multi-region CloudTrail trail for account activity logging."
    if "no multi-region cloudtrail" in issue_lower:
        return "Enable a multi-region CloudTrail trail for broader audit coverage."
    return "Review this configuration and apply AWS security best practices."


def build_summary_banner(findings):
    if not findings:
        return """
        <div class="summary-banner success">
            <strong>All checks passed.</strong> No security findings were detected in this scan.
        </div>
        """

    service_counter = Counter(f.get("service", "Unknown") for f in findings)
    high = sum(1 for f in findings if f.get("severity") == "High")
    medium = sum(1 for f in findings if f.get("severity") == "Medium")
    low = sum(1 for f in findings if f.get("severity") == "Low")

    severity_parts = []
    if high:
        severity_parts.append(f"{high} high-risk")
    if medium:
        severity_parts.append(f"{medium} medium-risk")
    if low:
        severity_parts.append(f"{low} low-risk")

    services = ", ".join(f"{k}: {v}" for k, v in service_counter.items())

    return f"""
    <div class="summary-banner warning">
        <strong>Action required:</strong> This scan detected {", ".join(severity_parts)} issue(s).<br>
        <span class="subtle">Affected services: {services}</span>
    </div>
    """


def severity_pill(severity):
    severity = severity or "Low"
    return f'<span class="severity-pill {severity.lower()}">{severity}</span>'


def status_pill(status):
    css = status.lower()
    return f'<span class="status-pill {css}">{status}</span>'


def build_iam_section(findings):
    if not findings:
        return """
        <div class="section-card">
            <h3>IAM — Identity and Access Management</h3>
            <table class="service-table">
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Check</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>IAM Users</td>
                        <td>MFA Configuration</td>
                        <td>""" + status_pill("PASS") + """</td>
                    </tr>
                </tbody>
            </table>
        </div>
        """

    rows = ""
    for finding in findings:
        rows += f"""
        <tr>
            <td>{finding.get("resource", "N/A")}</td>
            <td>{finding.get("issue", "N/A")}</td>
            <td>{severity_pill(finding.get("severity", "Medium"))}</td>
            <td>{status_pill("FAIL")}</td>
        </tr>
        """

    return f"""
    <div class="section-card">
        <h3>IAM — Identity and Access Management</h3>
        <table class="service-table">
            <thead>
                <tr>
                    <th>Resource</th>
                    <th>Issue</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def build_s3_section(findings):
    bucket_name = "security-test-2026"

    if not findings:
        return f"""
        <div class="section-card">
            <h3>S3 — Simple Storage Service</h3>
            <table class="service-table">
                <thead>
                    <tr>
                        <th>Bucket</th>
                        <th>Public Access Block</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>{bucket_name}</td>
                        <td>Enabled</td>
                        <td>{status_pill("PASS")}</td>
                    </tr>
                </tbody>
            </table>
        </div>
        """

    rows = ""
    for finding in findings:
        rows += f"""
        <tr>
            <td>{finding.get("resource", "N/A")}</td>
            <td>{finding.get("issue", "N/A")}</td>
            <td>{severity_pill(finding.get("severity", "Medium"))}</td>
            <td>{status_pill("FAIL")}</td>
        </tr>
        """

    return f"""
    <div class="section-card">
        <h3>S3 — Simple Storage Service</h3>
        <table class="service-table">
            <thead>
                <tr>
                    <th>Bucket</th>
                    <th>Issue</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def build_ec2_section(findings):
    if not findings:
        return """
        <div class="section-card">
            <h3>EC2 — Security Groups</h3>
            <table class="service-table">
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Check</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Security Groups</td>
                        <td>Public Inbound Access Review</td>
                        <td>""" + status_pill("PASS") + """</td>
                    </tr>
                </tbody>
            </table>
        </div>
        """

    rows = ""
    for finding in findings:
        rows += f"""
        <tr>
            <td>{finding.get("resource", "N/A")}</td>
            <td>{finding.get("issue", "N/A")}</td>
            <td>{severity_pill(finding.get("severity", "High"))}</td>
            <td>{status_pill("FAIL")}</td>
        </tr>
        """

    return f"""
    <div class="section-card">
        <h3>EC2 — Security Groups</h3>
        <table class="service-table">
            <thead>
                <tr>
                    <th>Resource</th>
                    <th>Issue</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def build_cloudtrail_section(findings):
    if not findings:
        return """
        <div class="section-card">
            <h3>CloudTrail — Audit Logging</h3>
            <table class="service-table">
                <thead>
                    <tr>
                        <th>Resource</th>
                        <th>Check</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>Account</td>
                        <td>CloudTrail Enabled</td>
                        <td>""" + status_pill("PASS") + """</td>
                    </tr>
                </tbody>
            </table>
        </div>
        """

    rows = ""
    for finding in findings:
        rows += f"""
        <tr>
            <td>{finding.get("resource", "N/A")}</td>
            <td>{finding.get("issue", "N/A")}</td>
            <td>{severity_pill(finding.get("severity", "High"))}</td>
            <td>{status_pill("FAIL")}</td>
        </tr>
        """

    return f"""
    <div class="section-card">
        <h3>CloudTrail — Audit Logging</h3>
        <table class="service-table">
            <thead>
                <tr>
                    <th>Resource</th>
                    <th>Issue</th>
                    <th>Severity</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def build_recommendations(findings):
    if not findings:
        return """
        <div class="section-card">
            <h3>Recommended Actions</h3>
            <div class="empty-state">No remediation actions needed.</div>
        </div>
        """

    rows = ""
    for finding in findings:
        rows += f"""
        <tr>
            <td>{severity_pill(finding.get("severity", "Low"))}</td>
            <td>{finding.get("service", "N/A")}</td>
            <td>{finding.get("issue", "N/A")}</td>
            <td>{get_recommendation(finding.get("service", ""), finding.get("issue", ""))}</td>
        </tr>
        """

    return f"""
    <div class="section-card">
        <h3>Recommended Actions</h3>
        <table class="service-table">
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Service</th>
                    <th>Issue</th>
                    <th>Recommended Fix</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def generate_html_report():
    report_path = Path("scan_report.json")

    if not report_path.exists():
        print("scan_report.json not found. Run scanner.py first.")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    findings = report.get("findings", [])
    total_findings = len(findings)
    score = calculate_score(findings)
    grade = get_grade(score)

    severity_counter = Counter(f.get("severity", "Low") for f in findings)
    high_count = severity_counter.get("High", 0)
    medium_count = severity_counter.get("Medium", 0)
    low_count = severity_counter.get("Low", 0)

    services_scanned = 4
    account_id = get_account_id()
    region = get_region()
    grouped = group_findings_by_service(findings)

    score_class = "good"
    if score < 80:
        score_class = "warn"
    if score < 60:
        score_class = "bad"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>AWS Security Audit Report</title>
    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
            background: #f3f6fb;
            color: #1f2937;
        }}

        .topbar {{
            background: linear-gradient(135deg, #0f172a, #0891b2);
            color: white;
            padding: 28px 20px;
        }}

        .topbar-inner {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .topbar h1 {{
            margin: 0 0 10px 0;
            font-size: 34px;
            font-weight: 700;
        }}

        .topbar p {{
            margin: 4px 0;
            opacity: 0.95;
            font-size: 15px;
        }}

        .container {{
            max-width: 1200px;
            margin: 24px auto 50px;
            padding: 0 20px;
        }}

        .scorebar-wrap {{
            background: white;
            border-radius: 16px;
            padding: 18px 20px;
            box-shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
            margin-bottom: 20px;
        }}

        .scorebar-head {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            gap: 12px;
            flex-wrap: wrap;
        }}

        .scorebar-title {{
            font-size: 16px;
            font-weight: 600;
        }}

        .scorebar-track {{
            width: 100%;
            height: 14px;
            background: #e5e7eb;
            border-radius: 999px;
            overflow: hidden;
        }}

        .scorebar-fill {{
            height: 100%;
            border-radius: 999px;
        }}

        .scorebar-fill.good {{
            background: linear-gradient(90deg, #16a34a, #22c55e);
        }}

        .scorebar-fill.warn {{
            background: linear-gradient(90deg, #f59e0b, #fbbf24);
        }}

        .scorebar-fill.bad {{
            background: linear-gradient(90deg, #dc2626, #ef4444);
        }}

        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 18px;
            margin-bottom: 20px;
        }}

        .card {{
            background: white;
            border-radius: 18px;
            padding: 22px 18px;
            box-shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
            text-align: center;
        }}

        .card .value {{
            font-size: 34px;
            font-weight: 800;
            margin-bottom: 8px;
        }}

        .card .label {{
            color: #6b7280;
            font-size: 15px;
        }}

        .grade-a, .grade-b {{
            color: #16a34a;
        }}

        .grade-c {{
            color: #d97706;
        }}

        .grade-d, .grade-f {{
            color: #dc2626;
        }}

        .summary-banner {{
            border-radius: 14px;
            padding: 16px 18px;
            margin-bottom: 22px;
            font-size: 15px;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.06);
            line-height: 1.5;
        }}

        .summary-banner.success {{
            background: #ecfdf5;
            border-left: 6px solid #16a34a;
            color: #166534;
        }}

        .summary-banner.warning {{
            background: #fff7ed;
            border-left: 6px solid #f97316;
            color: #9a3412;
        }}

        .subtle {{
            color: #7c2d12;
            font-size: 14px;
        }}

        .section-grid {{
            display: grid;
            gap: 20px;
        }}

        .section-card {{
            background: white;
            border-radius: 18px;
            padding: 20px;
            box-shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
        }}

        .section-card h3 {{
            margin: 0 0 16px 0;
            font-size: 21px;
            color: #0f172a;
        }}

        .service-table {{
            width: 100%;
            border-collapse: collapse;
            overflow: hidden;
            border-radius: 12px;
        }}

        .service-table th {{
            background: #0f172a;
            color: white;
            text-align: left;
            padding: 14px;
            font-size: 14px;
        }}

        .service-table td {{
            padding: 14px;
            border-bottom: 1px solid #e5e7eb;
            vertical-align: top;
            font-size: 14px;
        }}

        .service-table tr:last-child td {{
            border-bottom: none;
        }}

        .severity-pill, .status-pill {{
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
        }}

        .severity-pill.high {{
            background: #fee2e2;
            color: #b91c1c;
        }}

        .severity-pill.medium {{
            background: #ffedd5;
            color: #c2410c;
        }}

        .severity-pill.low {{
            background: #dbeafe;
            color: #1d4ed8;
        }}

        .status-pill.pass {{
            background: #dcfce7;
            color: #166534;
        }}

        .status-pill.fail {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .status-pill.warn {{
            background: #fef3c7;
            color: #92400e;
        }}

        .empty-state {{
            padding: 14px;
            background: #ecfdf5;
            border-radius: 12px;
            color: #166534;
            font-weight: 500;
        }}

        .footer {{
            margin-top: 24px;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
        }}

        @media (max-width: 768px) {{
            .topbar h1 {{
                font-size: 28px;
            }}

            .card .value {{
                font-size: 28px;
            }}

            .service-table th,
            .service-table td {{
                font-size: 13px;
                padding: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="topbar">
        <div class="topbar-inner">
            <h1>AWS Security Audit Report</h1>
            <p>Automated cloud security scan using Python and boto3</p>
            <p><strong>Account:</strong> {account_id} &nbsp; | &nbsp; <strong>Region:</strong> {region}</p>
            <p><strong>Scan Time:</strong> {report.get("scan_time", "N/A")}</p>
        </div>
    </div>

    <div class="container">
        <div class="scorebar-wrap">
            <div class="scorebar-head">
                <div class="scorebar-title">Overall Security Score</div>
                <div><strong>{score}%</strong></div>
            </div>
            <div class="scorebar-track">
                <div class="scorebar-fill {score_class}" style="width: {score}%;"></div>
            </div>
        </div>

        <div class="metrics">
            <div class="card">
                <div class="value grade-{grade.lower()}">{grade}</div>
                <div class="label">Security Grade</div>
            </div>
            <div class="card">
                <div class="value">{score}%</div>
                <div class="label">Security Score</div>
            </div>
            <div class="card">
                <div class="value">{services_scanned}</div>
                <div class="label">Services Scanned</div>
            </div>
            <div class="card">
                <div class="value">{total_findings}</div>
                <div class="label">Issues Found</div>
            </div>
            <div class="card">
                <div class="value" style="color:#dc2626;">{high_count}</div>
                <div class="label">High Severity</div>
            </div>
            <div class="card">
                <div class="value" style="color:#ea580c;">{medium_count}</div>
                <div class="label">Medium Severity</div>
            </div>
        </div>

        {build_summary_banner(findings)}

        <div class="section-grid">
            {build_iam_section(grouped.get("IAM", []))}
            {build_s3_section(grouped.get("S3", []))}
            {build_ec2_section(grouped.get("EC2", []))}
            {build_cloudtrail_section(grouped.get("CloudTrail", []))}
            {build_recommendations(findings)}
        </div>

        <div class="footer">
            Generated automatically by your Python AWS Cloud Security Auditor.
        </div>
    </div>
</body>
</html>
"""

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    print("Fixed HTML report generated: report.html")


if __name__ == "__main__":
    generate_html_report()