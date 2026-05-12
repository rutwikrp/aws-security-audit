# AWS Security Audit & Compliance Tool

## Overview

This project is a lightweight AWS security audit tool built using Python and Boto3 to identify common cloud security misconfigurations aligned with industry security frameworks and best practices.

The tool performs automated security checks on AWS resources and generates structured compliance findings with severity classification and framework mapping.

The project was developed to gain hands-on understanding of:

* Cloud security assessments
* Security misconfiguration detection
* CIS Benchmarks
* NIST security controls
* ISO 27001 compliance concepts
* AWS IAM and network security fundamentals

---

# Features

## Implemented Security Checks

### 1. Public SSH Exposure Detection

Detects AWS Security Groups exposing SSH (`22/tcp`) to the internet via:

```text id="jmw40f"
0.0.0.0/0
```

### 2. Overly Permissive IAM Policy Detection

Identifies IAM policies containing wildcard permissions such as:

```json id="c1h0z8"
"Action": "*"
```

or service-wide permissions like:

```json id="zud4wr"
"s3:*"
```

### 3. S3 Public Access Validation

Checks S3 bucket public access block configuration to identify potentially public buckets.

---

# Framework Mapping

The findings are mapped to commonly used security frameworks:

| Framework                    | Example Controls              |
| ---------------------------- | ----------------------------- |
| Center for Internet Security | CIS AWS Foundations Benchmark |
| NIST                         | AC-3, AC-6, SC-7              |
| ISO                          | ISO 27001 A.9, A.13           |

---

# Technologies Used

* Python 3
* Boto3
* AWS CLI
* IAM
* EC2 Security Groups
* S3

---

# Project Structure

```text id="3uvl5h"
aws-security-audit/
│
├── audit.py
├── checks/
│   ├── s3_check.py
│   ├── sg_check.py
│   └── iam_check.py
│
├── utils/
│   └── report.py
│
└── reports/
```

---

# Setup Instructions

## 1. Clone Repository

```bash id="2q4r56"
git clone <your-repo-url>
cd aws-security-audit
```

---

## 2. Create Virtual Environment

```bash id="cxdk7o"
python3 -m venv venv
```

Activate environment:

### Linux/macOS

```bash id="gvjlwm"
source venv/bin/activate
```

### Windows

```bash id="emjgmo"
venv\Scripts\activate
```

---

## 3. Install Dependencies

```bash id="74e9oe"
pip install boto3 colorama
```

---

## 4. Configure AWS Credentials

Install and configure AWS CLI:

[AWS CLI Configuration Guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html?utm_source=chatgpt.com)

Run:

```bash id="gkrw2s"
aws configure
```

---

# Running the Tool

Execute:

```bash id="r4v3pd"
python audit.py
```

---

# Sample Output

```text id="ap4l9h"
[HIGH] EC2 - Port 22 open to internet -
launch-wizard-4 (sg-004db2028f3240a3b)
VPC:vpc-093572cbe5e55ea27
Port:22
CIDR:0.0.0.0/0
```

---

# Example JSON Finding

```json id="g9n7gx"
{
    "service": "EC2",
    "issue": "Port 22 open to internet",
    "severity": "HIGH",
    "frameworks": {
        "CIS": "4.1",
        "NIST": "SC-7",
        "ISO27001": "A.13"
    }
}
```

---

# Security Concepts Demonstrated

This project demonstrates practical understanding of:

* Least privilege access
* Public network exposure risks
* IAM policy analysis
* Security posture visibility
* Cloud compliance awareness
* Basic cloud governance concepts

---

# Current Limitations

This tool is intentionally lightweight and currently does not support:

* Multi-account scanning
* AWS Organizations integration
* Real-time monitoring
* CloudTrail analysis
* Advanced IAM policy parsing
* Automated remediation

---

# Future Improvements

Possible enhancements include:

* CSV report export
* Docker support
* Multi-region scanning
* Logging support
* CLI arguments using argparse
* Additional CIS benchmark checks
* Colored terminal output

---

# Learning Outcome

While building this project, the following practical cloud security concepts were explored:

* AWS IAM permissions and least privilege
* Security Group exposure analysis
* CIS benchmark interpretation
* Security finding prioritization
* Reducing noisy findings and false positives
* Compliance-oriented security assessments
