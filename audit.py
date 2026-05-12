from checks.s3_check import check_s3_public_access
from checks.sg_check import check_security_groups
from checks.iam_check import check_iam_policies
from utils.reports import generate_report

all_findings = []

print("\nStarting AWS Security Audit...\n")

all_findings.extend(check_s3_public_access())
all_findings.extend(check_security_groups())
all_findings.extend(check_iam_policies())

generate_report(all_findings)

print("\nAudit Completed.\n")