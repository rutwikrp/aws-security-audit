import boto3
import json

iam = boto3.client('iam')


def check_iam_policies():
    findings = []
    severity= None
    policies = iam.list_policies(Scope='Local')['Policies']

    for policy in policies:

        version = iam.get_policy_version(
            PolicyArn=policy['Arn'],
            VersionId=policy['DefaultVersionId']
        )

        document = version['PolicyVersion']['Document']

        statements = document.get('Statement', [])

        for stmt in statements:

            actions = stmt.get('Action')
            resources = stmt.get('Resource')

            if isinstance(actions, list):
                action_str = " ".join(actions)
            else:
                action_str = actions

            if action_str == "*":
                severity = "CRITICAL"
                print(actions)

            elif "iam:*" in action_str:
                severity = "HIGH"
                print(actions)

            elif "s3:*" in action_str:
                severity = "MEDIUM"
                print(actions)

            elif "*" in action_str:
                severity = "LOW"
                print(actions)

            if severity:
                findings.append({
                    "service": "IAM",
                    "resource": policy['PolicyName'],
                    "issue": f"Overly permissive policy: {action_str}",
                    "severity": severity,
                    "frameworks": {
                        "CIS": "1.22",
                        "NIST": "AC-6",
                        "ISO27001": "A.9.1"
                    },
                    "remediation": "Apply least privilege permissions instead of wildcard access"
                })

    return findings