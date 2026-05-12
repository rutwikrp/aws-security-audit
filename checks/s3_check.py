import boto3
from botocore.exceptions import ClientError

s3 = boto3.client('s3')


def check_s3_public_access():
    findings = []

    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        bucket_name = bucket['Name']

        try:
            public_block = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = public_block['PublicAccessBlockConfiguration']

            if not all(config.values()):
                findings.append({
                    "service": "S3",
                    "resource": bucket_name,
                    "issue": "Public access block disabled",
                    "severity": "HIGH",
                    "frameworks": {
                        "CIS": "2.1.1",
                        "NIST": "AC-3",
                        "ISO27001": "A.9"
                    }
                })

        except ClientError as e:
            findings.append({
                "service": "S3",
                "resource": bucket_name,
                "issue": f"Unable to check bucket: {str(e)}",
                "severity": "MEDIUM"
            })

    return findings