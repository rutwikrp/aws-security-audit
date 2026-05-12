import boto3

ec2 = boto3.client('ec2')


def check_security_groups():
    findings = []

    response = ec2.describe_security_groups()

    for sg in response['SecurityGroups']:
        instances = ec2.describe_network_interfaces(
                        Filters=[
                            {
                                'Name': 'group-id',
                                'Values': [sg['GroupId']]
                            }
                        ]
                    )
        attachment_count = len(instances['NetworkInterfaces'])

        for permission in sg.get('IpPermissions', []):

            for ip_range in permission.get('IpRanges', []):

                if ip_range.get('CidrIp') == '0.0.0.0/0':

                    from_port = permission.get('FromPort')

                    if from_port in [22, 3389]:

                        findings.append({
                            "attached_resources": attachment_count,
                            "service": "EC2",
                            "resource": {
                            "GroupId": sg['GroupId'],
                            "GroupName": sg['GroupName'],
                            "VpcId": sg.get('VpcId'),
                            "Port": from_port,
                            "CIDR": ip_range.get('CidrIp')
                        },
                            "issue": f"Port {from_port} open to internet",
                            "severity": "HIGH",
                            "frameworks": {
                                "CIS": "4.1",
                                "NIST": "SC-7",
                                "ISO27001": "A.13"
                            }
                        })

    return findings