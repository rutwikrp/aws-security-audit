import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)  # auto-resets color after each print

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.LIGHTRED_EX,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.GREEN,
}

def generate_report(findings):

    report_name = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(report_name, 'w') as file:
        json.dump(findings, file, indent=4)

    print(f"\nReport saved: {report_name}")

    print("\nFindings Summary:\n")

    for finding in findings:

        resource = finding['resource']

        if isinstance(resource, dict):

            resource_text = (
                f"{resource.get('GroupName')} "
                f"({resource.get('GroupId')}) "
                f"VPC:{resource.get('VpcId')} "
                f"Port:{resource.get('Port')} "
                f"CIDR:{resource.get('CIDR')}"
            )

        else:
            resource_text = resource
        
        color = SEVERITY_COLORS.get(finding['severity'], Fore.WHITE)

        print(
            f"{color}[{finding['severity']}]{Style.RESET_ALL} "
            f"{finding['service']} - "
            f"{finding['issue']} - "
            f"{resource_text}"
        )