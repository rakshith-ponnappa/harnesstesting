import socket
import boto3
import dns.resolver

# Initialize boto3 EC2 resource
ec2 = boto3.resource('ec2')
elbv2 = boto3.client('elbv2')
ec2_client = boto3.client('ec2')

def generate_green_hosts_file():
    # Entries pointing to WAF-APP
    alb_name = 'ubuntu-app-green-waf-planhub-287873929.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)

    print(f"\n### Paste FOLLOWING to your hosts file located at:")
    print(f"### Windows: C:\\Windows\\System32\\drivers\\etc\\hosts ")
    print(f"### MacOSX:/etc/hosts \n")
    print(f"# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  app.planhub.com")
    print(f"{ip_alb}  access.planhub.com")
    print(f"{ip_alb}  subcontractor.planhub.com")
    print(f"{ip_alb}  supplier.planhub.com")
    print(f"{ip_alb}  generalcontractor.planhub.com")
    print(f"{ip_alb}  takeoff.planhub.com")

    alb_name = 'ubuntu-api-green-waf-planhub-1160386651.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  api.planhub.com")

    alb_name = 'ubuntu-admin-green-2060211592.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  admin.planhub.com")

    alb_name = 'ubuntu-admin-api-green-1063202688.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  adminapi.planhub.com")

    alb_name = 'internal-alb-sciapi-green-private-1946634648.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  sci.planhub.com")
    print(f"{ip_alb}  sciapi.planhub.com")

    alb_name = 'takeoff-alb-green-1528082587.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  takeoffapi.planhub.com")


def generate_blue_hosts_file():
    # Entries pointing to WAF-APP
    alb_name = 'ubuntu-app-waf-planhub-1524637417.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)

    print(f"\n### Paste FOLLOWING to your hosts file located at:")
    print(f"### Windows: C:\\Windows\\System32\\drivers\\etc\\hosts ")
    print(f"### MacOSX:/etc/hosts \n")
    print(f"# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  app.planhub.com")
    print(f"{ip_alb}  access.planhub.com")
    print(f"{ip_alb}  subcontractor.planhub.com")
    print(f"{ip_alb}  supplier.planhub.com")
    print(f"{ip_alb}  generalcontractor.planhub.com")
    print(f"{ip_alb}  takeoff.planhub.com")

    alb_name = 'ubuntu-api-waf-planhub-2036842260.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  api.planhub.com")

    alb_name = 'ubuntu-admin-api-1338592854.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  admin.planhub.com")

    alb_name = 'ubuntu-admin-api-1338592854.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  adminapi.planhub.com")

    alb_name = 'internal-alb-sciapi-private-1629289029.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  sci.planhub.com")
    print(f"{ip_alb}  sciapi.planhub.com")

    alb_name = 'alb-tkl-app-planhub-1572631107.us-west-2.elb.amazonaws.com'
    ip_alb = socket.gethostbyname(alb_name)
    print(f"\n# Name={alb_name} --> {ip_alb}")
    print(f"{ip_alb}  takeoffapi.planhub.com")

def get_instance_info_by_name(ec2_name):
    instances = ec2.instances.filter(Filters=[
        {'Name': 'tag:Name', 'Values': [ec2_name]}
    ])
    for instance in instances:
        # Find the Name tag to get the instance's name
        name_tag = next((tag['Value'] for tag in instance.tags if tag['Key'] == 'Name'), "Unknown")
        print(f"Instance ID: {instance.id}, Name: {name_tag}, State: {instance.state['Name']} , Private IP: {instance.private_ip_address}")


def generate_servers_info(environment):
    if environment:
        postfix = f"-{environment}"
    else:
        postfix = ""
    server_names = [
        "ec2-prod-web1-ubuntu73",
        "ec2-prod-web2-ubuntu73",
        "ec2-prod-web-02w-AdminUbuntu",
        "ec2-prod-mailer",
        "ec2-tkl-prod-uw-01",
        "ec2-prod-sci-api-uw2-01",
    ]

    for server_name in server_names:
        ec2_name = server_name + postfix
        get_instance_info_by_name(ec2_name)


def generate_hosts_file(environment):
    alb_postfix = f"-{environment}"
    albs = {
        'ubuntu-app': 'app.planhub.com access.planhub.com subcontractor.planhub.com supplier.planhub.com generalcontractor.planhub.com takeoff.planhub.com',
        'ubuntu-api': 'api.planhub.com',
        'ubuntu-admin': 'admin.planhub.com',
        'ubuntu-admin-api': 'adminapi.planhub.com',
        'internal-alb-sciapi-private': 'sci.planhub.com sciapi.planhub.com',
        'takeoff-alb': 'takeoffapi.planhub.com',
    }

    print(f"\n### Paste the following to your hosts file for the {environment} environment:")
    resolver = dns.resolver.Resolver()
    for alb_name, domains in albs.items():
        full_alb_name = f"{alb_name}{alb_postfix}.us-west-2.elb.amazonaws.com"
        try:
            answers = resolver.resolve(full_alb_name, 'A')
            for ip in answers:
                for domain in domains.split():
                    print(f"{ip}  {domain}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"DNS lookup failed for {full_alb_name}")

def truncate_arn(arn):
    """Truncate the ARN to show only the last part for brevity."""
    parts = arn.split(':')
    return ':'.join(parts[:3]) + '...:' + parts[-1]

def get_instance_name(instance_id):
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    for reservation in response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    return tag['Value']
    return "Unknown"  # If no Name tag is found

def truncate_arn(arn):
    """Truncate the ARN to show only the last part for brevity."""
    parts = arn.split(':')
    return ':'.join(parts[:3]) + '...:' + parts[-1]

def list_elbs(environment):
    elb_names = {
        'green': [
            'alb-sciapi-green-private',
            'ubuntu-api-green-waf-planhub',
            'ubuntu-admin-api-green',
            'ubuntu-admin-green',
            'ubuntu-app-green-waf-planhub',
            'takeoff-alb-green'
        ],
        'blue': [
            'alb-sciapi-private',
            'ubuntu-api-waf-planhub',
            'ubuntu-admin-api',
            'ubuntu-admin',
            'ubuntu-app-waf-planhub'
        ]
    }[environment]

    print(f"\nListing {environment} ELBs:\n")
    header = "{:<30} {:<50} {:<30} {:<30} {:<15}".format("ELB Name", "ARN (truncated)", "Target Group", "Instance Name", "Health Status")
    print(header)
    print("-" * len(header))

    next_token = ''
    while True:
        if next_token:
            response = elbv2.describe_load_balancers(Names=elb_names, Marker=next_token)
        else:
            response = elbv2.describe_load_balancers(Names=elb_names)

        for elb in response['LoadBalancers']:
            elb_name = elb['LoadBalancerName']
            elb_arn = truncate_arn(elb['LoadBalancerArn'])

            target_groups = elbv2.describe_target_groups(LoadBalancerArn=elb['LoadBalancerArn'])
            for tg in target_groups['TargetGroups']:
                tg_name = tg['TargetGroupName']
                tg_arn = truncate_arn(tg['TargetGroupArn'])

                target_health_descriptions = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                for target_health in target_health_descriptions['TargetHealthDescriptions']:
                    instance_id = target_health['Target']['Id']
                    instance_name = get_instance_name(instance_id)
                    health_status = target_health['TargetHealth']['State']

                    print("{:<30} {:<50} {:<30} {:<30} {:<15}".format(
                        elb_name, elb_arn, tg_name, instance_name, health_status))

        next_token = response.get('NextMarker', '')
        if not next_token:
            break
def list_blue_target_groups():
    elb_names = [
        'alb-sciapi-private',
        'ubuntu-api-waf-planhub',
        'ubuntu-admin-api',
        'ubuntu-admin',
        'ubuntu-app-waf-planhub'
    ]

    print("\nListing Blue Target Groups and Associated Instances:\n")
    header = "{:<30} {:<30} {:<30} {:<15}".format("Target Group", "Instance Name", "Instance ID", "Health Status")
    print(header)
    print("-" * len(header))

    for elb_name in elb_names:
        try:
            response = elbv2.describe_load_balancers(Names=[elb_name])
            for elb in response['LoadBalancers']:
                target_groups = elbv2.describe_target_groups(LoadBalancerArn=elb['LoadBalancerArn'])
                for tg in target_groups['TargetGroups']:
                    tg_name = tg['TargetGroupName']
                    target_health_descriptions = elbv2.describe_target_health(TargetGroupArn=tg['TargetGroupArn'])
                    for target_health in target_health_descriptions['TargetHealthDescriptions']:
                        instance_id = target_health['Target']['Id']
                        instance_name = get_instance_name(instance_id)
                        health_status = target_health['TargetHealth']['State']
                        print("{:<30} {:<30} {:<30} {:<15}".format(tg_name, instance_name, instance_id, health_status))
        except Exception as e:
            print(f"Error processing {elb_name}: {e}")

if __name__ == '__main__':
    generate_hosts_file('blue')
    generate_servers_info('blue')
    generate_servers_info('')
    generate_green_hosts_file()
    generate_blue_hosts_file()
    print("Generating information for the green environment...")
    list_elbs('green')
    print("\nGenerating information for the blue environment...")
    list_elbs('blue')
    print("\nListing only Blue Target Groups and their associated instances:")
    list_blue_target_groups()
