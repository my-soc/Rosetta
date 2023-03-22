[![made-with](https://img.shields.io/badge/Built%20with-grey)]()
[![made-with-Python](https://img.shields.io/badge/Python-blue)](https://www.python.org/)
[![made-with-FastAPI](https://img.shields.io/badge/FastAPI-green)](https://fastapi.tiangolo.com/)
[![made-with-GraphQL](https://img.shields.io/badge/GraphQL-red)](https://graphql.org/)
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

<img  align="left" src="img/logo.svg" width="30%" alt="Rosetta"> 

# Rosetta
Rosetta is a tiny GraphQL API service to fake log messages in different formats and convert between those formats.

## Installation

- Clone the repository.
- Install the required packages using `pip install -r requirements.txt`. 
- Start the server using  `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload.`

## Run Your Container

- Build the image `docker build -t rosetta`
- Run the image `docker run --name rosetta -p 8000:8000 -d rosetta`

## Run a Ready Container
- You can run a ready container: `docker run aymanam/rosetta:latest`

## Available Queries

You can use the built-in GraphiQL in-browser tool `http://[rosseta-address]:[port]` for writing, validating, and
testing your GraphQL queries. Type queries into this side of the screen, and you will see intelligent typeaheads aware of the current GraphQL type schema and live syntax and  validation errors highlighted within the text.

You can also click on the Explorer page to view a list of the available queries:

### Log Converters
Converter queries can be used to convert a log from one format to another.

#### convertCefToJson
***
A query to convert cef code line to json dictionary.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{
    "query": "query ConvertCefToJson($cefLog: String!) { convertCefToJson(cefLog: $cefLog) { jsonLog } }",
    "variables": { "cefLog": "CEF:0|PANW|FW|v10|Class1b|Traffic|src=10.0.0.1 dst=2.2.2.2 spt=1232" }
}'
```
Example output:
```json
{
    "data": {
        "convertCefToJson": {
            "jsonLog": "{'version': 'CEF:0', 'device_vendor': 'PANW', 'device_product': 'FW', 'device_version': 'v10', 'device_event_class_id': 'Class1b', 'name': 'Traffic', 'extensions': {'src': '10.0.0.1', 'dst': '2.2.2.2', 'spt': '1232'}}"
        }
    }
}
```

### Log Fakers
Faker queries to generate fake logs in different log formats.

#### generateFakeSyslogMessage
***
A query to generate random syslog message, the message represent a fake risky command  execution on a unix server.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{ "query": "{ generateFakeJsonMessage }" }'
```
Example output:
```json
{
    "data": {
        "generateFakeSyslogMessage": "Jan 26 23:34:40 email-18.leonard.com sudo[16150]: pkramer : COMMAND ; cat /etc/shadow"
    }
}
```


#### generateFakeWineventMessage
***
A query to generate random windows security event message, the message represent a fake user action that simulates an attack technique like Credential Dumping, Process Injection and more.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{ "query": "{ generateFakeWineventMessage }" }'
```
Example output:
```json
{
    "data": {
        "generateFakeWineventMessage": "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"1c20189b-d61e-419d-9b50-3e06683f5acb\"/><EventID>4624</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2023-02-15T15:47:58\"/><EventRecordID>8697</EventRecordID><Correlation/><Execution ProcessID=\"4883\" ThreadID=\"7882\" Channel=\"Security\"/><Computer>web-73.frost-thompson.org</Computer><Security UserID=\"b696f2a8-0c9b-4fc7-8c47-04e8ea2282a2\"/><EventData><Data Name=\"SubjectUserSid\">8a52fb03-3de2-47ba-a4fe-e91afaefd111</Data><Data Name=\"SubjectUserName\">johncollins</Data><Data Name=\"SubjectDomainName\">russell.com</Data><Data Name=\"SubjectLogonId\">2476</Data><Data Name=\"LogonType\">3</Data><Data Name=\"TargetUserSid\">e49e06a3-a2cf-4d02-9bd6-16e657b5d58d</Data><Data Name=\"TargetUserName\">joyce31</Data><Data Name=\"TargetDomainName\">anderson.com</Data><Data Name=\"ProcessName\">change.odt</Data><Data Name=\"ProcessId\">8903</Data><Data Name=\"DestinationLogonId\">3475</Data><Data Name=\"SourceNetworkAddress\">109.128.234.80</Data><Data Name=\"SourcePort\">7295</Data><Data Name=\"LogonGuid\">fe2f5084-1716-41cc-b413-298ed5a2c80b</Data><Data Name=\"TransmittedServices\">Free far discussion.</Data></EventData></Event>"
    }
}
```


#### generateFakeCefMessage
***
A query to generate random cef message, the message represent a fake firewall log of allowed or denied access to a malicious ip address.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{ "query": "{ generateFakeCefMessage }" }'
```
Example output:
```json
{
    "data": {
        "generateFakeCefMessage": "CEF:0|Jenkins PLC|Firewall|1.0.6|ec412a83-5e71-444b-b513-5a217cb4c1a5|Firewall DENY UDP traffic from 48.200.150.28:37022 to 45.190.124.34:21821|3|src=48.200.150.28 spt=37022 dst=45.190.124.34 dpt=21821 proto=UDP act=DENY"
    }
}
```


#### generateFakeJsonMessage
***
A query to generate random json event message, the message represent a fake vulnerability  found event.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{ "query": "{ generateFakeJsonMessage }" }'
```
Example output:
```json
{
    "data": {
        "generateFakeJsonMessage": "{'event_type': 'vulnerability_discovered', 'timestamp': datetime.datetime(2023, 2, 4, 19, 22, 46), 'host_ip': '10.174.170.76', 'severity': 3, 'cve_id': 'CVE-2022-23456', 'cve_description': 'An attacker could exploit this vulnerability by sending a crafted TCP packet to an affected device on a TCP port that is listening.', 'service': 'Cisco IOS XR Software', 'service_version': '7.1'}"
    }
}
```


#### generateFakeLeefMessage
***
A query to generate random leef message, the message represent a fake web request log, a random request URL is generated to simulated one of the OWASP10 attack techniques.

##### A curl example:

```bash
curl --location 'http://localhost:8000' \
--header 'Content-Type: application/json' \
--data '{ "query": "{ generateFakeLeefMessage }" }'
```
Example output:
```json
{
    "data": {
        "generateFakeLeefMessage": "LEEF:1.0|Leaf|Payment Portal|1.0|160.39.241.18|27.36.9.144|de:b4:cf:c2:02:8d|aa:8b:2d:6b:c1:3c|src=136.97.179.102 dst=44.62.206.110 spt=10418 dpt=443 request=https://example.com/index.php method=GET proto=HTTP/1.1 status=500 request_size=869 response_size=3851 user_agent=Mozilla/5.0 (iPad; CPU iPad OS 10_3_3 like Mac OS X) AppleWebKit/532.0 (KHTML, like Gecko) FxiOS/9.1o3896.0 Mobile/72X248 Safari/532.0"
    }
}
```