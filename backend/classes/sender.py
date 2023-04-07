import threading
import time
import datetime
import socket
import requests
import json

from classes.datafaker import DataFaker
from app.types.sender import WorkerTypeEnum

import warnings
from urllib3.exceptions import InsecureRequestWarning


class DataSenderWorker:
    def __init__(self, worker_name: str, data_type: WorkerTypeEnum, count: int, destination: str,
                 created_at: datetime):
        self.thread = None
        self.worker_name = worker_name
        self.data_type = data_type
        self.count = count
        self.destination = destination
        self.created_at = created_at
        self.status = "Stopped"

    def start(self):
        if self.status == "Stopped":
            self.thread = threading.Thread(target=self.send_data, args=())
            self.status = "Running"
            self.thread.start()
        return self.status

    def stop(self):
        if self.status == "Running":
            self.thread.join()
            self.status = "Stopped"
        return self.status

    def send_data(self):
        fake_message = None
        while self.status == "Running" and self.count > 0:
            try:
                self.count -= 1
                if self.data_type == (WorkerTypeEnum.SYSLOG or WorkerTypeEnum.CEF or WorkerTypeEnum.LEEF):
                    if self.data_type == WorkerTypeEnum.SYSLOG:
                        fake_message = DataFaker.generate_fake_syslog_messages(1)
                    if self.data_type == WorkerTypeEnum.CEF:
                        fake_message = DataFaker.generate_fake_cef_messages(1)
                    if self.data_type == WorkerTypeEnum.LEEF:
                        fake_message = DataFaker.generate_fake_leef_messages(1)
                    if 'tcp' in self.destination:
                        ip_address = self.destination.split(':')[1]
                        port = self.destination.split(':')[2]
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.connect((ip_address, int(port)))
                        sock.sendall(fake_message[0].encode())
                        sock.close()
                    else:
                        ip_address = self.destination.split(':')[1]
                        port = self.destination.split(':')[2]
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(5)
                        sock.sendto(fake_message[0].encode(), (ip_address, int(port)))
                elif self.data_type == (WorkerTypeEnum.JSON or WorkerTypeEnum.Incident):
                    fake_message = DataFaker.generate_fake_json_messages(1)
                    if '://' not in self.destination:
                        url = 'http://' + self.destination
                    else:
                        url = self.destination
                    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
                    response = requests.post(url, json=fake_message[0], timeout=(2, 5), verify=False)
                    response.raise_for_status()
            except (ConnectionRefusedError, socket.timeout, requests.exceptions.RequestException) as e:
                print(f"Connection error: {e}")
                self.status = "Connection Error"
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                self.status = "Stopped"
                break
            time.sleep(1)
        if self.status == "Running":
            self.status = "Stopped"


