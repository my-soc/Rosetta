# worker.py

import threading
import time
from classes.data_faker import DataFaker
from app.types.data_worker import WorkerTypeEnum
import socket


class DataSenderWorker:
    def __init__(self, worker_name: str, data_type: WorkerTypeEnum, count: int, destination: str, data_faker: DataFaker):
        self.thread = None
        self.worker_name = worker_name
        self.data_type = data_type
        self.count = count
        self.destination = destination
        self.data_faker = data_faker
        self.status = "Stopped"

    def start(self):
        if self.status == "Stopped":
            self.status = "Running"
            self.thread = threading.Thread(target=self.send_data, args=())
            self.thread.start()
        return self.status

    def stop(self):
        if self.status == "Running":
            self.status = "Stopped"
            self.thread.join()
        return self.status

    def send_data(self):
        while self.status == "Running" and self.count > 0:
            self.count -= 1
            if self.data_type == WorkerTypeEnum.SYSLOG:
                fake_message = self.data_faker.generate_fake_syslog_messages(1)
                print(fake_message[0])
                if 'tcp' in self.destination:
                    ip_address = self.destination.split(':')[-1]
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip_address, 514))
                    sock.sendall(fake_message[0].encode())
                    sock.close()
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.sendto(fake_message[0].encode(), (self.destination, 514))
            time.sleep(1)
        self.status = "Stopped"
