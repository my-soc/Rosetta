import os
import shutil
import re
import json
from datetime import datetime


def rotate_models(models_dir, size):
    match = re.match(r"(\d+)\s*(\w+)", size, re.IGNORECASE)
    if not match:
        raise ValueError("Invalid max size in config file")
    max_size, unit = match.groups()
    if unit.lower() == "kb" or unit.lower() == "k":
        max_size_bytes = int(max_size) * 1024
    elif unit.lower() == "mb" or unit.lower() == "m":
        max_size_bytes = int(max_size) * 1024 * 1024
    elif unit.lower() == "gb" or unit.lower() == "g":
        max_size_bytes = int(max_size) * 1024 * 1024 * 1024
    else:
        raise ValueError(f"Unknown unit '{unit}' in config file")

    folders = [f for f in os.listdir(models_dir) if
               os.path.isdir(os.path.join(models_dir, f)) and f.startswith('model_')]
    total_size = sum(
        sum(os.path.getsize(os.path.join(models_dir, folder, f)) for f in
            os.listdir(os.path.join(models_dir, folder)))
        for folder in folders)
    if total_size > max_size_bytes:
        folders = [(f, datetime.strptime(f.split("_")[1], '%Y%m%d%H%M%S')) for f in folders]
        folders.sort(key=lambda x: x[1])
        while total_size > max_size_bytes:
            folder_to_delete = folders[0][0]
            total_size -= sum(os.path.getsize(os.path.join(models_dir, folder_to_delete, f)) for f in
                              os.listdir(os.path.join(models_dir, folder_to_delete)))
            shutil.rmtree(os.path.join(models_dir, folder_to_delete))
            folders.pop(0)


def rotate_workers(workers_dir, number):
    with open(f'{workers_dir}/workers.json', 'r+') as f:
        try:
            workers = json.load(f)
        except json.JSONDecodeError:
            workers = []
        if len(workers) >= number:
            oldest_stopped_worker = None
            for worker in workers:
                if worker['status'] == 'Stopped' and (
                        not oldest_stopped_worker or worker['created_at'] < oldest_stopped_worker['created_at']):
                    oldest_stopped_worker = worker
            if oldest_stopped_worker:
                workers.remove(oldest_stopped_worker)
            else:
                return 'All workers are busy, you need to stop a running worker before starting a new one.'
