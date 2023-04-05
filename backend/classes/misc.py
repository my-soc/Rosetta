import os
import shutil
from .config import Config
from datetime import datetime
import re


def rotate_models():
    match = re.match(r"(\d+)\s*(\w+)", Config.MODELS_STORAGE_SIZE, re.IGNORECASE)
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

    folders = [f for f in os.listdir(Config.MODELS_DIR) if
               os.path.isdir(os.path.join(Config.MODELS_DIR, f)) and f.startswith('model_')]
    total_size = sum(
        sum(os.path.getsize(os.path.join(Config.MODELS_DIR, folder, f)) for f in
            os.listdir(os.path.join(Config.MODELS_DIR, folder)))
        for folder in folders)
    if total_size > max_size_bytes:
        folders = [(f, datetime.strptime(f.split("_")[1], '%Y%m%d%H%M%S')) for f in folders]
        folders.sort(key=lambda x: x[1])
        while total_size > max_size_bytes:
            folder_to_delete = folders[0][0]
            total_size -= sum(os.path.getsize(os.path.join(Config.MODELS_DIR, folder_to_delete, f)) for f in
                              os.listdir(os.path.join(Config.MODELS_DIR, folder_to_delete)))
            shutil.rmtree(os.path.join(Config.MODELS_DIR, folder_to_delete))
            folders.pop(0)

