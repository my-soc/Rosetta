import yaml


class Config:
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)

    MODELS_DIR = config.get('ml_training', {}).get('directory', 'models')
    MODELS_STORAGE_SIZE = config.get('ml_training', {}).get('storage', '500M')

    WORKERS_NUMBER = config.get('workers', {}).get('number', '25')

    LOGGING_DIR = config.get('logging', {}).get('directory', 'logs')
    LOGGING_STORAGE_SIZE = config.get('logging', {}).get('storage', '10M')
    LOGGING_TRUNCATE_LIMIT = config.get('logging', {}).get('truncate', '100')
