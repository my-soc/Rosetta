import yaml


class Config:
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)

    MODELS_STORAGE_SIZE = config['models_storage']
    MODELS_DIR = config['models_dir']
