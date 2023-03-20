import json


def cef_to_json(cef_log: str) -> str:
    parts = cef_log.split('|')
    if len(parts) < 6:
        raise ValueError('Invalid CEF log format')

    cef_json = {
        'version': parts[0],
        'device_vendor': parts[1],
        'device_product': parts[2],
        'device_version': parts[3],
        'device_event_class_id': parts[4],
        'name': parts[5],
        'extensions': {}
    }

    if len(parts) > 6:
        for ext in parts[6].split(' '):
            key, value = ext.split('=', 1)
            cef_json['extensions'][key] = value

    return cef_json.__str__()
