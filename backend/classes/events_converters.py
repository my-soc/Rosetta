import xml.etree.ElementTree as Et


class EventsConverter:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def cef_to_json(cls, cef_log: str) -> str:
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

    @classmethod
    def cef_to_leef(cls, cef_log: str) -> str:
        parts = cef_log.split('|')
        if len(parts) < 6:
            raise ValueError('Invalid CEF log format')

        leef_dict = {
            'LEEF': '1.0',
            'Vendor': parts[1],
            'Product': parts[2],
            'Version': parts[3],
            'EventID': parts[4],
            'Name': parts[5]
        }

        if len(parts) > 6:
            for ext in parts[6].split(' '):
                key, value = ext.split('=', 1)
                leef_dict[key] = value

        leef_str = '!'.join([f"{k}={v}" for k, v in leef_dict.items()])
        return leef_str
