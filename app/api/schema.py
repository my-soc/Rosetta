import strawberry
from ..modules.events_converters import EventsConverter
from ..modules.events_faker import EventsFaker

faker = EventsFaker()


@strawberry.type
class FakeLogMessages:
    syslog: str
    cef: str
    leef: str
    winevent: str
    json: str


@strawberry.type
class LogConverter:
    conversion_type: str
    log_entry: str
    converted_log_entry: str


@strawberry.type
class Query:
    @strawberry.field
    def generate_fake_messages(self, info) -> FakeLogMessages:
        # A query to generate random log messages.
        requested_fields = info.field_nodes[0].selection_set.selections
        has_requested_fields = any(selection.name.value != "__typename" for selection in requested_fields)

        if not has_requested_fields:
            raise ValueError("At least one subfield must be specified in the request.")

        return FakeLogMessages(
            syslog=faker.generate_fake_syslog_message(),
            cef=faker.generate_fake_cef_message(),
            leef=faker.generate_fake_leef_message(),
            winevent=faker.generate_fake_winevent_message(),
            json=faker.generate_fake_json_message()
        )

    @strawberry.field
    def convert_log_entry(self, conversion_type: str, log_entry: str) -> LogConverter:
        if conversion_type == "cef_to_json":
            converted_log_entry = EventsConverter.cef_to_json(cef_log=log_entry)
        elif conversion_type == "cef_to_leef":
            converted_log_entry = EventsConverter.cef_to_leef(cef_log=log_entry)
        else:
            raise ValueError("Unsupported conversion type")

        return LogConverter(conversion_type=conversion_type, log_entry=log_entry, converted_log_entry=converted_log_entry)


schema = strawberry.Schema(query=Query)
