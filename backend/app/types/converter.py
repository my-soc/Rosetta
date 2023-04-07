import strawberry
from enum import Enum


@strawberry.enum
class ConverterTypeEnum(Enum):
    CEF_JSON = 'cef_to_json'
    CEF_LEEF = 'cef_to_leef'


@strawberry.input
class ConverterInput:
    conversion_type: ConverterTypeEnum
    log_entry: str


@strawberry.type
class ConverterOutput:
    conversion_type: str
    log_entry: str
    converted_log_entry: str
