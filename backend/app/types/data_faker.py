import strawberry
from enum import Enum
from typing import Optional, List
from strawberry.scalars import JSON


@strawberry.enum
class FakerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    Incident = 'incident'


@strawberry.input
class DataFakerInput:
    type: FakerTypeEnum
    count: int = 1
    fields: Optional[List[str]] = None


@strawberry.type
class DataFakerOutput:
    data: List[JSON]
    type: str
    count: int
