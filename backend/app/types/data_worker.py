import strawberry
from enum import Enum
from typing import Optional, List


@strawberry.enum
class WorkerTypeEnum(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    Incident = 'incident'


@strawberry.input
class DataWorkerCreateInput:
    type: WorkerTypeEnum
    count: int = 1
    destination: str
    fields: Optional[List[str]] = None


@strawberry.input
class DataWorkerStartInput:
    worker: str


@strawberry.input
class DataWorkerStopInput:
    worker: str


@strawberry.input
class DataWorkerStatusInput:
    worker: str


@strawberry.type
class DataWorkerOutput:
    type: str
    worker: str
    status: str
    destination: str


