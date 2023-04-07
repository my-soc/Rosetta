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


@strawberry.enum
class WorkerActionEnum(Enum):
    Stop = 'stop'
    Status = 'status'


@strawberry.input
class DataWorkerCreateInput:
    type: WorkerTypeEnum
    count: int = 1
    destination: str
    fields: Optional[List[str]] = None


@strawberry.input
class DataWorkerActionInput:
    worker: str
    action: WorkerActionEnum


@strawberry.type
class DataWorkerOutput:
    type: WorkerTypeEnum
    worker: str
    status: str
    destination: str
    createdAt: str


@strawberry.type
class DataWorkerStatusOutput:
    worker: str
    status: str
