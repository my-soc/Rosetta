from pydantic import BaseModel
import strawberry
from .converters import cef_to_json


@strawberry.type
class ConvertCEFOutput:
    json_log: str


@strawberry.type
class Query:
    @strawberry.field
    def convert_cef_to_json(self, cef_log: str) -> ConvertCEFOutput:
        json_log = cef_to_json(cef_log)
        return ConvertCEFOutput(json_log=json_log)


schema = strawberry.Schema(query=Query)
