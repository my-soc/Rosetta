import strawberry
from typing import Optional
from strawberry.scalars import JSON


@strawberry.input
class ModelTrainInput:
    data: JSON
    type: str


@strawberry.input
class ModelTestInput:
    data:  JSON
    model: str
    type: str


@strawberry.type
class ModelOutput:
    model_name: str
    training_status: str
    accuracy: Optional[str]


@strawberry.type
class ModelPrediction:
    prediction: str
    accuracy: Optional[str]