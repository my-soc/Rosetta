import datetime
from enum import Enum
from typing import Optional, List, Union, Dict, Any
from strawberry.scalars import JSON
import strawberry
from ..modules.events_converters import EventsConverter
from ..modules.data_faker import DataFaker
from ..modules.model_trainers import KNNModelTrainer

faker = DataFaker()

# ML Trainer Schema


@strawberry.input
class ModelTrainInput:
    data: str
    type: str


@strawberry.input
class ModelTestInput:
    data:  JSON
    model: str
    type: str


@strawberry.type
class Model:
    model_name: str
    training_status: str
    accuracy: Optional[str]


@strawberry.type
class ModelPrediction:
    prediction: str
    accuracy: Optional[str]

# Faker Schema


@strawberry.enum
class FakeDataType(Enum):
    SYSLOG = 'syslog'
    CEF = 'cef'
    LEEF = 'leef'
    WINEVENT = 'winevent'
    JSON = 'json'
    Incident = 'incident'


@strawberry.input
class FakerDataInput:
    type: FakeDataType
    count: int = 1
    fields: Optional[List[str]] = None


@strawberry.type
class FakerDataOutput:
    data: List[JSON]
    type: str
    count: int

# Converter Schema


@strawberry.enum
class LogConverterType(Enum):
    CEF_JSON = 'cef_to_json'
    CEF_LEEF = 'cef_to_leef'


@strawberry.input
class LogConverterInput:
    conversion_type: LogConverterType
    log_entry: str


@strawberry.type
class LogConverterOutput:
    conversion_type: str
    log_entry: str
    converted_log_entry: str


@strawberry.type
class Query:
    @strawberry.field
    def generate_fake_data(self, request_input: FakerDataInput) -> FakerDataOutput:
        data = []
        if request_input.type == FakeDataType.SYSLOG:
            data = faker.generate_fake_syslog_messages(request_input.count)
        elif request_input.type == FakeDataType.CEF:
            data = faker.generate_fake_cef_messages(request_input.count)
        elif request_input.type == FakeDataType.LEEF:
            data = faker.generate_fake_leef_messages(request_input.count)
        elif request_input.type == FakeDataType.WINEVENT:
            data = faker.generate_fake_winevent_messages(request_input.count)
        elif request_input.type == FakeDataType.JSON:
            data = faker.generate_fake_json_messages(request_input.count)
        elif request_input.type == FakeDataType.Incident:
            data = faker.generate_fake_incidents(request_input.count, request_input.fields)

        return FakerDataOutput(
            data=data,
            type=request_input.type,
            count=request_input.count
        )

    @strawberry.field
    def convert_log_entry(self, request_input: LogConverterInput) -> LogConverterOutput:
        if request_input.conversion_type == LogConverterType.CEF_JSON:
            converted_log_entry = EventsConverter.cef_to_json(cef_log=request_input.log_entry)
        elif request_input.conversion_type == LogConverterType.CEF_LEEF:
            converted_log_entry = EventsConverter.cef_to_leef(cef_log=request_input.log_entry)
        else:
            raise ValueError("Unsupported conversion type")

        return LogConverterOutput(conversion_type=request_input.conversion_type, log_entry=request_input.log_entry,
                                  converted_log_entry=converted_log_entry)

    @strawberry.field
    def ml_model_train(self, request_input: ModelTrainInput) -> Model:
        now = datetime.datetime.now()
        model_name = f"model_{now.strftime('%Y%m%d_%H%M%S')}"
        if request_input.type == 'KNN':
            model = KNNModelTrainer(model_name=model_name, dataset_json=request_input.data)
            model.data_preprocessing()
            if model.data_preprocessed:
                print ('processing done')
                model.data_transformation()
                if model.data_transformed:
                    print('transformation done')
                    model.model_training()
                    if model.is_trained:
                        print('training done')
                        return Model(model_name=model_name, training_status='Model-Trained', accuracy=model.accuracy)
                    else:
                        return Model(model_name=model_name, training_status='Training-Failed', accuracy='N/A')
                else:
                    return Model(model_name=model_name, training_status='Transformation-Failed', accuracy='N/A')
            else:
                return Model(model_name=model_name, training_status='Preprocessing-Failed', accuracy='N/A')
        else:
            return Model(model_name='Model not available.', training_status='N/A', accuracy='N/A')

    @strawberry.field
    def ml_model_test(self, request_input: ModelTestInput) -> ModelPrediction:
        if request_input.type == "KNN":
            prediction = KNNModelTrainer.test_trained_model(data=request_input.data, model=request_input.model)
            return ModelPrediction(prediction=prediction, accuracy='N/A')
        else:
            return ModelPrediction(prediction="Model is not supported.", accuracy='N/A')


schema = strawberry.Schema(query=Query)
