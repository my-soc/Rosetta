import datetime
import time
from enum import Enum
import json
from typing import Optional, List, NewType, Union
import strawberry
from classes.events_converters import EventsConverter
from classes.data_faker import DataFaker
from classes.model_trainers import KNNModelTrainer
from classes.data_sender_worker import DataSenderWorker
from app.types.data_faker import FakerTypeEnum, DataFakerInput, DataFakerOutput
from app.types.data_converter import ConverterTypeEnum, ConverterInput, ConverterOutput
from app.types.ml_trainer import ModelTrainInput, ModelTestInput, ModelOutput, ModelPrediction
from app.types.data_worker import WorkerTypeEnum, DataWorkerCreateInput, DataWorkerStartInput, DataWorkerStopInput,\
    DataWorkerStatusInput, DataWorkerOutput

from typing import Dict, Any
faker = DataFaker()
workers = {}


@strawberry.type
class Query:
    @strawberry.field
    def generate_fake_data(self, request_input: DataFakerInput) -> DataFakerOutput:
        data = []
        if request_input.type == FakerTypeEnum.SYSLOG:
            data = faker.generate_fake_syslog_messages(request_input.count)
        elif request_input.type == FakerTypeEnum.CEF:
            data = faker.generate_fake_cef_messages(request_input.count)
        elif request_input.type == FakerTypeEnum.LEEF:
            data = faker.generate_fake_leef_messages(request_input.count)
        elif request_input.type == FakerTypeEnum.WINEVENT:
            data = faker.generate_fake_winevent_messages(request_input.count)
        elif request_input.type == FakerTypeEnum.JSON:
            data = faker.generate_fake_json_messages(request_input.count)
        elif request_input.type == FakerTypeEnum.Incident:
            data = faker.generate_fake_incidents(request_input.count, request_input.fields)

        return DataFakerOutput(
            data=data,
            type=request_input.type,
            count=request_input.count
        )

    @strawberry.field
    def convert_log_entry(self, request_input: ConverterInput) -> ConverterOutput:
        if request_input.conversion_type == ConverterTypeEnum.CEF_JSON:
            converted_log_entry = EventsConverter.cef_to_json(cef_log=request_input.log_entry)
        elif request_input.conversion_type == ConverterTypeEnum.CEF_LEEF:
            converted_log_entry = EventsConverter.cef_to_leef(cef_log=request_input.log_entry)
        else:
            raise ValueError("Unsupported conversion type")

        return ConverterOutput(conversion_type=request_input.conversion_type, log_entry=request_input.log_entry,
                               converted_log_entry=converted_log_entry)

    @strawberry.field
    def ml_model_train(self, request_input: ModelTrainInput) -> ModelOutput:
        time.sleep(1)
        now = datetime.datetime.now()
        model_name = f"model_{now.strftime('%Y%m%d%H%M%S')}"
        if request_input.type == 'KNN':
            model = KNNModelTrainer(model_name=model_name, dataset_json=request_input.data)
            model.data_preprocessing()
            if model.data_preprocessed:
                model.data_transformation()
                if model.data_transformed:
                    model.model_training()
                    if model.is_trained:
                        return ModelOutput(model_name=model_name, training_status='Model-Trained',
                                           accuracy=model.accuracy)
                    else:
                        return ModelOutput(model_name=model_name, training_status='Training-Failed', accuracy='N/A')
                else:
                    return ModelOutput(model_name=model_name, training_status='Transformation-Failed', accuracy='N/A')
            else:
                return ModelOutput(model_name=model_name, training_status='Preprocessing-Failed', accuracy='N/A')
        else:
            return ModelOutput(model_name='Model not available.', training_status='N/A', accuracy='N/A')

    @strawberry.field
    def ml_model_test(self, request_input: ModelTestInput) -> ModelPrediction:
        if request_input.type == "KNN":
            prediction = KNNModelTrainer.test_trained_model(data=request_input.data, model=request_input.model)
            return ModelPrediction(prediction=prediction, accuracy='N/A')
        else:
            return ModelPrediction(prediction="Model is not supported.", accuracy='N/A')

    @strawberry.field
    def data_worker_create(self, request_input: DataWorkerCreateInput) -> DataWorkerOutput:
        now = datetime.datetime.now()
        worker_name = f"worker_{now.strftime('%Y%m%d%H%M%S')}"
        data_worker = DataSenderWorker(worker_name=worker_name, data_type=request_input.type, count=request_input.count,
                                       destination=request_input.destination, data_faker=faker)
        workers[worker_name] = data_worker
        data_worker.start()

        return DataWorkerOutput(type=data_worker.data_type, worker=data_worker.worker_name, status=data_worker.status,
                                destination=data_worker.destination)

    @strawberry.field
    def data_worker_list(self) -> List[DataWorkerOutput]:
        workers_data = []
        for worker in workers.keys():
            print(workers[worker].data_type)
            workers_data.append(DataWorkerOutput(type="workers[worker].data_type", worker="workers[worker].worker_name",
                                                 status="workers[worker].status",
                                                 destination="workers[worker].destination"))
        return workers_data


schema = strawberry.Schema(query=Query)
