import json
import os
import joblib
import pickle
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier

from .config import Config
from .misc import rotate_models


class KNNModelTrainer:
    def __init__(self, model_name: str, dataset_json: str):
        self.accuracy = None
        self.y_test = None
        self.y_train = None
        self.X_test = None
        self.X_train = None
        self.X = None
        self.y = None
        self.X_transformed = None
        self.y_transformed = None
        self.data_preprocessed = False
        self.data_transformed = False
        self.is_trained = False
        self.model_name = model_name
        self.dataset = dataset_json
        self.training_status = "pending"
        self.is_trained = False

    def data_preprocessing(self):
        if type(self.dataset) == str:
            dataset = json.loads(self.dataset)
        else:
            dataset = self.dataset
        try:
            dataset = pd.DataFrame(dataset)
        except Exception as e:
            return f"Error while framing the data, error: {e}"
        self.X = dataset.iloc[:, :-1]
        self.y = dataset.iloc[:, -1]
        self.data_preprocessed = True

    def data_transformation(self):
        categorical_cols = list(self.X.select_dtypes(include=['object', 'bool']).columns)
        ct = ColumnTransformer([('categorical-encoding', OneHotEncoder(), categorical_cols)], remainder='passthrough')
        try:
            self.X_transformed = ct.fit_transform(self.X)
        except Exception as e:
            return f"Error while encoding the data, error: {e}"
        os.makedirs(f'{Config.MODELS_DIR}/{self.model_name}')
        joblib.dump(ct, f'{Config.MODELS_DIR}/{self.model_name}/data_encoder.joblib')
        y_fitted = LabelEncoder().fit(self.y)
        try:
            self.y_transformed = y_fitted.transform(self.y)
        except Exception as e:
            return f"Error while encoding the target, error: {e}"
        joblib.dump(y_fitted, f'{Config.MODELS_DIR}/{self.model_name}/target_encoder.joblib')
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(self.X_transformed, self.y_transformed,
                                                                                test_size=0.2, random_state=1)
        self.data_transformed = True

    def model_training(self):
        rotate_models(models_dir=Config.MODELS_DIR, size=Config.MODELS_STORAGE_SIZE)
        if len(self.dataset) < 500:
            n_neighbors = 5
        elif 500 <= len(self.dataset) < 10000:
            n_neighbors = 10
        else:
            n_neighbors = 20
        knn = KNeighborsClassifier(n_neighbors=n_neighbors)
        try:
            knn.fit(self.X_train, self.y_train)
        except Exception as e:
            return f"Error while training the model, error: {e}"
        knn.predict(self.X_test)
        accuracy = knn.score(self.X_test, self.y_test)
        self.is_trained = True
        self.accuracy = accuracy
        pickle.dump(knn, open(f'{Config.MODELS_DIR}/{self.model_name}/knn_model.sav', 'wb'))

    @classmethod
    def test_trained_model(cls, data, model):
        if type(data) == str:
            data = json.loads(data)
        if model == 'pretrained':
            loaded_model = pickle.load(open(f'{Config.MODELS_DIR}/trained/knn_model.sav', 'rb'))
            incident_encoder = joblib.load(f'{Config.MODELS_DIR}/trained/ct.joblib')
            owner_encoder = joblib.load(f'{Config.MODELS_DIR}/trained/owner.joblib')
            encoded_incident = incident_encoder.transform(pd.DataFrame(data, index=[0]))
            prediction = loaded_model.predict(encoded_incident)

        else:
            loaded_model = pickle.load(open(f'{Config.MODELS_DIR}/{model}/knn_model.sav', 'rb'))
            incident_encoder = joblib.load(f'{Config.MODELS_DIR}/{model}/data_encoder.joblib')
            owner_encoder = joblib.load(f'{Config.MODELS_DIR}/{model}/target_encoder.joblib')
            encoded_incident = incident_encoder.transform(pd.DataFrame(data, index=[0]))
            prediction = loaded_model.predict(encoded_incident)

        return owner_encoder.inverse_transform(prediction)[0]
