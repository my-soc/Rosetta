import pickle
import joblib
import pandas as pd

MODEL_PATH = '../models/knn_model.sav'
INC_ENCODER_PATH = '../models/ct.joblib'
OWNER_ENCODER_PATH = '../models/owner.joblib'


def predict_owner(model, incident, incident_encoder, owner_encoder):
    new_X = incident_encoder.transform(pd.DataFrame(incident, index=[0]))
    prediction = model.predict(new_X)
    return owner_encoder.inverse_transform(prediction)[0]


def main():

    incident_type = input("Enter the incident type: ")
    duration = input("Enter the duration (in days): ")

    incident = {
        "type": incident_type,
        "duration": duration
    }

    # load the model and encoders
    loaded_model = pickle.load(open(MODEL_PATH, 'rb'))
    ct = joblib.load(INC_ENCODER_PATH)
    owner_encoder = joblib.load(OWNER_ENCODER_PATH)

    owner = predict_owner(model=loaded_model, incident=incident, incident_encoder=ct, owner_encoder=owner_encoder)

    print("Suggested owner: " + owner)


if __name__ == '__main__':
    main()
