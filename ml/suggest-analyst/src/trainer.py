import json
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier

import pandas as pd
import pickle
import joblib

DATASET_PATH = '../data/generated/incidents.json'

print("Pre-processing the dataset")

# Importing the dataset
with open(DATASET_PATH) as f:
    data = json.load(f)
dataset = pd.DataFrame(data)

# Separate features (X) from target variable (y)
X = dataset.drop(columns=['id', 'owner'])
y = dataset['owner']
joblib.dump(LabelEncoder(), '../models/owner.joblib')

# Encode the categorical and variable features
categorical_cols = list(X.select_dtypes(include=['object']).columns)
ct = ColumnTransformer([('categorical-encoding', OneHotEncoder(), categorical_cols)],
                       remainder='passthrough')
X = ct.fit_transform(X)
y_fitted = LabelEncoder().fit(dataset['owner'])
y = y_fitted.transform(dataset['owner'])
joblib.dump(y_fitted, '../models/owner.joblib')

# Splitting the dataset into the Training set and Test set
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1)

print("Training on the dataset")
# Training the KNN model
knn = KNeighborsClassifier(n_neighbors=20)
knn.fit(X_train, y_train)

# Predicting the owners for the test set
y_pred = knn.predict(X_test)

# Calculating the accuracy of the model
accuracy = knn.score(X_test, y_test)
print("Accuracy:", accuracy)

# save the model and encoders to a file
joblib.dump(ct, '../models/ct.joblib')

pickle.dump(knn, open('../models/knn_model.sav', 'wb'))
print("Model is saved to disk")
