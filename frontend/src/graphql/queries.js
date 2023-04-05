import { gql } from '@apollo/client';

export const GENERATE_FAKE_DATA = gql`
  query GenerateFakeData($type: FakeDataType!, $count: Int = 1, $fields: [String]) {
    generateFakeData(requestInput: { type: $type, count: $count, fields: $fields }) {
      data
      type
      count
    }
  }
`;

export const CONVERT_LOG_ENTRY = gql`
  query ConvertLogEntry($conversionType: LogConverterType!, $logEntry: String!) {
    convertLogEntry(requestInput: { conversionType: $conversionType, logEntry: $logEntry }) {
      conversionType
      logEntry
      convertedLogEntry
    }
  }
`;

export const TRAIN_ML_MODEL = gql`
  query TrainMLModel($type: String!, $data: JSON!) {
    mlModelTrain(requestInput: { type: $type, data: $data }) {
      modelName
      trainingStatus
      accuracy
    }
  }
`;

export const TEST_ML_MODEL = gql`
  query TestMLModel($type: String!, $model: String!, $data: JSON!) {
    mlModelTest(requestInput: { type: $type, model: $model, data: $data }) {
      prediction
      accuracy
    }
  }
`;
