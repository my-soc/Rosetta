import matplotlib.pyplot as plt
import pandas as pd
import json

DATASET_PATH = '../data/generated/incidents.json'


def plot_data(dataset, incident_type):

    incident_data = dataset[dataset['type'] == incident_type]

    incident_counts = incident_data['owner'].value_counts()

    avg_durations = incident_data.groupby('owner')['duration'].mean()

    fig, ax = plt.subplots()
    ax.bar(incident_counts.index, incident_counts.values)
    ax.set_ylabel('Number of Incidents')
    ax2 = ax.twinx()
    ax2.plot(avg_durations.index, avg_durations.values, color='orange', marker='o')
    ax2.set_ylabel('Average Duration (days)')
    ax.set_xlabel('Analyst')
    plt.title(f'Number of {incident_type} Incidents per Analyst and Average Duration')
    plt.show()


def main():

    incident_type = input("Enter the incident type: ")

    with open(DATASET_PATH) as f:
        data = json.load(f)
    dataset = pd.DataFrame(data)

    plot_data(dataset=dataset, incident_type=incident_type)


if __name__ == '__main__':
    main()
