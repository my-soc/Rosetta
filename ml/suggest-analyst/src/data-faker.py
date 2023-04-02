import argparse
import random
import json

INCIDENT_SEVERITIES_PATH = '../data/features/severities.txt'
INCIDENT_TYPES_PATH = '../data/features/types.txt'
INCIDENT_OWNERS_PATH = '../data/features/owners.txt'
EXPERIENCE_MAPPER = '../datasets/features/experience-mapping.json'
DATA_SAVING_PATH = '../data/generated/incidents.json'


Basic_Duration = 6
Average_Duration = 4
Advanced_Duration = 2

Skip_Step = 10


def generate_random_list(owners, types, experience_mapper, length=10):
    incidents = []
    incident_ids = set()

    for i in range(int(length)):
        while True:
            incident_id = random.randint(1, int(length))
            if incident_id not in incident_ids:
                incident_ids.add(incident_id)
                break
        duration = random.randint(1, 5)
        incident_type = random.choice(types)
        owner = random.choice(owners)
        if owner in experience_mapper and random.randint(1, 100) == 2:
            incident_type = experience_mapper[owner]
            duration = random.randint(1, 2)
        incidents.append({
            "id": incident_id,
            "type": incident_type,
            "duration": duration,
            "owner": owner
        })

    return incidents


def main():

    parser = argparse.ArgumentParser(description='Generate randomized incident list.')
    parser.add_argument('length', type=int, help='The length of the incident list in numbers')
    args = parser.parse_args()

    # Read the feature values

    with open(INCIDENT_TYPES_PATH, 'r') as types, open(INCIDENT_OWNERS_PATH, 'r') as owners,\
            open(EXPERIENCE_MAPPER, 'r') as experience_mapper:
        types = types.read().splitlines()
        owners = owners.read().splitlines()
        experience_mapper = json.loads(experience_mapper.read())

    with open(DATA_SAVING_PATH, 'w') as dataset:
        incidents = generate_random_list(owners=owners, types=types, length=args.length,
                                         experience_mapper=experience_mapper)
        json.dump(incidents, dataset, indent=4)
        print('Random dataset is generated')


if __name__ == '__main__':
    main()
