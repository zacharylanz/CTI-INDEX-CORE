# Generate_Base_Profiles.py

import os
import json
import git
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Step 1: Clone the MISP repository
def clone_repo():
    try:
        misp_repo = "https://github.com/MISP/misp-galaxy"
        if not os.path.exists("misp-galaxy"):
            git.Repo.clone_from(misp_repo, "misp-galaxy")
    except Exception as e:
        logging.error(f"Error cloning repository: {e}")

# Step 2: Extract JSON data
def extract_json_file(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        logging.error(f"Error extracting JSON file from {file_path}: {e}")
        return []

# Step 3: Generate and output individual JSON files for each threat actor
def generate_json_profiles(threat_actors):
    for actor in threat_actors:
        output_file = f"profiles/{actor['value'].replace(' ', '_').replace('/', '_')}.json"
        with open(output_file, 'w') as out:
            json.dump(actor, out, indent=4)
        logging.info(f"Generated JSON profile for {actor['value']}")

def main():
    clone_repo()

    misp_file = "./misp-galaxy/clusters/threat-actor.json"

    threat_actors = extract_json_file(misp_file).get('values', [])

    # Create profiles directory if not exists
    if not os.path.exists("profiles"):
        os.makedirs("profiles")

    generate_json_profiles(threat_actors)

if __name__ == "__main__":
    main()
