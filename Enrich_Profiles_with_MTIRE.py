# Enrich_Profiles_with_MITRE.py

import os
import json
import git
import glob
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname=s - %(message)s')

# Step 1: Clone the MITRE repository
def clone_mitre_repo():
    try:
        mitre_repo = "https://github.com/mitre/cti"
        if not os.path.exists("cti"):
            git.Repo.clone_from(mitre_repo, "cti")
        logging.info("Cloned MITRE CTI repository successfully.")
    except Exception as e:
        logging.error(f"Error cloning MITRE repository: {e}")

# Step 2: Extract MITRE intrusion sets
def extract_mitre_intrusion_sets():
    mitre_path = "cti/enterprise-attack/intrusion-set/*.json"  # Verify this path is correct
    try:
        json_files = glob.glob(mitre_path)
        logging.info(f"Found JSON files: {json_files}")
        intrusion_sets = []
        for file in json_files:
            with open(file, 'r') as f:
                data = json.load(f)
                intrusion_sets.extend(data.get('objects', []))  # Extract intrusion set objects
        return intrusion_sets
    except Exception as e:
        logging.error(f"Error extracting MITRE intrusion sets: {e}")
        return []

# Step 3: Load existing threat profiles
def load_threat_profiles(profiles_path):
    profiles = []
    try:
        for json_file in glob.glob(os.path.join(profiles_path, "*.json")):
            with open(json_file, 'r') as f:
                profiles.append(json.load(f))
        logging.info(f"Loaded {len(profiles)} threat profiles.")
        return profiles
    except Exception as e:
        logging.error(f"Error loading threat profiles: {e}")
        return []

# Step 4: Correlate and enrich profiles
def correlate_and_enrich_profiles(intrusion_sets, threat_profiles):
    intrusion_set_dict = {intrusion_set.get('name', '').lower(): intrusion_set for intrusion_set in intrusion_sets}

    for intrusion_set in intrusion_sets:
        for alias in intrusion_set.get('aliases', []):
            intrusion_set_dict[alias.lower()] = intrusion_set

    enriched_profiles = []

    for profile in threat_profiles:
        profile_name = profile.get('value', '').lower()
        aliases = [alias.lower() for alias in profile.get('meta', {}).get('synonyms', [])]

        matched_intrusion_set = intrusion_set_dict.get(profile_name)
        if not matched_intrusion_set:
            for alias in aliases:
                matched_intrusion_set = intrusion_set_dict.get(alias)
                if matched_intrusion_set:
                    break

        if matched_intrusion_set:
            logging.info(f"Enriching profile {profile.get('value')} with MITRE data.")
            profile['mitre_attack_ids'] = [matched_intrusion_set.get('id', 'N/A')]
            profile['mitre_attack_urls'] = [ref.get('url') for ref in matched_intrusion_set.get('external_references', []) if ref.get('url')]
            profile['mitre_description'] = matched_intrusion_set.get('description', 'No description available')

            profile['mitre_aliases'] = matched_intrusion_set.get('aliases', [])
            profile['mitre_contributors'] = matched_intrusion_set.get('x_mitre_contributors', [])
            profile['mitre_created'] = matched_intrusion_set.get('created', '')
            profile['mitre_modified'] = matched_intrusion_set.get('modified', '')

        enriched_profiles.append(profile)

    return enriched_profiles

# Step 5: Save enriched profiles
def save_enriched_profiles(enriched_profiles, output_path):
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    for profile in enriched_profiles:
        output_file = os.path.join(output_path, f"{profile['value'].replace(' ', '_').replace('/', '_')}.json")
        with open(output_file, 'w') as out:
            json.dump(profile, out, indent=4)
        logging.info(f"Saved enriched profile for {profile['value']}.")

def main():
    clone_mitre_repo()

    intrusion_sets = extract_mitre_intrusion_sets()
    if not intrusion_sets:
        logging.error("No MITRE intrusion sets found. Exiting.")
        return

    threat_profiles_path = "profiles"  # Verify this path is correct
    threat_profiles = load_threat_profiles(threat_profiles_path)
    if not threat_profiles:
        logging.error("No threat profiles found. Exiting.")
        return

    enriched_profiles = correlate_and_enrich_profiles(intrusion_sets, threat_profiles)

    output_path = "enriched_profiles"  # Verify this path is correct
    save_enriched_profiles(enriched_profiles, output_path)

if __name__ == "__main__":
    main()
