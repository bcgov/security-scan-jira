import os
import json
from pathlib import Path
import requests
from requests.auth import HTTPBasicAuth
import logging


BUILD_CONFIG_PATH = Path('./openshift/build-config.yaml')
OLD_SCAN_PATH = Path('./old_scan_results.json')

JIRA_EMAIL = os.environ.get('JIRA_EMAIL')
JIRA_API_KEY = os.environ.get('JIRA_API_KEY')
JIRA_API_URL = "https://dpdd.atlassian.net/rest/api/2"
JIRA_AUTH = HTTPBasicAuth(JIRA_EMAIL, JIRA_API_KEY)
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)


def strtobool(s):
    if not isinstance(s, str):
        return s
    return s.lower() in {"yes", "true", "t", "1"}


def post_request(ticket):
    """
    Post issue request to Jira.
    """
    payload = json.dumps({
        "fields": {
            "project": {
                "key": "APS"
            },
            "summary": ticket['summary'],
            "description": ticket['description'],
            "issuetype": {
                "name": "Story"
            },
            "customfield_10014": "APS-908",
            "priority": {
                "id": "10000"
            }
        }
    })

    post_url = JIRA_API_URL + '/issue'

    response = requests.post(url=post_url, data=payload,
                             headers=HEADERS, auth=JIRA_AUTH)
    logger.info(f'POST to Jira status code: {response.status_code}')
    logger.info(response.text)


def put_request(ticket, ticket_id):
    """
    Put issue request to Jira. Mostly used for testing.
    """
    payload = json.dumps({
        "fields": {
            "project": {
                "key": "APS"
            },
            "summary": ticket['summary'],
            "description": ticket['description'],
            "customfield_10014": "APS-908",
            "priority": {
                "id": "10000"
            }
        }
    })

    put_url = JIRA_API_URL + '/issue/' + ticket_id

    response = requests.put(url=put_url, data=payload,
                            headers=HEADERS, auth=JIRA_AUTH)

    logger.info(f'PUT to Jira status code: {response.status_code}')
    logger.info(response.text)


def get_old_scan_results():
    """
    Opens old-scan-results artifact downloaded from most recent run-aqua-scans workflow run
    """
    with OLD_SCAN_PATH.open() as f:
        return json.load(f)


def save_data_to_json(filename: str, data: dict):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile)


def load_json(file: str):
    with open(file, 'r') as f:
        return json.load(f)
