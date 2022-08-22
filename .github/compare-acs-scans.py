import utils
from datetime import datetime
import os
from pathlib import Path
import json
import requests
import logging


USE_TEST_DATA = utils.strtobool(
    os.environ.get('USE_TEST_DATA', False))
# Use POST, PUT, or NONE
JIRA_OPERATION = os.environ.get('JIRA_OPERATION', 'POST').upper()
# Required if using PUT:
JIRA_PUT_ID = os.environ.get('JIRA_PUT_ID', 'APS-1247')
START_FRESH = utils.strtobool(os.environ.get('START_FRESH', False))

LAST_SCAN_FILE = 'last_acs_results.json'
LAST_SCAN_PATH = Path(f'./last_acs_scans/{LAST_SCAN_FILE}')
TICKET_FILENAME = 'acs_ticket_data.json'

ACS_API_URL = 'https://acs.developer.gov.bc.ca/v1'
ACS_API_KEY = os.environ.get('ACS_API_KEY', '')

ACS_URL = 'https://acs.developer.gov.bc.ca'
ACS_REQ_LIMIT = 5000

ACCEPTED_VULNERABILITIES = set(
    [f'{v.upper()}_SEVERITY' for v in os.environ.get('ACCEPTED_VULNERABILITIES', 'HIGH,CRITICAL').split(',')])

JIRA_DESC_MAX_LEN = 32000


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

stream_handler = logging.StreamHandler()
logger.addHandler(stream_handler)


def get_scan_delta(old_scans, new_scans):
    """
    Compares old scan results with new. Returns list with new vulnerabilities not found in old vulnerabilties.
    """
    if not old_scans:
        logger.info('No previous scans found. Returning all newly found scans.')
        return new_scans.get('alerts', [])

    delta = []

    for new_alert in new_scans.get('alerts', []):
        new_alert_is_unique = True
        for old_alert in old_scans.get('alerts', []):
            if new_alert['id'] == old_alert['id']:
                new_alert_is_unique = False
                break
        if new_alert_is_unique:
            logger.debug(f'New alert found: {new_alert["id"]}')
            delta.append(new_alert)
    return delta


def format_tickets(alerts):
    """
    Converts vulnerabilities into format that can be posted to Jira.
    """
    date_str = datetime.now().strftime("%d %b %Y")
    summary = f'{date_str} - ACS Scan Results'

    description = ''
    tickets = []
    ticket_num = 1

    for a in alerts:

        if len(description) > JIRA_DESC_MAX_LEN:
            tickets.append(
                {'summary': f'{summary} - {ticket_num}', 'description': description})
            ticket_num += 1
            description = ''

        description += f"""* *URL*: {ACS_URL}/main/violations/{a['id']}
* *Lifecycle Stage*: {a['lifecycleStage']}
* *Time*: {a['time'].split('.')[0]}
* *State*: {a['state']}
* *POLICY*
** *Name*: {a['policy']['name']}
** *Severity*: {a['policy']['severity']}
** *Description*: {a['policy']['description']}
* *DEPLOYMENT*
** *ID*: {a['deployment']['id']}
** *Name*: {a['deployment']['name']}
** *Cluster Name*: {a['deployment']['clusterName']}
** *Namespace*: {a['deployment']['namespace']}\n\n-----------\n"""

    if len(tickets) > 0:
        summary = f'{summary} - {ticket_num}'

    tickets.append({'summary': summary, 'description': description})

    return tickets


def handle_jira(tickets):
    logger.info(f'Performing JIRA_OPERATION: {JIRA_OPERATION}')
    if JIRA_OPERATION == 'POST':
        [utils.post_request(ticket) for ticket in tickets]
    elif JIRA_OPERATION == 'PUT':
        if len(tickets) > 0:
            logger.warning('WARNING: Multiple tickets are present. Only first ticket will be PUT.')
            tickets[0][
                'description'] = f'*NOTE: PUT operation with multiple tickets occurred. PUT applied to only first ticket*\n{tickets[0]["description"]}'
        utils.put_request(tickets[0], JIRA_PUT_ID)
    elif JIRA_OPERATION == 'NONE' or not JIRA_OPERATION:
        logger.warning('JIRA_OPERATION env var not specified or set to NONE. Will not send results to Jira.')


def get_last_scan_results():
    """
    Get ACS scan results from last scan/GitHub Action.
    """
    data = {}
    if START_FRESH:
        logger.warning('START_FRESH included. Last scan results will not be loaded.')
        return data

    try:
        with LAST_SCAN_PATH.open() as f:
            logger.info('Loading previous scan results...')
            data = json.load(f)
    except FileNotFoundError:
        logger.info('Previous scan results not found. Starting fresh...')
    return data


def get_latest_scan_results():
    """
    Get most recent ACS scan results
    """
    url = ACS_API_URL + f'/alerts?pagination.limit={ACS_REQ_LIMIT}'
    res = requests.get(url=url, headers={
                       "Authorization": f"Bearer {ACS_API_KEY}"})
    data = {}
    if res.status_code == 200:
        logger.info('Latest scans fetched!')
        data = json.loads(res.text)
    else:
        logger.error('Fetching latest scan results from ACS did result in 200 OK.')

    return data


def remove_unwanted_results(result):
    """Logic for removing any unwanted scan results"""
    return result['policy']['severity'] in ACCEPTED_VULNERABILITIES


def get_test_data():
    logger.info('Loading test data...')
    dir = f'{".github/" if ".github" in os.listdir() else ""}compare-acs-test-data'
    return utils.load_json(f'{dir}/old.json'), utils.load_json(f'{dir}/new.json')


def main():

    if USE_TEST_DATA:
        last_scans, latest_scans = get_test_data()
    else:
        last_scans = get_last_scan_results()
        latest_scans = get_latest_scan_results()

    latest_scans['alerts'] = list(
        filter(remove_unwanted_results, latest_scans['alerts']))

    logger.debug('Saving latest scan results to JSON...')
    utils.save_data_to_json(LAST_SCAN_FILE, latest_scans)

    alert_delta = get_scan_delta(last_scans, latest_scans)

    tickets = []

    if alert_delta:
        logger.info('Delta between last scan. Creating new ticket(s)...')
        tickets = format_tickets(alert_delta)
        handle_jira(tickets)

    else:
        logger.info('No delta detected. Ticket will not be created.')

    utils.save_data_to_json(TICKET_FILENAME, tickets)


if __name__ == '__main__':
    main()
