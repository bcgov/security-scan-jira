import csv
from pathlib import Path
import json
import re

"""
Security Scan to Jira

Converts security scans into JSON which can then be imported into Jira as tickets.

Works with the following scan types:

- AQUA (-aqua.csv)
- Trivy (-trivy.sarif)
- Anchore (-anchore.sarif)

Place scan results in the `scans` directory. Files must end with the appropriate file name and extension shown in parenthesis in the list above in order to be processed by this script.

Possible improvements
- Need better way of getting Trivy scan source (eg: my-app-repo). Right now it just uses the name of repo from the first record it finds in the `result` field. It would be nice if we can capture this and include it in the scan result file after the scan runs.
- Currently combines all scans with similar vulnerabilities into one ticket. This include image versions and repo vs image scans. Ie: Aqua, Trivy, and Anchore scans all combined into one ticket, and vulnerabilities from, say, kong:2.5 are combined with kong:2.1. We may want to modify this behaviour in the future.
- More robust error handling
- Create CLI
"""

with open("config.json", "r") as conf_f:
    config = json.load(conf_f)

    # What to save the output file. Must be .json
    OUTPUT_FILENAME = config.get('outputFileName', 'scans_for_jira.json')
    # Severity of scans that will be in the output file. Should be all upper case. Eg: CRITICAL, HIGH, etc. Leave empty to pick up all records.
    SCAN_SEVERITY = set(config.get('scanSeverity', []))
    # Set these according to your Jira project
    JIRA_PROJECT_NAME = config.get('jiraProjectName', 'MY JIRA PROJECT')
    JIRA_PROJECT_KEY = config.get('jiraProjectKey', 'MJP')
    # Some optional fields included in each ticket.
    JIRA_TICKET_LABELS = config.get('jiraTicketLabels', [])
    JIRA_ISSUE_TYPE = config.get('jiraIssueType', 'Task')
    SCAN_PATH = Path(config.get('scanPath', './scans'))


ticket_export_dict = {}

##########################################################################
# GENERAL FUNCTIONS                                                      #
##########################################################################


def handle_ticket_export_dict_insert(row):
    """
    Adds record to list which will later be exported. Handles duplicate records.
    """

    # Remove image tag from summary
    p = re.compile(r':([.]|\d)$')
    formatted_summary = p.sub('', row['summary'])

    if formatted_summary not in ticket_export_dict:
        ticket_export_dict[formatted_summary] = {
            'description': row['description'], 'issueType': JIRA_ISSUE_TYPE, 'labels': JIRA_TICKET_LABELS}
    else:
        if row['description'] not in ticket_export_dict[formatted_summary]:
            ticket_export_dict[formatted_summary][
                'description'] += f'\n-----------------------\nSimilar vulnerability found. Note this may appear as a duplicate. It may also be for a different image version.\n{row["description"]}'


def export_scan_results_to_json():
    issues = []
    for k, v in ticket_export_dict.items():
        v['summary'] = k
        issues.append(v)

    print(f'Records created: {len(ticket_export_dict)}')
    final_output_dict = {
        'projects': [
            {
                'name': JIRA_PROJECT_NAME,
                'key': JIRA_PROJECT_KEY,
                'issues': issues
            }
        ]
    }

    with open(OUTPUT_FILENAME, 'w') as f:
        json.dump(final_output_dict, f)

    print('Export complete.')


def remove_newline_whitespace(text):
    """Some descriptions have newline characters followed by excess whitespace (eg: '\n    ').
    This removes that whitespace"""
    p = re.compile(r'\n +')
    return p.sub(r'\n', text)


def is_severe_enough(record_severity):
    """Return true if record severity in scan severity, or if scan severity set is empty (no severity specified)"""
    return record_severity.upper() in SCAN_SEVERITY or not SCAN_SEVERITY


##########################################################################
# AQUA SCAN FUNCTIONS                                                    #
##########################################################################


def format_aqua_descriptions(row):
    desc = f"""*Scanner*: AQUA
*Registry:* {row['Registry']}
*Image Name:* {row['Image Name']}
*First Found on Image:* {row['First Found on Image']}
*Last Image Scan:* {row['Last Image Scan']}
*Resource:* {row['Resource']}
*Resource Type:* {row['Resource Type']}
*Vulnerability:* {row['Vulnerability Name']}
*Publish Data:* {row['Publish Date']}
*NVD URL:* {row['NVD URL']}

*Fix Version:* {row['Fix Version']}
*Solution:* {row['Solution']}

*Description:*
{row['Description']}"""
    return remove_newline_whitespace(desc)


def format_aqua_summary(aqua_row):
    return f"Security Vulnerability - {aqua_row['Image Name'].split('/')[1].split(':')[0]} - {aqua_row['Vulnerability Name']} - {aqua_row['Aqua severity'].upper()}"


def process_aqua_scans():
    """
    Entry point for handling aqua scan results. Note that scan files must end in '-aqua.csv' to be processed.
    """
    files = SCAN_PATH.glob('**/*-aqua.csv')

    for file in list(files):
        with file.open() as f:
            for row in csv.DictReader(f, skipinitialspace=True):
                if is_severe_enough(row['Aqua severity']):
                    row['summary'] = format_aqua_summary(row)
                    row['description'] = format_aqua_descriptions(row)

                    handle_ticket_export_dict_insert(row)


##########################################################################
# TRIVY SCAN FUNCTIONS                                                   #
##########################################################################


def get_trivy_severity(rule):
    vulnerabilityTag = 'vulnerability'
    tags = rule['properties']['tags']
    if vulnerabilityTag in tags:
        return tags[tags.index(vulnerabilityTag) + 1]
    return ''


def trivy_result_is_severe_enough(rule):
    vulnerabilityTag = 'vulnerability'
    tags = rule['properties']['tags']
    hasVulnerabilityTag = vulnerabilityTag in tags
    if hasVulnerabilityTag:
        return is_severe_enough(get_trivy_severity(rule))


def format_trivy_summary(rule, repo):
    return f"Security Vulnerability - {repo} - {rule['id']} - {get_trivy_severity(rule).upper()}"


def format_trivy_description(rule, repo):
    desc = f"""*Scanner*: Trivy
*Repository*: {repo}
*Severity:* {rule['severity']}
*Description:* {rule['fullDescription']['text']}
*Help URL:* {rule['helpUri']}

*Help:*
{rule['help']['text']}"""
    return remove_newline_whitespace(desc)


def get_trivy_scan_source(data):
    """Returns repo name of scan source, if found."""
    for d in data:
        repo_uri = d['locations'][0]['physicalLocation']['artifactLocation']['uri']
        try:
            return repo_uri.split('/')[1].split(':')[0]
        except IndexError:
            continue
    return '*scan source unavailable*'


def process_trivy_scans():
    """Entry point for processing trivy scans. Files must end in '-trivy.sarif' to be picked up."""
    files = SCAN_PATH.glob('**/*-trivy.sarif')
    for f in list(files):
        with f.open() as f:
            data = json.load(f)
            for run in data['runs']:
                scan_source = get_trivy_scan_source(run['results'])
                for rule in run['tool']['driver']['rules']:
                    if trivy_result_is_severe_enough(rule):
                        rule['summary'] = format_trivy_summary(
                            rule, scan_source)
                        rule['severity'] = get_trivy_severity(rule)
                        rule['description'] = format_trivy_description(
                            rule, scan_source)

                        handle_ticket_export_dict_insert(rule)


##########################################################################
# ANCHORE SCAN FUNCTIONS                                                 #
##########################################################################


def get_anchore_severity(rule):
    return rule['shortDescription']['text'].split(' ')[1].upper()


def format_anchore_summary(rule):
    repo = rule['id'].split('/')[1].split(':')[0]
    vuln_id = rule['shortDescription']['text'].split(' ')[0]
    return f"Security Vulnerability - {repo} - {vuln_id} - {get_anchore_severity(rule).upper()}"


def format_anchore_description(rule):
    desc = f"""*Scanner*: Anchore
*Anchore ID*: {rule['id']}
*Severity:* {rule['severity']}
*Description:* {rule['fullDescription']['text']}

*Help:*
{rule['help']['text']}"""
    return remove_newline_whitespace(desc)


def process_anchore_scans():
    files = SCAN_PATH.glob('**/*-anchore.sarif')

    for file in list(files):
        with file.open() as f:
            data = json.load(f)
            for run in data['runs']:
                for rule in run['tool']['driver']['rules']:
                    if is_severe_enough(get_anchore_severity(rule)):
                        rule['summary'] = format_anchore_summary(rule)
                        rule['severity'] = get_anchore_severity(rule)
                        rule['id'] = rule['shortDescription']['text'].split(' ')[
                            0]
                        rule['description'] = format_anchore_description(rule)

                        handle_ticket_export_dict_insert(rule)


def main():
    process_aqua_scans()
    process_trivy_scans()
    process_anchore_scans()
    export_scan_results_to_json()


if __name__ == '__main__':
    main()
