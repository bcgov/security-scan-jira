# Security Scan to Jira Script

Converts security scan results into JSON which can then be imported into Jira as tickets.

## Usage

Currently works with the following scan types:

- AQUA (-aqua.csv)
- Trivy (-trivy.sarif)
- Anchore (-anchore.sarif)

Place scan results in the `scans` directory. Files must end with the appropriate file name and extension shown in parenthesis in the list above in order to be processed by this script.

Feel free to modify the script as you see fit to include any details from your scans into the final output file. Pull requests welcomed!

## To Run

### Prerequisites

- Scan results placed in `scans` directory with appropriate file names (see Usage section above)
  - Sample scans results are included for demonstration. Copy these results from the `sample-scans` directory into `scans` before running.
- Python 3 installed

Once the scans are placed in the directory simply run using `python3 security-scan-jira-script.py`. The scipt will output a .json file to the project root.

## Resources

- [Jira JSON Documentation](https://support.atlassian.com/jira-cloud-administration/docs/import-data-from-json/) : How to import JSON files into JIRA. Also includes information on valid JSON structure and fields.    
  - Note: `summary` is the only mandatory field for `issues`. All others are optional.
