# Security Scan to Jira Script

Converts security scan results into JSON which can then be imported into Jira as tickets.

## Usage

Currently works with the following scan types:

- AQUA (-aqua.csv)
- Trivy (-trivy.sarif)
- Anchore (-anchore.sarif)

Create a `scans` directory at project root and place scan result files in that directory, or rename `sample-scans` directory to `scans` to run with sample data. Files must end with the appropriate file name and extension shown in parenthesis in the list above in order to be processed by this script.

Feel free to modify the script as you see fit to include any details from your scans into the final output file.

## To Run

### Prerequisites

- Scan results placed in a `scans` directory at project root with appropriate file names (see Usage section above)
- Python 3 installed

Once the scans are placed in the directory simply run using `python3 security-scan-jira-script.py`. The scipt will output a .json file to the project root.

## Resources

- [Jira JSON Documentation](https://support.atlassian.com/jira-cloud-administration/docs/import-data-from-json/) : How to import JSON files into JIRA. Also includes information on valid JSON structure and fields.    
  - Note: `summary` is the only mandatory field for `issues`. All others are optional.
