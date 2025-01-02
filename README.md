
# FMC Time-Based Rules Exporter

This script fetches and exports time-based access control rules from Cisco Firepower Management Center (FMC) to a CSV file. It matches the rules with configured time ranges, identifies expired objects, and provides a detailed report for analysis.

## Features

- **Authentication**: Secure login to FMC using username and password.
- **Fetch Policies**: Retrieve and list all available Access Control Policies.
- **Time-Based Rules**: Identify access control rules tied to specific time ranges.
- **Expired Objects Detection**: Detect time ranges that have expired.
- **CSV Export**: Save the results, including matched rules and expired objects, to a CSV file.
- **Progress Indicator**: Display the script's progress dynamically in the terminal.

---

## Prerequisites

- Python 3.6 or later
- Required Python libraries:
  - `requests`

Install the required libraries with:

```bash
pip install requests
```

---

## Usage

1. Clone this repository or download the script.

2. Run the script:

   ```bash
   python fmc_time_based_rules_exporter.py
   ```

3. Follow the on-screen prompts:

   - Enter the FMC server's IP or hostname.
   - Provide your FMC username and password.

4. The script will:

   - Retrieve all Access Control Policies.
   - Allow you to select a policy for analysis.
   - Identify all time-based rules associated with the selected policy.
   - Save the results to `time_based_rules.csv`.

---

## Output

- The script generates a CSV file named `time_based_rules.csv` with the following columns:
  - **Policy Name**: Name of the Access Control Policy.
  - **Rule Name**: Name of the time-based access rule.
  - **Time Range Objects**: Details of the associated time ranges.
  - **Expired Objects**: Names of expired time range objects (if any).

---

## Example

### Console Interaction
```
Enter the FMC server IP (e.g., https://192.168.1.1): https://192.168.1.1
Enter your FMC username: admin
Enter your FMC password: ******
Available Access Control Policies:
1. Corporate Policy
2. Test Policy
Select an Access Control Policy by entering the corresponding number: 1
Processing page 1...
Processing page 2...
All pages processed.
Time-based rules have been exported to 'time_based_rules.csv'.
```

### CSV Output
| Policy Name      | Rule Name     | Time Range Objects                   | Expired Objects |
|------------------|---------------|--------------------------------------|-----------------|
| Corporate Policy | Rule A        | Business Hours (Start: ..., End: ...) |                 |
| Corporate Policy | Rule B        | Maintenance Window (Start: ..., End: ...) | Maintenance Window |

---

## Notes

- The script disables SSL warnings to support self-signed certificates. For enhanced security, consider configuring trusted certificates.
- Ensure the provided FMC credentials have the necessary permissions to access policies and rules.

---

## Author

**Anupam Pavithran**  
Technical Consulting Engineer at Cisco Systems India  
Email: [anpavith@cisco.com](mailto:anpavith@cisco.com)

---

## License

This script is provided "as-is" without warranty of any kind. Use at your own risk.
