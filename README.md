#Nessus/ACAS Script

A security-hardened PowerShell script that converts Nessus/ACAS XML vulnerability scan files (`.nessus`) to CSV format.

## Features

- **Secure XML parsing** - Prevents XXE (XML External Entity) attacks via `DtdProcessing::Prohibit`
- **CSV injection protection** - Neutralizes formula injection characters in output
- **Path validation** - Guards against path traversal attempts
- **File permission hardening** - Restricts output file ACLs to the current user (Windows)
- **BOM-free UTF-8 output** - Compatible with non-Microsoft tools
- **GUI file dialogs** - Optional file picker when paths aren't provided via parameters
- **Severity summary** - Displays a color-coded breakdown of findings before export

## Requirements

- PowerShell 5.1 or later
- Windows (for GUI file dialogs; core parsing works cross-platform on PowerShell 7+)

## Usage

### Interactive (GUI file dialogs)

```powershell
.\nessustocsv.ps1
```

### Command-line

```powershell
.\nessustocsv.ps1 -NessusFilePath "C:\Scans\Weekly_Scan.nessus" -OutputCsvPath "C:\Reports\results.csv"
```

### Select specific columns

```powershell
.\nessustocsv.ps1 -NessusFilePath "scan.nessus" -OutputCsvPath "results.csv" -IncludeColumns HostIP, PluginName, Severity, CVE, Solution
```

### Verbose output

```powershell
.\nessustocsv.ps1 -NessusFilePath "scan.nessus" -OutputCsvPath "results.csv" -Verbose
```

## Output Columns

| Column | Description |
|--------|-------------|
| HostName | Target hostname |
| HostIP | Target IP address |
| OperatingSystem | Detected OS |
| Port | Affected port number |
| Protocol | Network protocol (tcp/udp) |
| Service | Service name |
| PluginID | Nessus/ACAS plugin identifier |
| PluginName | Vulnerability name |
| PluginFamily | Plugin category |
| Severity | Numeric severity (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical) |
| RiskFactor | Risk classification |
| Synopsis | Brief vulnerability description |
| Description | Detailed vulnerability description |
| Solution | Recommended remediation |
| CVE | Associated CVE identifiers |
| CVSS_BaseScore | CVSS v2 base score |
| CVSS_Vector | CVSS vector string |
| PluginOutput | Raw plugin output |
| SeeAlso | Reference URLs |
| ExploitAvailable | Whether a public exploit exists |
| PatchPublicationDate | Date a patch was published |
| VulnerabilityPublicationDate | Date the vulnerability was disclosed |

## Security Considerations

This script was designed with the following security controls:

- **XXE Prevention**: XML reader prohibits DTD processing and disables the XML resolver
- **CSV Injection Mitigation**: Cells starting with `=`, `+`, `-`, or `@` are prefixed with a single quote to prevent formula execution in spreadsheet applications
- **Input Sanitization**: Control characters are stripped from all output fields
- **Error Handling**: Stack traces are only shown with `-Verbose` to avoid leaking internal paths

## Authors

- **Daniel Barker** - Original author
- **Claude Opus 4.6** (Anthropic) - Co-author, security hardening and code improvements

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
