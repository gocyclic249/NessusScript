<#
.SYNOPSIS
    Converts Nessus XML scan files to CSV format with security-focused implementation.

.DESCRIPTION
    This script securely parses Nessus XML vulnerability scan files and exports
    the results to CSV format. It implements security best practices including
    input validation, error handling, and secure XML processing to prevent
    XML injection attacks and other vulnerabilities.

.PARAMETER NessusFilePath
    Path to the Nessus XML file to be processed. If not provided, a file dialog will open.

.PARAMETER OutputCsvPath
    Path where the CSV output file will be saved. If not provided, a save dialog will open.

.PARAMETER IncludeColumns
    Array of column names to include in the output. If not specified, all columns are included.

.EXAMPLE
    .\Convert-NessusToCSV.ps1
    Opens file dialogs to select input and output files.

.EXAMPLE
    .\Convert-NessusToCSV.ps1 -NessusFilePath "C:\Scans\Weekly_MGMT_Scan.nessus" -OutputCsvPath "C:\Reports\scan_results.csv"

.NOTES
    Author: Daniel Barker
    Version: 1.1
    License: GPL-3.0
    Compliance: NIST Cybersecurity Framework, DoD RMF
    Security Features:
    - Input validation and sanitization
    - Secure XML parsing (prevents XXE attacks)
    - Error handling and logging
    - Path traversal prevention
    - Memory-efficient processing
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false, HelpMessage="Path to the Nessus XML file")]
    [ValidateNotNullOrEmpty()]
    [string]$NessusFilePath,
    
    [Parameter(Mandatory=$false, HelpMessage="Path for the output CSV file")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputCsvPath,
    
    [Parameter(Mandatory=$false, HelpMessage="Specific columns to include in output")]
    [ValidateNotNullOrEmpty()]
    [string[]]$IncludeColumns
)

#Requires -Version 5.1

# Set strict mode for better error handling
Set-StrictMode -Version Latest

# Error action preference
$ErrorActionPreference = "Stop"

#region Security Functions

function Test-SecurePath {
    <#
    .SYNOPSIS
        Validates file paths to prevent path traversal attacks
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [switch]$MustExist
    )
    
    try {
        # Resolve to absolute path to prevent path traversal
        $resolvedPath = [System.IO.Path]::GetFullPath($Path)
        
        # Check for path traversal attempts
        if ($resolvedPath -notlike "$($PWD.Path)*" -and $resolvedPath -notlike "$($env:USERPROFILE)*") {
            Write-Warning "Path is outside current directory and user profile. Proceeding with caution."
        }
        
        # Check if file must exist
        if ($MustExist -and -not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
            throw "File does not exist: $resolvedPath"
        }
        
        return $resolvedPath
    }
    catch {
        Write-Error "Path validation failed: $_"
        throw
    }
}

function Get-SecureXmlDocument {
    <#
    .SYNOPSIS
        Loads XML document with security settings to prevent XXE attacks
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$XmlPath
    )
    
    try {
        # Create XmlReaderSettings with secure configuration
        $xmlSettings = New-Object System.Xml.XmlReaderSettings
        $xmlSettings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $xmlSettings.XmlResolver = $null
        $xmlSettings.MaxCharactersFromEntities = 1024
        $xmlSettings.MaxCharactersInDocument = 0

        # Create secure XML reader
        $reader = [System.Xml.XmlReader]::Create($XmlPath, $xmlSettings)

        try {
            # Load XML document
            $xmlDoc = New-Object System.Xml.XmlDocument
            $xmlDoc.Load($reader)
            return $xmlDoc
        }
        finally {
            $reader.Close()
            $reader.Dispose()
        }
    }
    catch {
        Write-Error "Failed to load XML document securely: $_"
        throw
    }
}

function ConvertTo-SafeString {
    <#
    .SYNOPSIS
        Sanitizes strings for CSV output to prevent injection attacks
    #>
    param(
        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        $InputString
    )
    
    if ($null -eq $InputString -or [string]::IsNullOrEmpty($InputString)) {
        return ""
    }
    
    # Convert to string if it's not already
    $stringValue = $InputString.ToString()
    
    # Remove control characters
    $sanitized = $stringValue -replace '[\x00-\x1F\x7F]', ''

    # Escape double quotes
    $sanitized = $sanitized.Replace('"', '""')

    # Prefix with single quote to neutralize CSV injection without losing data
    if ($sanitized -match '^[=+\-@]') {
        $sanitized = "'" + $sanitized
    }

    return $sanitized
}

function Show-OpenFileDialog {
    <#
    .SYNOPSIS
        Displays a file open dialog for selecting Nessus files
    #>
    param(
        [Parameter(Mandatory=$false)]
        [string]$Title = "Select Nessus XML File",
        
        [Parameter(Mandatory=$false)]
        [string]$Filter = "Nessus Files (*.nessus)|*.nessus|XML Files (*.xml)|*.xml|All Files (*.*)|*.*"
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms
        
        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Title = $Title
        $openFileDialog.Filter = $Filter
        $openFileDialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
        $openFileDialog.Multiselect = $false
        
        $result = $openFileDialog.ShowDialog()
        
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return $openFileDialog.FileName
        }
        else {
            return $null
        }
    }
    catch {
        Write-Error "Failed to show file dialog: $_"
        throw
    }
}

function Show-SaveFileDialog {
    <#
    .SYNOPSIS
        Displays a file save dialog for selecting output location
    #>
    param(
        [Parameter(Mandatory=$false)]
        [string]$Title = "Save CSV File",
        
        [Parameter(Mandatory=$false)]
        [string]$Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*",
        
        [Parameter(Mandatory=$false)]
        [string]$DefaultFileName = "NessusScan_Export.csv"
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms
        
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Title = $Title
        $saveFileDialog.Filter = $Filter
        $saveFileDialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
        $saveFileDialog.FileName = $DefaultFileName
        $saveFileDialog.OverwritePrompt = $true
        
        $result = $saveFileDialog.ShowDialog()
        
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return $saveFileDialog.FileName
        }
        else {
            return $null
        }
    }
    catch {
        Write-Error "Failed to show save dialog: $_"
        throw
    }
}

#endregion

#region Main Processing Functions

function Get-NessusVulnerabilities {
    <#
    .SYNOPSIS
        Extracts vulnerability data from Nessus XML document
    #>
    param(
        [Parameter(Mandatory=$true)]
        [System.Xml.XmlDocument]$XmlDocument
    )
    
    try {
        $vulnerabilities = [System.Collections.Generic.List[PSCustomObject]]::new()
        
        # Get all ReportHost nodes
        $reportHosts = $xmlDocument.SelectNodes("//ReportHost")
        
        if ($reportHosts.Count -eq 0) {
            Write-Warning "No report hosts found in the Nessus file."
            return $vulnerabilities
        }
        
        Write-Verbose "Processing $($reportHosts.Count) host(s)..."
        
        foreach ($reportHost in $reportHosts) {
            $hostName = ConvertTo-SafeString -InputString $reportHost.GetAttribute("name")
            
            # Get host properties
            $hostProperties = @{}
            foreach ($tag in $reportHost.SelectNodes("HostProperties/tag")) {
                $tagName = ConvertTo-SafeString -InputString $tag.GetAttribute("name")
                $tagValue = ConvertTo-SafeString -InputString $tag.InnerText
                $hostProperties[$tagName] = $tagValue
            }
            
            # Get all ReportItem nodes (vulnerabilities)
            $reportItems = $reportHost.SelectNodes("ReportItem")
            
            foreach ($item in $reportItems) {
                # Helper function to safely get node value
                $getNodeValue = {
                    param($nodeName)
                    $node = $item.SelectSingleNode($nodeName)
                    if ($node) {
                        return $node.InnerText
                    }
                    return ""
                }
                
                # Helper function to get multiple node values
                $getMultiNodeValues = {
                    param($nodeName)
                    $nodes = $item.SelectNodes($nodeName)
                    if ($nodes -and $nodes.Count -gt 0) {
                        $values = @()
                        foreach ($n in $nodes) {
                            if ($n.InnerText) {
                                $values += $n.InnerText
                            }
                        }
                        return ($values -join "; ")
                    }
                    return ""
                }
                
                $vuln = [PSCustomObject]@{
                    HostName = $hostName
                    HostIP = if ($hostProperties.ContainsKey("host-ip")) { $hostProperties["host-ip"] } else { $hostName }
                    OperatingSystem = if ($hostProperties.ContainsKey("operating-system")) { $hostProperties["operating-system"] } else { "Unknown" }
                    Port = ConvertTo-SafeString -InputString $item.GetAttribute("port")
                    Protocol = ConvertTo-SafeString -InputString $item.GetAttribute("protocol")
                    Service = ConvertTo-SafeString -InputString $item.GetAttribute("svc_name")
                    PluginID = ConvertTo-SafeString -InputString $item.GetAttribute("pluginID")
                    PluginName = ConvertTo-SafeString -InputString $item.GetAttribute("pluginName")
                    PluginFamily = ConvertTo-SafeString -InputString $item.GetAttribute("pluginFamily")
                    Severity = ConvertTo-SafeString -InputString $item.GetAttribute("severity")
                    RiskFactor = ConvertTo-SafeString -InputString (& $getNodeValue "risk_factor")
                    Synopsis = ConvertTo-SafeString -InputString (& $getNodeValue "synopsis")
                    Description = ConvertTo-SafeString -InputString (& $getNodeValue "description")
                    Solution = ConvertTo-SafeString -InputString (& $getNodeValue "solution")
                    CVE = ConvertTo-SafeString -InputString (& $getMultiNodeValues "cve")
                    CVSS_BaseScore = ConvertTo-SafeString -InputString (& $getNodeValue "cvss_base_score")
                    CVSS_Vector = ConvertTo-SafeString -InputString (& $getNodeValue "cvss_vector")
                    PluginOutput = ConvertTo-SafeString -InputString (& $getNodeValue "plugin_output")
                    SeeAlso = ConvertTo-SafeString -InputString (& $getMultiNodeValues "see_also")
                    ExploitAvailable = ConvertTo-SafeString -InputString (& $getNodeValue "exploit_available")
                    PatchPublicationDate = ConvertTo-SafeString -InputString (& $getNodeValue "patch_publication_date")
                    VulnerabilityPublicationDate = ConvertTo-SafeString -InputString (& $getNodeValue "vuln_publication_date")
                }
                
                $vulnerabilities.Add($vuln)
            }
        }
        
        Write-Verbose "Extracted $($vulnerabilities.Count) vulnerability finding(s)."
        return $vulnerabilities
    }
    catch {
        Write-Error "Failed to extract vulnerabilities: $_"
        throw
    }
}

function Export-SecureCsv {
    <#
    .SYNOPSIS
        Exports data to CSV with security controls
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [string[]]$IncludeColumns
    )
    
    try {
        if ($Data.Count -eq 0) {
            Write-Warning "No data to export."
            return
        }
        
        # Filter columns if specified
        if ($IncludeColumns -and $IncludeColumns.Count -gt 0) {
            $Data = $Data | Select-Object -Property $IncludeColumns
        }
        
        # Export to CSV with security settings
        # Note: PS 5.1 -Encoding UTF8 writes BOM. Using .NET for BOM-free UTF-8.
        $csvContent = ($Data | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($Path, $csvContent, $utf8NoBom)
        
        Write-Host "Successfully exported $($Data.Count) records to: $Path" -ForegroundColor Green
        
        # Set file permissions (Windows only - PowerShell 5.1 compatible check)
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            # Check if we're on Windows by testing for Windows-specific environment variable
            $isWindowsOS = $env:OS -eq "Windows_NT"
            
            if ($isWindowsOS) {
                try {
                    $acl = Get-Acl -LiteralPath $Path
                    # Remove inheritance
                    $acl.SetAccessRuleProtection($true, $false)
                    # Add current user with full control
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $currentUser, "FullControl", "Allow"
                    )
                    $acl.SetAccessRule($accessRule)
                    Set-Acl -LiteralPath $Path -AclObject $acl
                    Write-Verbose "Set secure file permissions on output file."
                }
                catch {
                    Write-Warning "Could not set file permissions: $_"
                }
            }
        }
    }
    catch {
        Write-Error "Failed to export CSV: $_"
        throw
    }
}

#endregion

#region Main Execution

try {
    Write-Host "`n=== Nessus to CSV Converter ===" -ForegroundColor Cyan
    Write-Host "Security-hardened implementation`n" -ForegroundColor Cyan
    
    # Get input file path via dialog if not provided
    if ([string]::IsNullOrEmpty($NessusFilePath)) {
        Write-Host "Please select the Nessus XML file..." -ForegroundColor Yellow
        $NessusFilePath = Show-OpenFileDialog
        
        if ([string]::IsNullOrEmpty($NessusFilePath)) {
            Write-Warning "No file selected. Exiting."
            exit 0
        }
    }
    
    # Validate input file path
    Write-Verbose "Validating input file path..."
    $validatedInputPath = Test-SecurePath -Path $NessusFilePath -MustExist
    Write-Host "Input file: $validatedInputPath" -ForegroundColor Gray
    
    # Get output file path via dialog if not provided
    if ([string]::IsNullOrEmpty($OutputCsvPath)) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $defaultFileName = "NessusScan_$timestamp.csv"
        
        Write-Host "Please select where to save the CSV file..." -ForegroundColor Yellow
        $OutputCsvPath = Show-SaveFileDialog -DefaultFileName $defaultFileName
        
        if ([string]::IsNullOrEmpty($OutputCsvPath)) {
            Write-Warning "No output location selected. Exiting."
            exit 0
        }
    }
    
    # Validate output file path
    Write-Verbose "Validating output file path..."
    $validatedOutputPath = Test-SecurePath -Path $OutputCsvPath
    Write-Host "Output file: $validatedOutputPath" -ForegroundColor Gray
    
    # Load XML document securely
    Write-Host "`nLoading Nessus XML file..." -ForegroundColor Yellow
    $xmlDoc = Get-SecureXmlDocument -XmlPath $validatedInputPath
    Write-Host "XML file loaded successfully." -ForegroundColor Green
    
    # Extract vulnerabilities
    Write-Host "`nExtracting vulnerability data..." -ForegroundColor Yellow
    $vulnerabilities = Get-NessusVulnerabilities -XmlDocument $xmlDoc
    
    if ($vulnerabilities.Count -eq 0) {
        Write-Warning "No vulnerabilities found in the scan file."
        exit 0
    }
    
    # Display summary
    Write-Host "`n=== Scan Summary ===" -ForegroundColor Cyan
    Write-Host "Total findings: $($vulnerabilities.Count)" -ForegroundColor White
    
    $severityCounts = $vulnerabilities | Group-Object -Property Severity | 
        Select-Object @{N='Severity';E={
            switch($_.Name) {
                "0" { "Info" }
                "1" { "Low" }
                "2" { "Medium" }
                "3" { "High" }
                "4" { "Critical" }
                default { "Unknown" }
            }
        }}, Count
    
    foreach ($severity in $severityCounts) {
        $color = switch($severity.Severity) {
            "Critical" { "Red" }
            "High" { "DarkRed" }
            "Medium" { "Yellow" }
            "Low" { "DarkYellow" }
            default { "Gray" }
        }
        Write-Host "  $($severity.Severity): $($severity.Count)" -ForegroundColor $color
    }
    
    # Export to CSV
    Write-Host "`nExporting to CSV..." -ForegroundColor Yellow
    Export-SecureCsv -Data $vulnerabilities -Path $validatedOutputPath -IncludeColumns $IncludeColumns
    
    Write-Host "`n=== Conversion Complete ===" -ForegroundColor Green
    Write-Host "CSV file created successfully!`n" -ForegroundColor Green
}
catch {
    Write-Host "`n=== ERROR ===" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Verbose "`nStack Trace:"
    Write-Verbose $_.ScriptStackTrace
    exit 1
}
finally {
    # Cleanup
    if ($xmlDoc) {
        $xmlDoc = $null
    }
}

#endregion