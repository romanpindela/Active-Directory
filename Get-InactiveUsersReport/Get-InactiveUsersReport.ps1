<#
================================================================================
  Script Name : Get-InactiveUsersReport.ps1
  Author      : Roman Pindela
  Contact     : roman.pindela@gmail.com
  Version     : 1.2.0
  Release Date: 2026-10-17
  License     : MIT
  Repository  : https://github.com/romanpindela

  DESCRIPTION:
    Enterprise-grade PowerShell security auditing script that discovers inactive
    user accounts (e.g., accounts that have not logged into the domain or cloud
    tenant for more than 90 days) and exports the audit report to a UTF-8 CSV file.

    Default CSV Report Path:
      C:\Logs\<yyyyMMdd_HHmmss>Get-InactiveUsersReport<ADServerName>nieaktywni_uzytkownicy.csv

    Default Execution Log Path:
      C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs

    Supports Dual Directory Modes:
    1. Local Active Directory Mode (-Provider AD / LocalAD):
       Queries On-Premises Windows Server Active Directory Domain Services (AD DS)
       using Get-ADUser:
         $DataGraniczna = (Get-Date).AddDays(-$InactiveDays)
         Get-ADUser -Filter {LastLogonDate -lt $DataGraniczna -and Enabled -eq $true} `
             -Properties LastLogonDate, DisplayName
    2. Cloud Active Directory Mode (-Provider EntraID / CloudAD):
       Queries Microsoft Entra ID (Azure AD) via Microsoft Graph PowerShell SDK
       (Get-MgUser -Property SignInActivity), supporting both interactive sign-in
       and unattended / non-interactive App-Only authentication using Client Secret
       or X.509 Certificate.
    3. Hybrid Mode (-Provider Both):
       Audits both Local On-Premises AD DS and Cloud Microsoft Entra ID in one run.
================================================================================
.SYNOPSIS
    Generates a security audit CSV report of inactive user accounts (default: >90 days
    since last logon) in Local Active Directory (AD DS) and/or Cloud Microsoft Entra ID.

.DESCRIPTION
    Local network and cloud identity security require regular auditing of stale and
    dormant accounts. Get-InactiveUsersReport.ps1 searches for enabled user accounts
    that have not authenticated for more than a configurable threshold (default: 90 days)
    and exports the findings to a UTF-8 CSV file in C:\Logs\.

    Key Features:
    - Zero-Parameter Help (-Help / -h): Displays full usage instructions, examples,
      Entra ID non-interactive setup guide, version, and author details when run
      without parameters.
    - Dual Directory Support: Local Active Directory (AD DS) and Cloud Microsoft
      Entra ID (Microsoft Graph SDK), or Both.
    - Language-Independent UAC Auto-Elevation: Uses well-known Windows SID
      S-1-5-32-544 (BuiltInAdministratorsSid) for full compatibility across Polish
      ("Administratorzy") and English ("Administrators") Windows systems.
    - Defensive Input Sanitization: Protects against command injection, invalid paths,
      and unsafe LDAP/OData filter characters.
    - Detailed Audit Logging: Writes timestamped execution logs to
      C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs.

.PARAMETER Run
    Switch parameter. Executes the inactive users audit with default settings
    (90 days threshold, Local AD mode, exporting to C:\Logs\).
    Aliases: -Audit, -All

.PARAMETER InactiveDays
    Number of days of inactivity required to flag a user account as stale/inactive.
    Calculates $DataGraniczna = (Get-Date).AddDays(-$InactiveDays). Default: 90.
    Aliases: -Days, -ThresholdDays

.PARAMETER Provider
    Target directory environment to audit:
      - 'AD' / 'Local' / 'LocalAD' / 'OnPrem'      : Local Active Directory (AD DS). Default.
      - 'EntraID' / 'Cloud' / 'CloudAD' / 'AzureAD': Cloud Microsoft Entra ID (Graph SDK).
      - 'Both'                                     : Audits both Local AD and Cloud Entra ID.
    Aliases: -Mode, -Target, -Directory

.PARAMETER OutputPath
    Custom file path for the exported UTF-8 CSV report.
    If omitted, automatically saves to:
    C:\Logs\<yyyyMMdd_HHmmss>Get-InactiveUsersReport<ADServerName>nieaktywni_uzytkownicy.csv
    Aliases: -CsvPath, -ExportCsv, -Path

.PARAMETER Delimiter
    CSV field delimiter character (',' or ';' or Tab). Default: ','.

.PARAMETER SimpleCsv
    Switch parameter. Exports strictly the three classic columns:
    Name, SamAccountName, LastLogonDate.
    When omitted (default), includes extended audit columns: Name, SamAccountName,
    DisplayName, UserPrincipalName, LastLogonDate, DaysInactive, Enabled, Department,
    Title, WhenCreated, DirectorySource, ServerOrTenant.

.PARAMETER SearchBase
    Optional Distinguished Name (DN) of an Organizational Unit (OU) to scope the
    Local Active Directory search (e.g., "OU=Pracownicy,DC=firma,DC=local").
    Aliases: -OU, -OrganizationalUnit

.PARAMETER DomainController
    Optional specific Active Directory Domain Controller FQDN or IP address to query.
    If omitted, automatically discovers the active Domain Controller for the domain.
    Aliases: -Server, -DC

.PARAMETER Department
    Optional filter to include only users belonging to a specific Department.

.PARAMETER IncludeDisabled
    Switch parameter. Includes disabled accounts in addition to enabled accounts.
    By default, only enabled accounts (Enabled -eq $true) are queried.

.PARAMETER IncludeNeverLoggedOn
    Switch parameter. Also includes enabled accounts that have never logged on
    (LastLogonDate -eq $null) and were created prior to the cutoff date.

.PARAMETER PassThru
    Switch parameter. Outputs the discovered inactive user objects to the PowerShell
    pipeline in addition to exporting the CSV report.

.PARAMETER TenantId
    Microsoft Entra ID Directory (Tenant) ID for Cloud AD mode authentication.
    Aliases: -Tenant, -DirectoryId

.PARAMETER ClientId
    Microsoft Entra ID Application (Client) ID for non-interactive Cloud AD authentication.
    Aliases: -AppId, -ApplicationId

.PARAMETER ClientSecret
    Microsoft Entra ID Client Secret string for non-interactive Cloud AD authentication.
    Aliases: -Secret

.PARAMETER ClientSecretSecure
    Microsoft Entra ID Client Secret provided as a SecureString.

.PARAMETER CertificateThumbprint
    Thumbprint of an X.509 Certificate installed in Cert:\CurrentUser\My or
    Cert:\LocalMachine\My for non-interactive Cloud AD authentication.
    Aliases: -Thumbprint

.PARAMETER DryRun
    Switch parameter. Runs in simulation mode with sample audit records to verify
    CSV export formatting and logging when testing outside a domain environment.
    Aliases: -Simulate, -Preview

.PARAMETER SkipAdminCheck
    Switch parameter. Skips the automatic UAC Administrator privilege check.

.PARAMETER LogPath
    Custom file path for the execution log file.
    Default: C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs
    Aliases: -l, -Log

.PARAMETER NoLog
    Switch parameter. Disables writing execution logs to disk.

.PARAMETER Help
    Displays the interactive help screen, usage examples, Entra ID setup guide,
    author information, and script version.
    Aliases: -h

.EXAMPLE
    .\Get-InactiveUsersReport.ps1
    Displays the help screen, usage examples, version, and author details.

.EXAMPLE
    .\Get-InactiveUsersReport.ps1 -Run
    Finds all enabled Local Active Directory users who have not logged on in the
    last 90 days and exports them to:
    C:\Logs\<yyyyMMdd_HHmmss>Get-InactiveUsersReport<ADServer>nieaktywni_uzytkownicy.csv

.EXAMPLE
    .\Get-InactiveUsersReport.ps1 -InactiveDays 90 -SimpleCsv
    Executes the exact core AD audit query for users inactive >90 days and exports
    columns Name, SamAccountName, LastLogonDate to C:\Logs\.

.EXAMPLE
    .\Get-InactiveUsersReport.ps1 -Provider LocalAD -InactiveDays 60 -SearchBase "OU=Pracownicy,DC=firma,DC=local" -IncludeNeverLoggedOn
    Audits Local Active Directory within a specific OU for enabled accounts inactive
    for over 60 days (including accounts that have never logged on).

.EXAMPLE
    .\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90
    Connects interactively to Microsoft Entra ID (Cloud AD) and exports enabled cloud
    users whose last sign-in was more than 90 days ago.

.EXAMPLE
    .\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90 `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -ClientSecret "YourClientSecretValue"
    Audits Cloud Microsoft Entra ID non-interactively (unattended mode) using an
    Entra ID App Registration and Client Secret.

.NOTES
    Author  : Roman Pindela
    Email   : roman.pindela@gmail.com
    GitHub  : https://github.com/romanpindela
    Version : 1.2.0
#>

[CmdletBinding(DefaultParameterSetName = 'Audit')]
param(
    [Parameter(ParameterSetName = 'Audit')]
    [Alias('Audit', 'All')]
    [switch]$Run,

    [Parameter(ParameterSetName = 'Audit', Position = 0)]
    [Alias('Days', 'ThresholdDays')]
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('Mode', 'Target', 'Directory')]
    [ValidateSet('AD', 'Local', 'LocalAD', 'OnPrem', 'EntraID', 'Cloud', 'CloudAD', 'AzureAD', 'Both')]
    [string]$Provider = 'AD',

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('CsvPath', 'ExportCsv', 'Path')]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'Audit')]
    [ValidateSet(',', ';', "`t")]
    [string]$Delimiter = ',',

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$SimpleCsv,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('OU', 'OrganizationalUnit')]
    [string]$SearchBase,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('Server', 'DC')]
    [string]$DomainController,

    [Parameter(ParameterSetName = 'Audit')]
    [string]$Department,

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$IncludeDisabled,

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$IncludeNeverLoggedOn,

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$PassThru,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('Tenant', 'DirectoryId')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('AppId', 'ApplicationId')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('Secret')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'Audit')]
    [System.Security.SecureString]$ClientSecretSecure,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('Thumbprint')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('Simulate', 'Preview')]
    [switch]$DryRun,

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$SkipAdminCheck,

    [Parameter(ParameterSetName = 'Audit')]
    [Alias('l', 'Log')]
    [string]$LogPath,

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$NoLog,

    [Parameter(ParameterSetName = 'Help', Mandatory = $true)]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==============================================================================
# GLOBAL SCRIPT METADATA & STATE
# ==============================================================================
$script:ScriptName      = "Get-InactiveUsersReport"
$script:ScriptVersion   = "1.2.0"
$script:ScriptDate      = "2026-10-17"
$script:ScriptAuthor    = "Roman Pindela"
$script:ScriptEmail     = "roman.pindela@gmail.com"
$script:ScriptGitHub    = "https://github.com/romanpindela"
$script:ActiveLogFile   = $null
$script:StartTimestamp  = (Get-Date).ToString("yyyyMMdd_HHmmss")

# ==============================================================================
# HELP & DOCUMENTATION DISPLAY (-Help / -h / Zero-Parameters)
# ==============================================================================
function Show-ScriptHelp {
    $helpText = @"
================================================================================
  SCRIPT  : Get-InactiveUsersReport.ps1
  VERSION : $script:ScriptVersion ($script:ScriptDate)
  AUTHOR  : $script:ScriptAuthor
  CONTACT : $script:ScriptEmail | $script:ScriptGitHub
================================================================================

DESCRIPTION:
    Local network and cloud identity security require periodic auditing of dormant
    accounts. This script discovers enabled user accounts that have not logged on
    for more than N days (default: 90 days) and exports them to a UTF-8 CSV report:
      C:\Logs\<datagodzina>Get-InactiveUsersReport<nazwaserweraad>nieaktywni_uzytkownicy.csv

    Supports Dual Directory Modes:
      1. Local Active Directory (-Provider AD / LocalAD):
         Uses Get-ADUser against On-Premises Windows Server Active Directory:
           `$DataGraniczna = (Get-Date).AddDays(-90)
           Get-ADUser -Filter {LastLogonDate -lt `$DataGraniczna -and Enabled -eq `$true} ``
               -Properties LastLogonDate, DisplayName |
           Select-Object Name, SamAccountName, LastLogonDate |
           Export-Csv -Path "C:\Logs\<datagodzina>Get-InactiveUsersReport<nazwaserweraad>nieaktywni_uzytkownicy.csv" ``
               -NoTypeInformation -Encoding UTF8
      2. Cloud Active Directory (-Provider EntraID / CloudAD):
         Uses Microsoft Graph PowerShell SDK (Get-MgUser -Property SignInActivity)
         to audit inactive cloud accounts in Microsoft Entra ID (Azure AD).
      3. Hybrid Mode (-Provider Both):
         Audits both Local AD DS and Cloud Microsoft Entra ID in a single run.

--------------------------------------------------------------------------------
HOW TO CONFIGURE ENTRA ID FOR NON-INTERACTIVE / UNATTENDED AUTHENTICATION:
(Only via API Keys / Credentials and Entra ID Microsoft Graph SDK Permissions)
--------------------------------------------------------------------------------
To run this script in unattended / non-interactive mode against Microsoft Entra ID
(e.g., Windows Task Scheduler, SIEM/SOC compliance jobs, CI/CD) without prompts:

Step 1: Register an Application in Microsoft Entra ID
    1. Sign in to Microsoft Entra admin center (https://entra.microsoft.com).
    2. Navigate to: Identity > Applications > App registrations > New registration.
    3. Name: 'EntraID-InactiveUsers-Auditor'.
    4. Supported account types: 'Accounts in this organizational directory only'.
    5. Click 'Register' and copy:
       - Application (client) ID  -> pass to -ClientId
       - Directory (tenant) ID    -> pass to -TenantId

Step 2: Grant Microsoft Graph API Application Permissions (App-Only)
    1. In the App Registration, go to: Manage > API permissions > Add a permission.
    2. Select 'Microsoft Graph' > 'Application permissions' (NOT Delegated).
    3. Search for and select the following permissions required for SignInActivity:
       * AuditLog.Read.All   (Required to read SignInActivity / LastSignInDateTime)
       * User.Read.All       (Required to read all user profiles and status)
       * Directory.Read.All  (Required to read directory organization metadata)
    4. Click 'Add permissions'.
    5. Click 'Grant admin consent for <Your Tenant>' and verify green checkmarks.

Step 3: Configure Non-Interactive Credentials (Choose Option A or Option B)
    Option A: Client Secret (API Key / Secret)
      1. Go to: Manage > Certificates & secrets > Client secrets > New client secret.
      2. Enter a description, select expiration, and click 'Add'.
      3. Copy the secret 'Value' immediately (not the Secret ID).
      4. Run the script non-interactively:
         .\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90 ``
             -TenantId "<TenantId>" -ClientId "<ClientId>" -ClientSecret "<SecretValue>"

    Option B: X.509 Certificate (Recommended for Production Scheduled Tasks)
      1. Generate a self-signed certificate in PowerShell:
         `$cert = New-SelfSignedCertificate -Subject "CN=EntraInactiveUsersAuditor" ``
             -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable ``
             -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
         Export-Certificate -Cert `$cert -FilePath "C:\Logs\EntraInactiveUsersAuditor.cer"
      2. Upload 'EntraInactiveUsersAuditor.cer' in Entra Admin Center under:
         Manage > Certificates & secrets > Certificates > Upload certificate.
      3. Run the script non-interactively:
         .\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90 ``
             -TenantId "<TenantId>" -ClientId "<ClientId>" -CertificateThumbprint `$cert.Thumbprint

--------------------------------------------------------------------------------
USAGE EXAMPLES:
--------------------------------------------------------------------------------
  # 1. Audit Local AD for enabled users inactive for >90 days (default settings):
  .\Get-InactiveUsersReport.ps1 -Run

  # 2. Audit Local AD for users inactive >90 days with classic 3-column CSV output:
  .\Get-InactiveUsersReport.ps1 -InactiveDays 90 -SimpleCsv

  # 3. Audit Local AD on a specific Domain Controller and Organizational Unit (OU):
  .\Get-InactiveUsersReport.ps1 -Provider LocalAD -InactiveDays 120 ``
      -DomainController "DC01.firma.local" ``
      -SearchBase "OU=Pracownicy,DC=firma,DC=local" ``
      -IncludeNeverLoggedOn

  # 4. Audit Cloud Microsoft Entra ID interactively (prompts for admin login):
  .\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90

  # 5. Audit Cloud Microsoft Entra ID non-interactively via Client Secret:
  .\Get-InactiveUsersReport.ps1 -Provider CloudAD -InactiveDays 90 ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -ClientSecret "YourClientSecretValue"

  # 6. Audit BOTH Local Active Directory and Cloud Entra ID in one execution:
  .\Get-InactiveUsersReport.ps1 -Provider Both -InactiveDays 90

  # 7. Run in Dry-Run simulation mode (generates sample report without live AD):
  .\Get-InactiveUsersReport.ps1 -Run -DryRun

--------------------------------------------------------------------------------
PARAMETERS:
--------------------------------------------------------------------------------
  -Run, -Audit, -All            Run the audit with default parameters (90 days, Local AD).
  -InactiveDays, -Days          Inactivity threshold in days (Default: 90).
  -Provider, -Mode              Target directory: 'AD'/'LocalAD' (default), 'EntraID'/'CloudAD', 'Both'.
  -OutputPath, -CsvPath         Custom CSV path. Default:
                                C:\Logs\<datagodzina>Get-InactiveUsersReport<ADServer>nieaktywni_uzytkownicy.csv
  -Delimiter                    CSV delimiter character: ',' (default), ';', or Tab.
  -SimpleCsv                    Export only Name, SamAccountName, LastLogonDate columns.
  -SearchBase, -OU              Organizational Unit DN to scope Local AD search.
  -DomainController, -Server    Specific Active Directory Domain Controller FQDN/IP.
  -Department                   Filter inactive users by Department name.
  -IncludeDisabled              Include disabled user accounts in the audit report.
  -IncludeNeverLoggedOn         Include enabled accounts that have never logged on.
  -PassThru                     Return inactive user objects to the PowerShell pipeline.
  -TenantId                     Entra ID Tenant ID (for Cloud AD mode).
  -ClientId                     Entra ID App Client ID (for non-interactive Cloud AD auth).
  -ClientSecret                 Entra ID Client Secret (for non-interactive Cloud AD auth).
  -CertificateThumbprint        Certificate thumbprint (for non-interactive Cloud AD auth).
  -DryRun, -Simulate            Run simulation mode with sample data.
  -SkipAdminCheck               Skip automatic UAC Administrator privilege elevation.
  -LogPath, -Log                Custom log file path.
  -NoLog                        Disable file logging.
  -Help, -h                     Display this help screen and exit.

LOGGING:
  Detailed execution logs are automatically written by default to:
  C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs

SECURITY & UNBLOCKING:
  After downloading this script from GitHub, unblock the file before execution:
  Unblock-File -Path .\Get-InactiveUsersReport.ps1
================================================================================
"@
    Write-Host $helpText -ForegroundColor Cyan
}

# ==============================================================================
# ZERO-PARAMETER & HELP CHECK
# ==============================================================================
if ($Help -or $PSBoundParameters.Count -eq 0) {
    Show-ScriptHelp
    exit 0
}

# ==============================================================================
# NORMALIZE PROVIDER MODE ('AD', 'EntraID', 'Both')
# ==============================================================================
$normalizedProvider = switch ($Provider) {
    { $_ -in @('AD', 'Local', 'LocalAD', 'OnPrem') }           { 'AD' }
    { $_ -in @('EntraID', 'Cloud', 'CloudAD', 'AzureAD') }     { 'EntraID' }
    'Both'                                                     { 'Both' }
    default                                                    { 'AD' }
}

# ==============================================================================
# LANGUAGE-INDEPENDENT ADMINISTRATOR SID CHECK & AUTO-ELEVATION
# (Supports both Polish "Administratorzy" and English "Administrators" via SID)
# ==============================================================================
function Assert-AdministratorPrivileges {
    # Check if the script is already running with Administrator privileges using SID (language-independent)
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $adminSid  = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::BuiltInAdministratorsSid, $null)

    $isAdmin = $principal.IsInRole($adminSid)

    if (-not $isAdmin) {
        # If not running as Admin, prompt for UAC consent and relaunch the script with elevated privileges
        Write-Host "Missing Administrator privileges. Requesting elevation..." -ForegroundColor Yellow
        $escapedArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
        foreach ($key in $PSBoundParameters.Keys) {
            $val = $PSBoundParameters[$key]
            if ($val -is [switch]) {
                if ($val.IsPresent) {
                    $escapedArgs += "-$key"
                }
            } elseif ($val -is [bool]) {
                $escapedArgs += "-${key}:`$$val"
            } elseif ($val -is [array]) {
                $joined = ($val | ForEach-Object { "`"$_`"" }) -join ","
                $escapedArgs += "-$key $joined"
            } elseif ($val -isnot [System.Security.SecureString]) {
                $escapedArgs += "-$key `"$val`""
            }
        }
        Start-Process powershell.exe -ArgumentList ($escapedArgs -join " ") -Verb RunAs
        Exit
    }
}

if (-not $SkipAdminCheck -and -not $DryRun -and ($normalizedProvider -eq 'AD' -or $normalizedProvider -eq 'Both')) {
    Assert-AdministratorPrivileges
}

# ==============================================================================
# LOGGING ENGINE
# Default: C:\Logs\<dataigodzina>-nazwaskryptu-nazwakomputera-uzytkownik.logs
# ==============================================================================
function Initialize-ScriptLogging {
    if ($NoLog) {
        $script:ActiveLogFile = $null
        return
    }

    if ([string]::IsNullOrWhiteSpace($LogPath)) {
        $defaultLogDir = "C:\Logs"
        if (-not (Test-Path -LiteralPath $defaultLogDir)) {
            try {
                New-Item -Path $defaultLogDir -ItemType Directory -Force | Out-Null
            } catch {
                $defaultLogDir = Join-Path -Path $PSScriptRoot -ChildPath "logs"
                if (-not (Test-Path -LiteralPath $defaultLogDir)) {
                    New-Item -Path $defaultLogDir -ItemType Directory -Force | Out-Null
                }
            }
        }
        $compName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "UNKNOWN-PC" }
        $userName = if ($env:USERNAME) { $env:USERNAME } else { "UNKNOWN-USER" }
        $fileName = "$($script:StartTimestamp)-$($script:ScriptName)-${compName}-${userName}.logs"
        $script:ActiveLogFile = Join-Path -Path $defaultLogDir -ChildPath $fileName
    } else {
        $parentDir = Split-Path -Path $LogPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }
        $script:ActiveLogFile = $LogPath
    }

    $logHeader = @"
================================================================================
  Script Name   : $script:ScriptName.ps1
  Version       : $script:ScriptVersion
  Author        : $script:ScriptAuthor ($script:ScriptEmail)
  GitHub        : $script:ScriptGitHub
  Start Time    : $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
  Computer Name : $env:COMPUTERNAME
  Executed By   : $env:USERDOMAIN\$env:USERNAME
  OS Version    : $([System.Environment]::OSVersion.VersionString)
  PS Version    : $($PSVersionTable.PSVersion.ToString())
  Provider Mode : $normalizedProvider
  Inactive Days : $InactiveDays
  Log File      : $script:ActiveLogFile
================================================================================
"@
    try {
        Set-Content -LiteralPath $script:ActiveLogFile -Value $logHeader -Encoding UTF8 -Force
    } catch {
        Write-Warning "Could not initialize log file at '$script:ActiveLogFile': $_"
        $script:ActiveLogFile = $null
    }
}

function Write-ScriptLog {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [ValidateSet('INFO', 'SUCCESS', 'WARN', 'ERROR', 'DEBUG', 'STEP')]
        [string]$Level = 'INFO',

        [switch]$NoConsole
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $formatted = "[$timestamp] [$($Level.PadRight(7))] $Message"

    if ($script:ActiveLogFile) {
        try {
            Add-Content -LiteralPath $script:ActiveLogFile -Value $formatted -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {
            # Ignore transient file lock issues
        }
    }

    if (-not $NoConsole) {
        switch ($Level) {
            'SUCCESS' { Write-Host $formatted -ForegroundColor Green }
            'WARN'    { Write-Host $formatted -ForegroundColor Yellow }
            'ERROR'   { Write-Host $formatted -ForegroundColor Red }
            'STEP'    { Write-Host $formatted -ForegroundColor Magenta }
            'DEBUG'   { Write-Host $formatted -ForegroundColor DarkGray }
            default   { Write-Host $formatted -ForegroundColor Cyan }
        }
    }
}

Initialize-ScriptLogging
Write-ScriptLog -Level INFO -Message "Starting $script:ScriptName v$script:ScriptVersion (Provider: $normalizedProvider, InactiveDays: $InactiveDays)."
if ($script:ActiveLogFile) {
    Write-ScriptLog -Level INFO -Message "Execution log file initialized at: $script:ActiveLogFile"
}

# ==============================================================================
# DEFENSIVE INPUT VALIDATION & SANITIZATION
# ==============================================================================
$unsafeCharsPattern = '[\$`;&|><\x00\r\n]'

function Assert-SafeInputString {
    param(
        [string]$Value,
        [string]$ParameterName
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    if ($Value -match $unsafeCharsPattern) {
        Write-ScriptLog -Level ERROR -Message "Security violation: Parameter -$ParameterName contains disallowed characters."
        throw "Parameter -$ParameterName contains disallowed or unsafe characters."
    }
}

function Test-SafeFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath,
        [string]$ParameterName = "OutputPath"
    )
    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        throw "Parameter -$ParameterName cannot be empty."
    }
    if ($InputPath -match '[\x00\|<>\?\*]') {
        Write-ScriptLog -Level ERROR -Message "Security violation: Parameter -$ParameterName contains illegal file path characters: '$InputPath'."
        throw "Parameter -$ParameterName contains illegal file path characters: '$InputPath'."
    }
}

function Get-SanitizedFileNameSegment {
    param([string]$RawName)
    if ([string]::IsNullOrWhiteSpace($RawName)) { return "UnknownServer" }
    $cleaned = $RawName -replace '[^a-zA-Z0-9._-]', '_'
    return $cleaned.Trim('_')
}

Assert-SafeInputString -Value $DomainController -ParameterName "DomainController"
Assert-SafeInputString -Value $Department -ParameterName "Department"
Assert-SafeInputString -Value $TenantId -ParameterName "TenantId"
Assert-SafeInputString -Value $ClientId -ParameterName "ClientId"
Assert-SafeInputString -Value $CertificateThumbprint -ParameterName "CertificateThumbprint"

if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    Assert-SafeInputString -Value $SearchBase -ParameterName "SearchBase"
    if ($SearchBase -notmatch '^(?i)(OU|CN|DC)=') {
        Write-ScriptLog -Level ERROR -Message "Invalid Distinguished Name in -SearchBase: '$SearchBase'. Expected format like 'OU=Users,DC=domain,DC=local'."
        exit 1
    }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Test-SafeFilePath -InputPath $OutputPath -ParameterName "OutputPath"
}

# Calculate the cutoff date ($DataGraniczna)
$DataGraniczna = (Get-Date).AddDays(-$InactiveDays)
Write-ScriptLog -Level INFO -Message "Calculated inactivity cutoff date (`$DataGraniczna): $($DataGraniczna.ToString('yyyy-MM-dd HH:mm:ss')) ($InactiveDays days ago)."

$allInactiveAccounts = New-Object System.Collections.Generic.List[PSObject]
$resolvedServerLabel = $null

# ==============================================================================
# MODE 1: LOCAL ON-PREMISES ACTIVE DIRECTORY (AD DS)
# ==============================================================================
if ($normalizedProvider -eq 'AD' -or $normalizedProvider -eq 'Both') {
    Write-ScriptLog -Level STEP -Message "Starting Local Active Directory (AD DS) inactive user audit..."

    if ($DryRun) {
        $adServerName = if (-not [string]::IsNullOrWhiteSpace($DomainController)) { $DomainController } elseif ($env:LOGONSERVER) { $env:LOGONSERVER.TrimStart('\') } else { "DC01.corp.local" }
        $resolvedServerLabel = Get-SanitizedFileNameSegment -RawName $adServerName
        Write-ScriptLog -Level WARN -Message "[DryRun] Simulating Local Active Directory query against server '$adServerName'..."

        $sampleAdUsers = @(
            [PSCustomObject]@{
                Name              = "Jan Kowalski"
                SamAccountName    = "jkowalski"
                DisplayName       = "Jan Kowalski"
                UserPrincipalName = "jkowalski@corp.local"
                LastLogonDate     = (Get-Date).AddDays(-($InactiveDays + 45))
                DaysInactive      = ($InactiveDays + 45)
                Enabled           = $true
                Department        = "IT"
                Title             = "System Administrator"
                WhenCreated       = (Get-Date).AddDays(-400)
                DirectorySource   = "LocalAD"
                ServerOrTenant    = $adServerName
            },
            [PSCustomObject]@{
                Name              = "Anna Nowak"
                SamAccountName    = "anowak"
                DisplayName       = "Anna Nowak"
                UserPrincipalName = "anowak@corp.local"
                LastLogonDate     = (Get-Date).AddDays(-($InactiveDays + 18))
                DaysInactive      = ($InactiveDays + 18)
                Enabled           = $true
                Department        = "Finance"
                Title             = "Senior Accountant"
                WhenCreated       = (Get-Date).AddDays(-320)
                DirectorySource   = "LocalAD"
                ServerOrTenant    = $adServerName
            }
        )

        foreach ($u in $sampleAdUsers) {
            if ([string]::IsNullOrWhiteSpace($Department) -or $u.Department -like "*$Department*") {
                $allInactiveAccounts.Add($u)
            }
        }
        Write-ScriptLog -Level SUCCESS -Message "[DryRun] Simulated Local AD audit returned $($allInactiveAccounts.Count) inactive account(s)."
    } else {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Write-ScriptLog -Level ERROR -Message "The 'ActiveDirectory' PowerShell module (RSAT-AD-PowerShell) is not installed on this machine."
            Write-ScriptLog -Level INFO  -Message "Install on Windows 10/11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            Write-ScriptLog -Level INFO  -Message "Install on Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell"
            Write-ScriptLog -Level INFO  -Message "Tip: Use '-Provider EntraID' for Cloud AD auditing or '-DryRun' for simulation."
            exit 1
        }

        Import-Module ActiveDirectory -ErrorAction Stop
        Write-ScriptLog -Level INFO -Message "Loaded 'ActiveDirectory' module successfully."

        # Resolve AD Server Name (<nazwaserweraad>)
        $adServerName = $DomainController
        if ([string]::IsNullOrWhiteSpace($adServerName)) {
            try {
                $dcObj = Get-ADDomainController -Discover -ErrorAction Stop
                $adServerName = if ($dcObj.HostName) { [string]$dcObj.HostName } else { [string]$dcObj.Name }
            } catch {
                try {
                    $domObj = Get-ADDomain -ErrorAction Stop
                    $adServerName = [string]$domObj.PDCEmulator
                } catch {
                    $adServerName = if ($env:LOGONSERVER) { $env:LOGONSERVER.TrimStart('\') } else { $env:COMPUTERNAME }
                }
            }
        }

        $resolvedServerLabel = Get-SanitizedFileNameSegment -RawName $adServerName
        Write-ScriptLog -Level INFO -Message "Target Active Directory Server: $adServerName"

        $adQueryParams = @{
            Properties  = @('LastLogonDate', 'DisplayName', 'Name', 'SamAccountName', 'UserPrincipalName', 'Enabled', 'Department', 'Title', 'WhenCreated')
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
            $adQueryParams['Server'] = $DomainController
        }
        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $adQueryParams['SearchBase'] = $SearchBase
            Write-ScriptLog -Level INFO -Message "Scoping AD search to Organizational Unit: $SearchBase"
        }

        try {
            Write-ScriptLog -Level INFO -Message "Executing Get-ADUser query for accounts with LastLogonDate < $($DataGraniczna.ToString('yyyy-MM-dd'))..."

            if (-not $IncludeDisabled -and -not $IncludeNeverLoggedOn) {
                # Exact core filter requested: LastLogonDate -lt $DataGraniczna -and Enabled -eq $true
                $adUsers = @(Get-ADUser -Filter { LastLogonDate -lt $DataGraniczna -and Enabled -eq $true } @adQueryParams)
            } elseif (-not $IncludeDisabled -and $IncludeNeverLoggedOn) {
                $adUsers = @(Get-ADUser -Filter { Enabled -eq $true } @adQueryParams | Where-Object {
                    ($null -ne $_.LastLogonDate -and $_.LastLogonDate -lt $DataGraniczna) -or
                    ($null -eq $_.LastLogonDate -and $_.WhenCreated -lt $DataGraniczna)
                })
            } elseif ($IncludeDisabled -and -not $IncludeNeverLoggedOn) {
                $adUsers = @(Get-ADUser -Filter { LastLogonDate -lt $DataGraniczna } @adQueryParams)
            } else {
                $adUsers = @(Get-ADUser -Filter * @adQueryParams | Where-Object {
                    ($null -ne $_.LastLogonDate -and $_.LastLogonDate -lt $DataGraniczna) -or
                    ($null -eq $_.LastLogonDate -and $_.WhenCreated -lt $DataGraniczna)
                })
            }

            if (-not [string]::IsNullOrWhiteSpace($Department)) {
                $adUsers = @($adUsers | Where-Object { $_.Department -and $_.Department -like "*$Department*" })
            }

            $now = Get-Date
            foreach ($user in $adUsers) {
                $daysStale = if ($null -ne $user.LastLogonDate) {
                    [math]::Round(($now - [datetime]$user.LastLogonDate).TotalDays, 0)
                } else {
                    "NeverLoggedOn"
                }

                $allInactiveAccounts.Add([PSCustomObject]@{
                    Name              = $user.Name
                    SamAccountName    = $user.SamAccountName
                    DisplayName       = $user.DisplayName
                    UserPrincipalName = $user.UserPrincipalName
                    LastLogonDate     = $user.LastLogonDate
                    DaysInactive      = $daysStale
                    Enabled           = $user.Enabled
                    Department        = $user.Department
                    Title             = $user.Title
                    WhenCreated       = $user.WhenCreated
                    DirectorySource   = "LocalAD"
                    ServerOrTenant    = $adServerName
                })
            }

            Write-ScriptLog -Level SUCCESS -Message "Local AD query completed. Found $($adUsers.Count) inactive user account(s)."
        } catch {
            Write-ScriptLog -Level ERROR -Message "Failed to query Local Active Directory on '$adServerName': $_"
            throw
        }
    }
}

# ==============================================================================
# MODE 2: CLOUD ACTIVE DIRECTORY (MICROSOFT ENTRA ID / AZURE AD VIA GRAPH SDK)
# ==============================================================================
if ($normalizedProvider -eq 'EntraID' -or $normalizedProvider -eq 'Both') {
    Write-ScriptLog -Level STEP -Message "Starting Cloud Active Directory (Microsoft Entra ID) inactive user audit..."

    if ($DryRun) {
        $cloudLabel = if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId } else { "EntraID-Cloud" }
        if ([string]::IsNullOrWhiteSpace($resolvedServerLabel)) {
            $resolvedServerLabel = Get-SanitizedFileNameSegment -RawName $cloudLabel
        } else {
            $resolvedServerLabel = "$resolvedServerLabel-EntraID"
        }

        Write-ScriptLog -Level WARN -Message "[DryRun] Simulating Microsoft Entra ID Graph API SignInActivity query..."
        $sampleCloudUsers = @(
            [PSCustomObject]@{
                Name              = "Piotr Wisniewski"
                SamAccountName    = "pwisniewski"
                DisplayName       = "Piotr Wisniewski"
                UserPrincipalName = "pwisniewski@contoso.onmicrosoft.com"
                LastLogonDate     = (Get-Date).AddDays(-($InactiveDays + 30))
                DaysInactive      = ($InactiveDays + 30)
                Enabled           = $true
                Department        = "Sales"
                Title             = "Account Executive"
                WhenCreated       = (Get-Date).AddDays(-500)
                DirectorySource   = "EntraID"
                ServerOrTenant    = $cloudLabel
            }
        )
        foreach ($cu in $sampleCloudUsers) {
            if ([string]::IsNullOrWhiteSpace($Department) -or $cu.Department -like "*$Department*") {
                $allInactiveAccounts.Add($cu)
            }
        }
        Write-ScriptLog -Level SUCCESS -Message "[DryRun] Simulated Cloud Entra ID audit added $($sampleCloudUsers.Count) inactive account(s)."
    } else {
        $requiredGraphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
        $missingModules = @()
        foreach ($mod in $requiredGraphModules) {
            if (-not (Get-Module -Name $mod -ListAvailable)) {
                $missingModules += $mod
            }
        }

        if ($missingModules.Count -gt 0) {
            Write-ScriptLog -Level ERROR -Message "Missing required Microsoft Graph PowerShell SDK module(s): $($missingModules -join ', ')."
            Write-ScriptLog -Level INFO  -Message "Install via: Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser -Force"
            exit 1
        }

        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Users -ErrorAction Stop

        # Connect to Microsoft Graph (Non-Interactive App-Only OR Interactive Admin Login)
        try {
            if (-not [string]::IsNullOrWhiteSpace($TenantId) -and -not [string]::IsNullOrWhiteSpace($ClientId)) {
                if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
                    Write-ScriptLog -Level INFO -Message "Authenticating to Microsoft Graph non-interactively using X.509 Certificate ($CertificateThumbprint)..."
                    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
                } elseif ($null -ne $ClientSecretSecure -or -not [string]::IsNullOrWhiteSpace($ClientSecret)) {
                    Write-ScriptLog -Level INFO -Message "Authenticating to Microsoft Graph non-interactively using Client Secret (AppId: $ClientId)..."
                    $secSecret = if ($null -ne $ClientSecretSecure) {
                        $ClientSecretSecure
                    } else {
                        ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
                    }
                    $clientCred = New-Object System.Management.Automation.PSCredential($ClientId, $secSecret)
                    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $clientCred -NoWelcome -ErrorAction Stop
                } else {
                    throw "When specifying -TenantId and -ClientId for non-interactive authentication, you must also provide -ClientSecret, -ClientSecretSecure, or -CertificateThumbprint."
                }
            } else {
                $mgContext = Get-MgContext -ErrorAction SilentlyContinue
                $requiredScopes = @('AuditLog.Read.All', 'User.Read.All')
                $needsLogin = $true
                if ($null -ne $mgContext -and $mgContext.Account -or $mgContext.AppName) {
                    $needsLogin = $false
                }
                if ($needsLogin) {
                    Write-ScriptLog -Level INFO -Message "Connecting interactively to Microsoft Graph (Scopes: AuditLog.Read.All, User.Read.All, Directory.Read.All)..."
                    $connectParams = @{
                        Scopes      = @('AuditLog.Read.All', 'User.Read.All', 'Directory.Read.All')
                        NoWelcome   = $true
                        ErrorAction = 'Stop'
                    }
                    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
                        $connectParams['TenantId'] = $TenantId
                    }
                    Connect-MgGraph @connectParams
                } else {
                    Write-ScriptLog -Level INFO -Message "Reusing existing Microsoft Graph session (TenantId: $($mgContext.TenantId))."
                }
            }

            $activeContext = Get-MgContext -ErrorAction Stop
            $tenantIdentifier = if ($activeContext.TenantId) { [string]$activeContext.TenantId } elseif (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId } else { "EntraID" }
            if ([string]::IsNullOrWhiteSpace($resolvedServerLabel)) {
                $resolvedServerLabel = Get-SanitizedFileNameSegment -RawName "EntraID-$($tenantIdentifier.Substring(0, [math]::Min(8, $tenantIdentifier.Length)))"
            } else {
                $resolvedServerLabel = "$resolvedServerLabel-EntraID"
            }

            Write-ScriptLog -Level INFO -Message "Querying Microsoft Entra ID users and SignInActivity via Get-MgUser..."
            $mgProperties = @(
                'Id', 'DisplayName', 'UserPrincipalName', 'MailNickname',
                'OnPremisesSamAccountName', 'AccountEnabled', 'Department',
                'JobTitle', 'CreatedDateTime', 'SignInActivity'
            )

            $cloudUsers = @(Get-MgUser -All -Property $mgProperties -ErrorAction Stop)
            Write-ScriptLog -Level INFO -Message "Retrieved $($cloudUsers.Count) total user object(s) from Microsoft Entra ID. Filtering for inactivity > $InactiveDays days..."

            $now = Get-Date
            $matchedCloudCount = 0

            foreach ($mgUser in $cloudUsers) {
                if (-not $IncludeDisabled -and $mgUser.AccountEnabled -ne $true) {
                    continue
                }

                if (-not [string]::IsNullOrWhiteSpace($Department)) {
                    if ([string]::IsNullOrWhiteSpace($mgUser.Department) -or $mgUser.Department -notlike "*$Department*") {
                        continue
                    }
                }

                # Determine most recent interactive or non-interactive sign-in timestamp
                $lastInteractive    = $null
                $lastNonInteractive = $null
                if ($null -ne $mgUser.SignInActivity) {
                    $lastInteractive    = $mgUser.SignInActivity.LastSignInDateTime
                    $lastNonInteractive = $mgUser.SignInActivity.LastNonInteractiveSignInDateTime
                }

                $effectiveLastSignIn = $null
                if ($null -ne $lastInteractive -and $null -ne $lastNonInteractive) {
                    $effectiveLastSignIn = if ([datetime]$lastInteractive -ge [datetime]$lastNonInteractive) { [datetime]$lastInteractive } else { [datetime]$lastNonInteractive }
                } elseif ($null -ne $lastInteractive) {
                    $effectiveLastSignIn = [datetime]$lastInteractive
                } elseif ($null -ne $lastNonInteractive) {
                    $effectiveLastSignIn = [datetime]$lastNonInteractive
                }

                $isStale = $false
                if ($null -ne $effectiveLastSignIn) {
                    if ($effectiveLastSignIn -lt $DataGraniczna) {
                        $isStale = $true
                    }
                } elseif ($IncludeNeverLoggedOn) {
                    if ($null -ne $mgUser.CreatedDateTime -and ([datetime]$mgUser.CreatedDateTime) -lt $DataGraniczna) {
                        $isStale = $true
                    }
                }

                if ($isStale) {
                    $matchedCloudCount++
                    $samName = if (-not [string]::IsNullOrWhiteSpace($mgUser.OnPremisesSamAccountName)) {
                        $mgUser.OnPremisesSamAccountName
                    } elseif (-not [string]::IsNullOrWhiteSpace($mgUser.MailNickname)) {
                        $mgUser.MailNickname
                    } else {
                        ($mgUser.UserPrincipalName -split '@')[0]
                    }

                    $daysStale = if ($null -ne $effectiveLastSignIn) {
                        [math]::Round(($now - $effectiveLastSignIn).TotalDays, 0)
                    } else {
                        "NeverLoggedOn"
                    }

                    $allInactiveAccounts.Add([PSCustomObject]@{
                        Name              = $mgUser.DisplayName
                        SamAccountName    = $samName
                        DisplayName       = $mgUser.DisplayName
                        UserPrincipalName = $mgUser.UserPrincipalName
                        LastLogonDate     = $effectiveLastSignIn
                        DaysInactive      = $daysStale
                        Enabled           = $mgUser.AccountEnabled
                        Department        = $mgUser.Department
                        Title             = $mgUser.JobTitle
                        WhenCreated       = $mgUser.CreatedDateTime
                        DirectorySource   = "EntraID"
                        ServerOrTenant    = $tenantIdentifier
                    })
                }
            }

            Write-ScriptLog -Level SUCCESS -Message "Cloud Entra ID query completed. Found $matchedCloudCount inactive user account(s)."
        } catch {
            Write-ScriptLog -Level ERROR -Message "Failed to query Microsoft Entra ID via Microsoft Graph: $_"
            throw
        }
    }
}

# ==============================================================================
# RESOLVE DEFAULT CSV REPORT PATH & EXPORT UTF-8 CSV
# Pattern: C:\Logs\<datagodzina>nazwaskryptu<nazwaserweraad>nieaktywni_uzytkownicy.csv
# ==============================================================================
if ([string]::IsNullOrWhiteSpace($resolvedServerLabel)) {
    $resolvedServerLabel = Get-SanitizedFileNameSegment -RawName $env:COMPUTERNAME
}

$finalCsvPath = if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath
} else {
    $csvDir = "C:\Logs"
    if (-not (Test-Path -LiteralPath $csvDir)) {
        try {
            New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
        } catch {
            $csvDir = Join-Path -Path $PSScriptRoot -ChildPath "logs"
            if (-not (Test-Path -LiteralPath $csvDir)) {
                New-Item -Path $csvDir -ItemType Directory -Force | Out-Null
            }
        }
    }
    $csvFileName = "$($script:StartTimestamp)$($script:ScriptName)${resolvedServerLabel}nieaktywni_uzytkownicy.csv"
    Join-Path -Path $csvDir -ChildPath $csvFileName
}

$csvParentDir = Split-Path -Path $finalCsvPath -Parent
if (-not [string]::IsNullOrWhiteSpace($csvParentDir) -and -not (Test-Path -LiteralPath $csvParentDir)) {
    New-Item -Path $csvParentDir -ItemType Directory -Force | Out-Null
}

# Sort results by LastLogonDate ascending (oldest logons first)
$sortedResults = @($allInactiveAccounts | Sort-Object -Property LastLogonDate, SamAccountName)

if ($SimpleCsv) {
    $exportObjects = @($sortedResults | Select-Object Name, SamAccountName, LastLogonDate)
} else {
    $exportObjects = @($sortedResults | Select-Object Name, SamAccountName, DisplayName, UserPrincipalName, LastLogonDate, DaysInactive, Enabled, Department, Title, WhenCreated, DirectorySource, ServerOrTenant)
}

try {
    $exportObjects | Export-Csv -Path $finalCsvPath -Delimiter $Delimiter -NoTypeInformation -Encoding UTF8 -Force
    Write-ScriptLog -Level SUCCESS -Message "Exported $($exportObjects.Count) inactive user record(s) to CSV: $finalCsvPath"
} catch {
    Write-ScriptLog -Level ERROR -Message "Failed to export CSV report to '$finalCsvPath': $_"
    throw
}

# ==============================================================================
# CONSOLE SUMMARY TABLE & AUDIT STATISTICS
# ==============================================================================
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  INACTIVE USERS SECURITY AUDIT SUMMARY" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ("  Provider Mode        : {0}" -f $normalizedProvider) -ForegroundColor White
Write-Host ("  Target Server/Tenant : {0}" -f $resolvedServerLabel) -ForegroundColor White
Write-Host ("  Inactivity Threshold : > {0} days (Cutoff: {1})" -f $InactiveDays, $DataGraniczna.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
Write-Host ("  Inactive Users Found : {0}" -f $sortedResults.Count) -ForegroundColor $(if ($sortedResults.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host ("  CSV Report Path      : {0}" -f $finalCsvPath) -ForegroundColor Green
if ($script:ActiveLogFile) {
    Write-Host ("  Execution Log File   : {0}" -f $script:ActiveLogFile) -ForegroundColor Gray
}
Write-Host "================================================================================" -ForegroundColor Cyan

if ($sortedResults.Count -gt 0) {
    Write-Host ""
    $sortedResults | Select-Object Name, SamAccountName, LastLogonDate, DaysInactive, Department, DirectorySource | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White
}

Write-ScriptLog -Level INFO -Message "Audit finished successfully. Total inactive accounts: $($sortedResults.Count)."

if ($PassThru) {
    Write-Output $sortedResults
}
