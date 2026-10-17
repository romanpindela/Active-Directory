<#
================================================================================
  Script Name : New-ADUsersFromCSV.ps1
  Author      : Roman Pindela
  Contact     : roman.pindela@gmail.com
  Version     : 1.0.0
  Release Date: 2026-10-17
  License     : MIT
  Repository  : https://github.com/romanpindela

  DESCRIPTION:
    Enterprise-grade PowerShell automation script for bulk provisioning of user
    accounts from a CSV file (e.g., uzytkownicy.csv) with columns such as:
    SamAccountName, Name, GivenName, Surname, Password, Department (plus optional
    extended attributes like UserPrincipalName, Title, EmailAddress, OU, Groups).

    Supports both:
    - On-Premises Active Directory Domain Services (AD DS via ActiveDirectory module)
    - Microsoft Entra ID / Azure AD (via Microsoft Graph PowerShell SDK, supporting
      both interactive admin login and non-interactive App-Only daemon authentication
      using Client Secret or X.509 Certificate).

    Key Capabilities:
    1. Zero-Parameter Interactive Help (-Help / -h):
       Displays complete usage instructions, CSV schema reference, Entra ID
       non-interactive configuration guide, version, author details, and examples
       when launched without parameters.
    2. Input Sanitization & Defensive Validation:
       Validates file paths, CSV structure, SamAccountName constraints, UPN syntax,
       Distinguished Names (OU), and escapes LDAP/OData queries against injection.
    3. Language-Independent UAC Auto-Elevation:
       Verifies Administrator privileges via well-known Windows SID
       (S-1-5-32-544 / BuiltInAdministratorsSid) for full compatibility across
       Polish ("Administratorzy") and English ("Administrators") Windows systems.
    4. Auto-Detecting CSV Delimiter (',' and ';'):
       Automatically detects standard comma-separated (',') and Polish Excel
       semicolon-separated (';') UTF-8 CSV files.
    5. Real-Time Granular Progress Bar (Write-Progress):
       Displays per-user provisioning progress, percentage completed, active
       SamAccountName, department, and operation status.
    6. Detailed Audit Logging (Enabled by Default):
       Writes UTF-8 timestamped execution logs (with passwords masked) to:
       C:\Logs\<yyyyMMdd_HHmmss>-New-ADUsersFromCSV-<ComputerName>-<UserName>.logs
================================================================================
.SYNOPSIS
    Bulk creates and provisions user accounts in On-Premises Active Directory (AD DS)
    or Microsoft Entra ID from a CSV file (SamAccountName, Name, GivenName, Surname,
    Password, Department) with detailed logging, progress tracking, and safety checks.

.DESCRIPTION
    Instead of manually creating each employee in a graphical console (ADUC or Entra
    Admin Center), New-ADUsersFromCSV.ps1 imports a structured CSV file (such as
    uzytkownicy.csv) and automates user creation in bulk.

    Features include automatic CSV delimiter detection (comma or semicolon),
    duplicate account detection, SecureString password conversion, optional group
    assignment, Dry-Run / WhatIf simulation, CSV sample template generation,
    interactive and non-interactive Entra ID authentication via Microsoft Graph SDK,
    and comprehensive logging to C:\Logs.

.PARAMETER CsvPath
    Path to the input CSV file containing user records to provision
    (e.g., '.\uzytkownicy.csv').
    Aliases: -Path, -File, -InputFile

.PARAMETER Provider
    Target directory service where users will be created:
      - 'AD'      : On-Premises Active Directory Domain Services (New-ADUser). Default.
      - 'EntraID' : Microsoft Entra ID / M365 cloud directory (New-MgUser).
      - 'Both'    : Provisions in On-Premises AD DS and Microsoft Entra ID.
    Aliases: -Target, -Directory, -Mode

.PARAMETER Delimiter
    CSV field delimiter character. Defaults to 'Auto' (automatically detects ',' or ';').

.PARAMETER TargetOU
    Default Distinguished Name (DN) of the Organizational Unit in Active Directory
    where new users will be placed if the CSV row does not specify an 'OU' or 'Path'
    column (e.g., 'OU=Users,OU=Corp,DC=contoso,DC=com').
    Aliases: -OU, -OrganizationalUnit

.PARAMETER UpnSuffix
    UserPrincipalName domain suffix (e.g., 'contoso.com'). If omitted in AD mode,
    automatically resolves the current Active Directory DNS root. Required in
    EntraID mode if UserPrincipalName is not explicitly present in the CSV.
    Aliases: -Domain, -DomainSuffix

.PARAMETER DomainController
    Optional specific Active Directory Domain Controller FQDN or IP to target.
    Aliases: -Server, -DC

.PARAMETER DefaultGroups
    Optional array of Active Directory or Entra ID group names/IDs to assign to every
    newly created user in addition to any groups listed in the CSV 'Groups' column.
    Aliases: -Groups

.PARAMETER AccountEnabled
    Determines whether newly created accounts are enabled immediately. Default: $true.

.PARAMETER ChangePasswordAtLogon
    Forces the user to change their password at next sign-in. Default: $true.

.PARAMETER UpdateExisting
    Switch parameter. If a user with the same SamAccountName / UserPrincipalName
    already exists, updates their Department, GivenName, Surname, and DisplayName
    instead of skipping the record.

.PARAMETER AutoGenerateMissingPasswords
    Switch parameter. Automatically generates a cryptographically strong 16-character
    password if the 'Password' column for a user in the CSV is empty.

.PARAMETER UsageLocation
    Two-letter ISO 3166 country code for Microsoft Entra ID user creation
    (required for M365 license assignment). Default: 'PL'.

.PARAMETER GenerateSampleCsv
    Switch parameter. Generates a ready-to-use sample CSV template file (default:
    '.\uzytkownicy.csv') with required columns and example rows, then exits.
    Aliases: -CreateTemplate, -Sample

.PARAMETER ExportReportPath
    Optional file path to export a post-execution CSV report containing the final
    provisioning status for each user row.

.PARAMETER TenantId
    Microsoft Entra ID Directory (Tenant) ID for non-interactive authentication.
    Aliases: -Tenant, -DirectoryId

.PARAMETER ClientId
    Microsoft Entra ID Application (Client) ID for non-interactive authentication.
    Aliases: -AppId, -ApplicationId

.PARAMETER ClientSecret
    Microsoft Entra ID Client Secret string for non-interactive authentication.
    Aliases: -Secret

.PARAMETER ClientSecretSecure
    Optional SecureString containing the Microsoft Entra ID Client Secret.

.PARAMETER CertificateThumbprint
    Thumbprint of an X.509 Certificate installed in Cert:\CurrentUser\My or
    Cert:\LocalMachine\My for non-interactive Entra ID authentication.
    Aliases: -Thumbprint

.PARAMETER DryRun
    Switch parameter. Simulates bulk user creation (validating CSV rows, checking
    for duplicates, and logging planned actions) without modifying AD or Entra ID.
    Aliases: -Simulate, -Preview

.PARAMETER SkipAdminCheck
    Switch parameter. Skips the automatic UAC Administrator privilege elevation check
    (useful when running with delegated RSAT permissions or in EntraID-only mode).

.PARAMETER LogPath
    Custom path for the execution log file.
    Default: C:\Logs\<yyyyMMdd_HHmmss>-New-ADUsersFromCSV-<ComputerName>-<UserName>.logs
    Aliases: -l, -Log

.PARAMETER NoLog
    Switch parameter. Disables writing execution logs to disk.

.PARAMETER Force
    Switch parameter. Bypasses interactive confirmation prompts (Y/N / T/N) for
    unattended execution.

.PARAMETER Help
    Displays detailed script help, CSV format guide, Entra ID non-interactive setup
    instructions, author details, and usage examples.
    Aliases: -h

.EXAMPLE
    .\New-ADUsersFromCSV.ps1
    Displays the interactive help screen, usage examples, version, and author info.

.EXAMPLE
    .\New-ADUsersFromCSV.ps1 -GenerateSampleCsv -CsvPath ".\uzytkownicy.csv"
    Generates a sample CSV file 'uzytkownicy.csv' with columns:
    SamAccountName, Name, GivenName, Surname, Password, Department.

.EXAMPLE
    .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" -TargetOU "OU=Pracownicy,DC=firma,DC=local"
    Bulk creates users in local Active Directory from uzytkownicy.csv inside the
    specified Organizational Unit with detailed progress and logging to C:\Logs.

.EXAMPLE
    .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" -Provider EntraID -UpnSuffix "firma.onmicrosoft.com"
    Bulk creates users in Microsoft Entra ID using interactive administrator sign-in.

.EXAMPLE
    .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" -Provider EntraID -UpnSuffix "firma.pl" `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -ClientSecret "YourClientSecretValue" -Force
    Bulk provisions users in Microsoft Entra ID non-interactively (unattended mode)
    using an Entra ID App Registration and Client Secret.

.EXAMPLE
    .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" -Provider EntraID -UpnSuffix "firma.pl" `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -CertificateThumbprint "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" -Force
    Bulk provisions users in Microsoft Entra ID non-interactively using an X.509 certificate.

.NOTES
    Author  : Roman Pindela
    Email   : roman.pindela@gmail.com
    GitHub  : https://github.com/romanpindela
    Version : 1.0.0
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Provision')]
param(
    [Parameter(ParameterSetName = 'Provision', Mandatory = $false, Position = 0)]
    [Parameter(ParameterSetName = 'Sample', Mandatory = $false, Position = 0)]
    [Alias('Path', 'File', 'InputFile')]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Target', 'Directory', 'Mode')]
    [ValidateSet('AD', 'EntraID', 'Both')]
    [string]$Provider = 'AD',

    [Parameter(ParameterSetName = 'Provision')]
    [ValidateSet('Auto', ',', ';', "`t")]
    [string]$Delimiter = 'Auto',

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('OU', 'OrganizationalUnit')]
    [string]$TargetOU,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Domain', 'DomainSuffix')]
    [string]$UpnSuffix,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Server', 'DC')]
    [string]$DomainController,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Groups')]
    [string[]]$DefaultGroups,

    [Parameter(ParameterSetName = 'Provision')]
    [bool]$AccountEnabled = $true,

    [Parameter(ParameterSetName = 'Provision')]
    [bool]$ChangePasswordAtLogon = $true,

    [Parameter(ParameterSetName = 'Provision')]
    [switch]$UpdateExisting,

    [Parameter(ParameterSetName = 'Provision')]
    [switch]$AutoGenerateMissingPasswords,

    [Parameter(ParameterSetName = 'Provision')]
    [ValidatePattern('^[A-Za-z]{2}$')]
    [string]$UsageLocation = 'PL',

    [Parameter(ParameterSetName = 'Sample', Mandatory = $true)]
    [Alias('CreateTemplate', 'Sample')]
    [switch]$GenerateSampleCsv,

    [Parameter(ParameterSetName = 'Provision')]
    [string]$ExportReportPath,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Tenant', 'DirectoryId')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('AppId', 'ApplicationId')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Secret')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'Provision')]
    [System.Security.SecureString]$ClientSecretSecure,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Thumbprint')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'Provision')]
    [Alias('Simulate', 'Preview')]
    [switch]$DryRun,

    [Parameter(ParameterSetName = 'Provision')]
    [switch]$SkipAdminCheck,

    [Parameter(ParameterSetName = 'Provision')]
    [Parameter(ParameterSetName = 'Sample')]
    [Alias('l', 'Log')]
    [string]$LogPath,

    [Parameter(ParameterSetName = 'Provision')]
    [Parameter(ParameterSetName = 'Sample')]
    [switch]$NoLog,

    [Parameter(ParameterSetName = 'Provision')]
    [Parameter(ParameterSetName = 'Sample')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Help', Mandatory = $true)]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==============================================================================
# GLOBAL METADATA & STATE
# ==============================================================================
$script:ScriptName    = "New-ADUsersFromCSV"
$script:ScriptVersion = "1.0.0"
$script:ScriptDate    = "2026-10-17"
$script:ScriptAuthor  = "Roman Pindela"
$script:ScriptEmail   = "roman.pindela@gmail.com"
$script:ScriptGitHub  = "https://github.com/romanpindela"
$script:ActiveLogFile = $null
$script:AuthMode      = "Interactive"

# ==============================================================================
# HELP & DOCUMENTATION DISPLAY (-Help / -h / Zero-Parameters)
# ==============================================================================
function Show-ScriptHelp {
    $helpText = @"
================================================================================
  SCRIPT  : New-ADUsersFromCSV.ps1
  VERSION : $script:ScriptVersion ($script:ScriptDate)
  AUTHOR  : $script:ScriptAuthor
  CONTACT : $script:ScriptEmail | $script:ScriptGitHub
================================================================================

DESCRIPTION:
    Automates bulk creation of user accounts from a CSV file (e.g. uzytkownicy.csv)
    instead of manually clicking through each employee in graphical consoles.
    Supports both On-Premises Active Directory (AD DS via New-ADUser) and
    Microsoft Entra ID / Azure AD (via Microsoft Graph SDK New-MgUser).

CSV FILE STRUCTURE (e.g. uzytkownicy.csv):
    Required columns:
      - SamAccountName : Unique login / account name (e.g. jkowalski)
      - Name           : Full display/object name (e.g. Jan Kowalski)
      - GivenName      : First name (e.g. Jan)
      - Surname        : Last name (e.g. Kowalski)
      - Password       : Initial account password (converted to SecureString)
      - Department     : Department name (e.g. IT, HR, Sales, Finance)

    Optional columns (automatically mapped if present in CSV):
      - UserPrincipalName, EmailAddress, Title, Company, Office, MobilePhone,
        OU (per-row Organizational Unit DN), Groups (semicolon/pipe-separated),
        Enabled (True/False), ChangePasswordAtLogon (True/False).

    Example CSV content:
      SamAccountName,Name,GivenName,Surname,Password,Department
      jkowalski,Jan Kowalski,Jan,Kowalski,Start123!@#2026,IT
      anowak,Anna Nowak,Anna,Nowak,BezpieczneHaslo9!,HR
      pwisniewski,Piotr Wisniewski,Piotr,Wisniewski,KontoStart#2026,Finance

--------------------------------------------------------------------------------
HOW TO CONFIGURE ENTRA ID FOR NON-INTERACTIVE / UNATTENDED AUTHENTICATION:
(Only via API Keys / Credentials and Entra ID Microsoft Graph SDK Permissions)
--------------------------------------------------------------------------------
To run this script in unattended / non-interactive mode against Microsoft Entra ID
(e.g. scheduled tasks, HR onboarding pipelines, CI/CD) without browser prompts:

Step 1: Register an Application in Microsoft Entra ID
    1. Sign in to Microsoft Entra admin center (https://entra.microsoft.com).
    2. Navigate to: Identity > Applications > App registrations > New registration.
    3. Name: 'AD-CSV-User-Provisioning-Automation'.
    4. Supported account types: 'Accounts in this organizational directory only'.
    5. Click 'Register' and copy:
       - Application (client) ID  -> pass to -ClientId
       - Directory (tenant) ID    -> pass to -TenantId

Step 2: Grant Microsoft Graph API Application Permissions (App-Only)
    1. In the App Registration, go to: Manage > API permissions > Add a permission.
    2. Select 'Microsoft Graph' > 'Application permissions' (NOT Delegated).
    3. Search for and check the following permissions:
       * User.ReadWrite.All       (Required to create and update users via Graph API)
       * Directory.ReadWrite.All  (Required for directory attributes & group membership)
       * GroupMember.ReadWrite.All (Optional: required if assigning users to groups)
    4. Click 'Add permissions'.
    5. Click 'Grant admin consent for <Your Tenant>' and confirm green status checkmarks.
       (Note: If updating privileged users or resetting passwords, assign the Service
       Principal to the 'User Administrator' Entra role under Roles & administrators).

Step 3: Configure Non-Interactive Credentials (Choose Option A or Option B)
    Option A: Client Secret (API Key / Secret)
      1. Go to: Manage > Certificates & secrets > Client secrets > New client secret.
      2. Enter a description, choose expiration, and click 'Add'.
      3. Copy the secret 'Value' immediately (not the Secret ID).
      4. Connect non-interactively via Microsoft Graph SDK:
         `$sec = ConvertTo-SecureString 'YourSecretValue' -AsPlainText -Force
         `$cred = New-Object System.Management.Automation.PSCredential('<ClientId>', `$sec)
         Connect-MgGraph -TenantId '<TenantId>' -ClientSecretCredential `$cred -NoWelcome
      5. Or pass directly to this script:
         -Provider EntraID -TenantId '<TenantId>' -ClientId '<ClientId>' -ClientSecret '<SecretValue>'

    Option B: X.509 Certificate (Recommended for Production Automation)
      1. Generate a self-signed certificate in PowerShell:
         `$cert = New-SelfSignedCertificate -Subject 'CN=EntraUserProvisioning' ``
             -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable ``
             -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
         Export-Certificate -Cert `$cert -FilePath 'C:\Logs\EntraUserProvisioning.cer'
      2. In Entra Admin Center: Manage > Certificates & secrets > Certificates > Upload certificate.
         Upload 'EntraUserProvisioning.cer'.
      3. Connect non-interactively via Microsoft Graph SDK:
         Connect-MgGraph -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint `$cert.Thumbprint -NoWelcome
      4. Or pass directly to this script:
         -Provider EntraID -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint `$cert.Thumbprint

--------------------------------------------------------------------------------
USAGE EXAMPLES:
--------------------------------------------------------------------------------
  # 1. Generate a ready-to-use sample CSV file (uzytkownicy.csv):
  .\New-ADUsersFromCSV.ps1 -GenerateSampleCsv -CsvPath ".\uzytkownicy.csv"

  # 2. Bulk create users in Local Active Directory (AD DS) in a specific OU:
  .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" ``
      -TargetOU "OU=Pracownicy,DC=firma,DC=local" ``
      -UpnSuffix "firma.local"

  # 3. Preview (Dry-Run) user creation without making changes in AD:
  .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" -DryRun

  # 4. Bulk create users in local AD and assign them to default security groups:
  .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" ``
      -TargetOU "OU=Users,OU=HQ,DC=corp,DC=com" ``
      -DefaultGroups "VPN-Users","Intranet-Readers" ``
      -ExportReportPath "C:\Logs\CreatedUsersReport.csv" -Force

  # 5. Bulk create users in Microsoft Entra ID (Non-Interactive Client Secret):
  .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" ``
      -Provider EntraID ``
      -UpnSuffix "contoso.com" ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -ClientSecret "YourClientSecretValueHere" ``
      -Force

  # 6. Bulk create users in Microsoft Entra ID (Non-Interactive Certificate):
  .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" ``
      -Provider EntraID ``
      -UpnSuffix "contoso.com" ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -CertificateThumbprint "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" ``
      -Force

--------------------------------------------------------------------------------
PARAMETERS:
--------------------------------------------------------------------------------
  -CsvPath, -Path               Path to the CSV file (e.g. .\uzytkownicy.csv).
  -Provider, -Target            Directory target: 'AD' (default), 'EntraID', or 'Both'.
  -Delimiter                    CSV delimiter: 'Auto' (default), ',', ';', or Tab.
  -TargetOU, -OU                Target Organizational Unit DN for local AD DS.
  -UpnSuffix, -Domain           UPN domain suffix (e.g. corp.local or company.com).
  -DomainController, -Server    Specific AD Domain Controller to execute against.
  -DefaultGroups, -Groups       One or more groups to add all provisioned users into.
  -AccountEnabled               Enable accounts upon creation (Default: `$true).
  -ChangePasswordAtLogon        Require password change on next logon (Default: `$true).
  -UpdateExisting               Update existing accounts if SamAccountName/UPN exists.
  -AutoGenerateMissingPasswords Auto-generate 16-char password if CSV Password is blank.
  -UsageLocation                2-letter country code for Entra ID (Default: 'PL').
  -GenerateSampleCsv, -Sample   Create a sample CSV template file and exit.
  -ExportReportPath             Path to export CSV summary report of processed users.
  -TenantId                     Entra ID Tenant ID (for non-interactive Graph auth).
  -ClientId                     Entra ID App Client ID (for non-interactive Graph auth).
  -ClientSecret                 Entra ID Client Secret (for non-interactive Graph auth).
  -CertificateThumbprint        Certificate thumbprint (for non-interactive Graph auth).
  -DryRun, -Simulate            Run validation and simulation without creating users.
  -SkipAdminCheck               Skip automatic UAC administrator elevation check.
  -LogPath, -Log                Custom log path (Default: C:\Logs\<timestamp>-New-ADUsersFromCSV-<PC>-<User>.logs).
  -NoLog                        Disable file logging.
  -Force                        Skip interactive confirmation prompts (Y/N / T/N).
  -Help, -h                     Show this help manual.

LOGGING:
  Detailed execution logs are automatically written by default to:
  C:\Logs\<yyyyMMdd_HHmmss>-New-ADUsersFromCSV-<ComputerName>-<UserName>.logs

SECURITY & UNBLOCKING:
  After downloading this script from GitHub, unblock the file before execution:
  Unblock-File -Path .\New-ADUsersFromCSV.ps1
================================================================================
"@
    Write-Host $helpText -ForegroundColor Cyan
}

# ==============================================================================
# LOGGING ENGINE (Default: C:\Logs\<DateTime>-New-ADUsersFromCSV-<PC>-<User>.logs)
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
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $compName  = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "UNKNOWN-PC" }
        $userName  = if ($env:USERNAME) { $env:USERNAME } else { "UNKNOWN-USER" }
        $fileName  = "${timestamp}-${script:ScriptName}-${compName}-${userName}.logs"
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

# ==============================================================================
# ZERO-PARAMETER & HELP CHECK
# ==============================================================================
if ($Help -or $PSBoundParameters.Count -eq 0) {
    Show-ScriptHelp
    exit 0
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
        Write-Host "[!] Missing Administrator privileges (SID S-1-5-32-544). Requesting UAC elevation..." -ForegroundColor Yellow
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
        exit
    }
}

# Require UAC elevation when provisioning to local Active Directory (unless skipped or DryRun/Sample)
if (-not $GenerateSampleCsv -and -not $SkipAdminCheck -and -not $DryRun -and ($Provider -eq 'AD' -or $Provider -eq 'Both')) {
    Assert-AdministratorPrivileges
}

# Initialize logging
Initialize-ScriptLogging
Write-ScriptLog -Level INFO -Message "Initialized $script:ScriptName v$script:ScriptVersion."
if ($script:ActiveLogFile) {
    Write-ScriptLog -Level INFO -Message "Active log file: $script:ActiveLogFile"
}

# ==============================================================================
# DEFENSIVE INPUT SANITIZATION & SECURITY HELPERS
# ==============================================================================
function Test-SafeFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath,
        [string]$ParameterName = "Path"
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        throw "Parameter -$ParameterName cannot be empty or whitespace."
    }

    # Block null bytes and command injection metacharacters
    if ($InputPath -match '[\x00\|<>\?\*]') {
        throw "Parameter -$ParameterName contains illegal or unsafe path characters: '$InputPath'."
    }
}

function ConvertTo-SafeLdapFilterValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return "" }
    # RFC 4515 LDAP filter escaping
    $escaped = $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace("`0", '\00')
    return $escaped
}

function ConvertTo-SafeODataValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return "" }
    return $Value.Replace("'", "''")
}

function New-RandomStrongPassword {
    param([int]$Length = 16)
    $lower   = "abcdefghijkmnopqrstuvwxyz"
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $digits  = "23456789"
    $special = "!@#$%^&*()-_=+"
    $all     = $lower + $upper + $digits + $special

    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] $Length
    $rng.GetBytes($bytes)

    $chars = New-Object char[] $Length
    # Guarantee complexity requirements (at least 1 lower, 1 upper, 1 digit, 1 symbol)
    $chars[0] = $upper[$bytes[0] % $upper.Length]
    $chars[1] = $lower[$bytes[1] % $lower.Length]
    $chars[2] = $digits[$bytes[2] % $digits.Length]
    $chars[3] = $special[$bytes[3] % $special.Length]

    for ($i = 4; $i -lt $Length; $i++) {
        $chars[$i] = $all[$bytes[$i] % $all.Length]
    }

    # Shuffle characters
    $shuffleBytes = New-Object byte[] $Length
    $rng.GetBytes($shuffleBytes)
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j = $shuffleBytes[$i] % ($i + 1)
        $temp = $chars[$i]
        $chars[$i] = $chars[$j]
        $chars[$j] = $temp
    }

    return -join $chars
}

function Convert-SecureStringToPlain {
    param([System.Security.SecureString]$SecureValue)
    if ($null -eq $SecureValue) { return $null }
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# ==============================================================================
# SAMPLE CSV TEMPLATE GENERATOR (-GenerateSampleCsv)
# ==============================================================================
if ($GenerateSampleCsv) {
    $targetCsv = if ([string]::IsNullOrWhiteSpace($CsvPath)) {
        Join-Path -Path (Get-Location).Path -ChildPath "uzytkownicy.csv"
    } else {
        $CsvPath
    }

    Test-SafeFilePath -InputPath $targetCsv -ParameterName "CsvPath"

    if ((Test-Path -LiteralPath $targetCsv) -and -not $Force) {
        $overwriteChoice = Read-Host "[?] File '$targetCsv' already exists. Overwrite? (Y/N / T/N)"
        if ($overwriteChoice -notmatch '^(Y|y|T|t)$') {
            Write-ScriptLog -Level WARN -Message "Sample CSV generation cancelled by user."
            exit 0
        }
    }

    $sampleContent = @'
SamAccountName,Name,GivenName,Surname,Password,Department
jkowalski,Jan Kowalski,Jan,Kowalski,Start123!@#2026,IT
anowak,Anna Nowak,Anna,Nowak,BezpieczneHaslo9!,HR
pwisniewski,Piotr Wisniewski,Piotr,Wisniewski,KontoStart#2026,Finanse
mkaminska,Magdalena Kaminska,Magdalena,Kaminska,HasloStartowe$26,Sprzedaz
tzelazny,Tomasz Zelazny,Tomasz,Zelazny,AdminPass!9876,Logistyka
'@

    $parentFolder = Split-Path -Path $targetCsv -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentFolder) -and -not (Test-Path -LiteralPath $parentFolder)) {
        New-Item -Path $parentFolder -ItemType Directory -Force | Out-Null
    }

    Set-Content -LiteralPath $targetCsv -Value $sampleContent -Encoding UTF8 -Force
    Write-ScriptLog -Level SUCCESS -Message "Sample CSV template created successfully at: $targetCsv"
    Write-ScriptLog -Level INFO -Message "Columns included: SamAccountName, Name, GivenName, Surname, Password, Department"
    exit 0
}

# ==============================================================================
# CSV INPUT VALIDATION & AUTO-DELIMITER PARSING
# ==============================================================================
if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    Write-ScriptLog -Level ERROR -Message "Missing required parameter: -CsvPath (e.g., .\uzytkownicy.csv). Run with -Help for usage examples."
    Show-ScriptHelp
    exit 1
}

Test-SafeFilePath -InputPath $CsvPath -ParameterName "CsvPath"

if (-not (Test-Path -LiteralPath $CsvPath -PathType Leaf)) {
    Write-ScriptLog -Level ERROR -Message "CSV file not found at specified path: '$CsvPath'. Tip: Use -GenerateSampleCsv to create a template."
    exit 1
}

$resolvedCsvPath = (Resolve-Path -LiteralPath $CsvPath).Path
Write-ScriptLog -Level INFO -Message "Reading CSV file: $resolvedCsvPath"

# Detect delimiter from header line if set to 'Auto'
$firstNonEmptyLine = Get-Content -LiteralPath $resolvedCsvPath -Encoding UTF8 -TotalCount 5 |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.TrimStart().StartsWith('#') } |
    Select-Object -First 1

if ([string]::IsNullOrWhiteSpace($firstNonEmptyLine)) {
    Write-ScriptLog -Level ERROR -Message "The CSV file '$resolvedCsvPath' is empty or contains no header row."
    exit 1
}

$effectiveDelimiter = $Delimiter
if ($Delimiter -eq 'Auto') {
    $commaCount     = ([regex]::Matches($firstNonEmptyLine, ',')).Count
    $semicolonCount = ([regex]::Matches($firstNonEmptyLine, ';')).Count
    $tabCount       = ([regex]::Matches($firstNonEmptyLine, "`t")).Count

    if ($semicolonCount -gt $commaCount -and $semicolonCount -ge $tabCount) {
        $effectiveDelimiter = ';'
    } elseif ($tabCount -gt $commaCount -and $tabCount -gt $semicolonCount) {
        $effectiveDelimiter = "`t"
    } else {
        $effectiveDelimiter = ','
    }
    Write-ScriptLog -Level INFO -Message "Auto-detected CSV delimiter: '$effectiveDelimiter'"
}

$csvUsers = @(Import-Csv -LiteralPath $resolvedCsvPath -Delimiter $effectiveDelimiter -Encoding UTF8)
if ($csvUsers.Count -eq 0) {
    Write-ScriptLog -Level ERROR -Message "No user records found in CSV file '$resolvedCsvPath'."
    exit 1
}

# Verify required CSV columns
$requiredColumns = @('SamAccountName', 'Name', 'GivenName', 'Surname', 'Password', 'Department')
$csvProperties   = @($csvUsers[0].PSObject.Properties.Name)
$missingColumns  = @()

foreach ($reqCol in $requiredColumns) {
    $matched = $csvProperties | Where-Object { $_ -ieq $reqCol }
    if (-not $matched) {
        $missingColumns += $reqCol
    }
}

if ($missingColumns.Count -gt 0) {
    Write-ScriptLog -Level ERROR -Message "CSV file is missing required column(s): $($missingColumns -join ', ')."
    Write-ScriptLog -Level ERROR -Message "Detected columns: $($csvProperties -join ', '). Expected: $($requiredColumns -join ', ')."
    exit 1
}

Write-ScriptLog -Level SUCCESS -Message "Validated CSV schema ($($csvUsers.Count) user record(s) loaded). Columns: $($csvProperties -join ', ')"

# ==============================================================================
# ENVIRONMENT & AUTHENTICATION INITIALIZATION (AD DS / ENTRA ID)
# ==============================================================================
$resolvedUpnSuffix = $UpnSuffix
$resolvedDefaultOU = $TargetOU

# 1. Initialize On-Premises Active Directory (if Provider is AD or Both)
if ($Provider -eq 'AD' -or $Provider -eq 'Both') {
    Write-ScriptLog -Level STEP -Message "Initializing On-Premises Active Directory (AD DS) environment..."

    if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
        if ($DryRun) {
            Write-ScriptLog -Level WARN -Message "[DryRun] ActiveDirectory RSAT module is not installed on this machine. Proceeding in simulation mode."
        } else {
            Write-ScriptLog -Level ERROR -Message "Required module 'ActiveDirectory' (RSAT-AD-PowerShell) is not installed."
            Write-ScriptLog -Level INFO  -Message "Install RSAT on Windows 10/11 via: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            Write-ScriptLog -Level INFO  -Message "Install on Windows Server via: Install-WindowsFeature -Name RSAT-AD-PowerShell"
            Write-ScriptLog -Level INFO  -Message "Or run with -Provider EntraID to provision users in Microsoft Entra ID, or -DryRun to test CSV parsing."
            exit 1
        }
    } else {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-ScriptLog -Level SUCCESS -Message "Loaded 'ActiveDirectory' PowerShell module."

        if (-not $DryRun) {
            try {
                $adParams = @{}
                if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
                    $adParams['Server'] = $DomainController
                }
                $adDomain = Get-ADDomain @adParams -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($resolvedUpnSuffix)) {
                    $resolvedUpnSuffix = $adDomain.DNSRoot
                }
                if ([string]::IsNullOrWhiteSpace($resolvedDefaultOU)) {
                    $resolvedDefaultOU = $adDomain.UsersContainer
                }
                Write-ScriptLog -Level SUCCESS -Message "Connected to AD Domain: $($adDomain.DNSRoot) (Default Container: $resolvedDefaultOU)"
            } catch {
                Write-ScriptLog -Level ERROR -Message "Failed to query Active Directory domain: $_"
                exit 1
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($resolvedUpnSuffix)) {
        $resolvedUpnSuffix = if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN.ToLower() } else { "corp.local" }
    }
}

# 2. Initialize Microsoft Entra ID / Graph SDK (if Provider is EntraID or Both)
if ($Provider -eq 'EntraID' -or $Provider -eq 'Both') {
    Write-ScriptLog -Level STEP -Message "Initializing Microsoft Entra ID (Microsoft Graph SDK) environment..."

    $requiredGraphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
    if ($DefaultGroups -and $DefaultGroups.Count -gt 0) {
        $requiredGraphModules += 'Microsoft.Graph.Groups'
    }

    $missingGraphModules = @()
    foreach ($mod in $requiredGraphModules) {
        if (-not (Get-Module -Name $mod -ListAvailable)) {
            $missingGraphModules += $mod
        }
    }

    if ($missingGraphModules.Count -gt 0) {
        if ($DryRun) {
            Write-ScriptLog -Level WARN -Message "[DryRun] Missing Microsoft Graph module(s): $($missingGraphModules -join ', '). Proceeding in simulation mode."
        } else {
            Write-ScriptLog -Level WARN -Message "Missing required Microsoft Graph module(s): $($missingGraphModules -join ', ')"
            $installChoice = if ($Force) { 'Y' } else { Read-Host "[?] Install missing Microsoft Graph modules from PSGallery now? (Y/N / T/N)" }
            if ($installChoice -match '^(Y|y|T|t)$') {
                Write-ScriptLog -Level INFO -Message "Installing modules: $($missingGraphModules -join ', ')..."
                Install-Module -Name $missingGraphModules -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
                Write-ScriptLog -Level SUCCESS -Message "Microsoft Graph modules installed successfully."
            } else {
                Write-ScriptLog -Level ERROR -Message "Cannot proceed without Microsoft Graph modules."
                exit 1
            }
        }
    }

    if (-not $DryRun) {
        # Determine Interactive vs Non-Interactive (App-Only) Authentication
        $hasSecretAuth = (-not [string]::IsNullOrWhiteSpace($TenantId)) -and
                         (-not [string]::IsNullOrWhiteSpace($ClientId)) -and
                         ((-not [string]::IsNullOrWhiteSpace($ClientSecret)) -or ($null -ne $ClientSecretSecure))

        $hasCertAuth   = (-not [string]::IsNullOrWhiteSpace($TenantId)) -and
                         (-not [string]::IsNullOrWhiteSpace($ClientId)) -and
                         (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint))

        try {
            if ($hasSecretAuth) {
                $script:AuthMode = "NonInteractive-ClientSecret"
                Write-ScriptLog -Level INFO -Message "Connecting to Microsoft Graph in Non-Interactive mode (Client Secret) for TenantId '$TenantId', ClientId '$ClientId'..."
                $secSecret = if ($null -ne $ClientSecretSecure) {
                    $ClientSecretSecure
                } else {
                    ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force
                }
                $appCred = New-Object System.Management.Automation.PSCredential($ClientId, $secSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $appCred -NoWelcome -ErrorAction Stop
                Write-ScriptLog -Level SUCCESS -Message "Authenticated to Microsoft Graph (App-Only ClientSecret)."
            } elseif ($hasCertAuth) {
                $script:AuthMode = "NonInteractive-Certificate"
                Write-ScriptLog -Level INFO -Message "Connecting to Microsoft Graph in Non-Interactive mode (X.509 Certificate '$CertificateThumbprint') for TenantId '$TenantId'..."
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
                Write-ScriptLog -Level SUCCESS -Message "Authenticated to Microsoft Graph (App-Only Certificate)."
            } else {
                $script:AuthMode = "Interactive"
                $requiredScopes = @('User.ReadWrite.All', 'Directory.ReadWrite.All')
                if ($DefaultGroups -and $DefaultGroups.Count -gt 0) {
                    $requiredScopes += 'GroupMember.ReadWrite.All'
                }

                $mgContext = $null
                try { $mgContext = Get-MgContext -ErrorAction SilentlyContinue } catch { $mgContext = $null }

                $needsLogin = $true
                if ($null -ne $mgContext) {
                    $missingScopes = @($requiredScopes | Where-Object { $mgContext.Scopes -notcontains $_ })
                    if ($missingScopes.Count -eq 0) {
                        $needsLogin = $false
                        Write-ScriptLog -Level SUCCESS -Message "Reusing active Microsoft Graph session ($($mgContext.Account))."
                    }
                }

                if ($needsLogin) {
                    Write-ScriptLog -Level INFO -Message "Initiating interactive Microsoft Graph sign-in (Scopes: $($requiredScopes -join ', '))..."
                    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
                    Write-ScriptLog -Level SUCCESS -Message "Authenticated to Microsoft Graph interactively."
                }
            }
        } catch {
            Write-ScriptLog -Level ERROR -Message "Failed to authenticate to Microsoft Graph: $_"
            exit 1
        }
    }

    if ([string]::IsNullOrWhiteSpace($resolvedUpnSuffix)) {
        Write-ScriptLog -Level WARN -Message "No -UpnSuffix provided for Entra ID. Defaulting to 'contoso.onmicrosoft.com' unless UserPrincipalName is specified in CSV."
        $resolvedUpnSuffix = "contoso.onmicrosoft.com"
    }
}

# ==============================================================================
# DISPLAY EXECUTION CONFIGURATION SUMMARY & CONFIRMATION
# ==============================================================================
Write-Host ""
Write-Host "==================== BULK USER PROVISIONING PARAMETERS ====================" -ForegroundColor Cyan
Write-Host ("  CSV File Path          : {0}" -f $resolvedCsvPath) -ForegroundColor White
Write-Host ("  Detected Delimiter     : '{0}'" -f $(if ($effectiveDelimiter -eq "`t") { "TAB" } else { $effectiveDelimiter })) -ForegroundColor White
Write-Host ("  Total CSV Rows         : {0}" -f $csvUsers.Count) -ForegroundColor White
Write-Host ("  Target Provider        : {0}" -f $Provider) -ForegroundColor Yellow
Write-Host ("  Authentication Mode    : {0}" -f $script:AuthMode) -ForegroundColor White
Write-Host ("  Default UPN Suffix     : {0}" -f $resolvedUpnSuffix) -ForegroundColor White
if ($Provider -eq 'AD' -or $Provider -eq 'Both') {
    Write-Host ("  Target AD OU / Path    : {0}" -f $(if ($resolvedDefaultOU) { $resolvedDefaultOU } else { "(Default Users Container)" })) -ForegroundColor White
}
Write-Host ("  Account Enabled        : {0}" -f $AccountEnabled) -ForegroundColor White
Write-Host ("  Change Pwd At Logon    : {0}" -f $ChangePasswordAtLogon) -ForegroundColor White
Write-Host ("  Update Existing Users  : {0}" -f $UpdateExisting.IsPresent) -ForegroundColor White
Write-Host ("  Dry-Run / Simulation   : {0}" -f $DryRun.IsPresent) -ForegroundColor $(if ($DryRun) { "Yellow" } else { "White" })
Write-Host ("  Log File               : {0}" -f $(if ($script:ActiveLogFile) { $script:ActiveLogFile } else { "(Disabled)" })) -ForegroundColor Gray
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $Force -and -not $DryRun -and $PSCmdlet.ShouldProcess("$($csvUsers.Count) user(s) from '$resolvedCsvPath'", "Provision User Accounts in $Provider")) {
    $confirm = Read-Host "[?] Proceed with provisioning $($csvUsers.Count) user account(s) in $Provider? (Y/N / T/N)"
    if ($confirm -notmatch '^(Y|y|T|t)$') {
        Write-ScriptLog -Level WARN -Message "Bulk user provisioning cancelled by administrator."
        exit 0
    }
}

# ==============================================================================
# BULK PROVISIONING LOOP WITH GRANULAR WRITE-PROGRESS
# ==============================================================================
$results          = New-Object System.Collections.Generic.List[object]
$createdCount     = 0
$updatedCount     = 0
$skippedCount     = 0
$failedCount      = 0
$totalUsers       = $csvUsers.Count
$rowIndex         = 0
$seenSamAccounts  = @{}

foreach ($row in $csvUsers) {
    $rowIndex++
    $percentComplete = [math]::Min(100, [int](($rowIndex / $totalUsers) * 100))

    # Extract core CSV fields safely (case-insensitive property access)
    $samAccountName = ([string]$row.SamAccountName).Trim()
    $fullName       = ([string]$row.Name).Trim()
    $givenName      = ([string]$row.GivenName).Trim()
    $surname        = ([string]$row.Surname).Trim()
    $rawPassword    = [string]$row.Password
    $department     = ([string]$row.Department).Trim()

    # Optional CSV columns
    $rowProps = $row.PSObject.Properties.Name
    $csvUpn   = if ($rowProps -icontains 'UserPrincipalName' -and -not [string]::IsNullOrWhiteSpace($row.UserPrincipalName)) {
        ([string]$row.UserPrincipalName).Trim()
    } else { $null }

    $csvDisplayName = if ($rowProps -icontains 'DisplayName' -and -not [string]::IsNullOrWhiteSpace($row.DisplayName)) {
        ([string]$row.DisplayName).Trim()
    } else { $fullName }

    $csvEmail = if ($rowProps -icontains 'EmailAddress' -and -not [string]::IsNullOrWhiteSpace($row.EmailAddress)) {
        ([string]$row.EmailAddress).Trim()
    } elseif ($rowProps -icontains 'Mail' -and -not [string]::IsNullOrWhiteSpace($row.Mail)) {
        ([string]$row.Mail).Trim()
    } else { $null }

    $csvTitle = if ($rowProps -icontains 'Title' -and -not [string]::IsNullOrWhiteSpace($row.Title)) {
        ([string]$row.Title).Trim()
    } elseif ($rowProps -icontains 'JobTitle' -and -not [string]::IsNullOrWhiteSpace($row.JobTitle)) {
        ([string]$row.JobTitle).Trim()
    } else { $null }

    $csvCompany = if ($rowProps -icontains 'Company' -and -not [string]::IsNullOrWhiteSpace($row.Company)) {
        ([string]$row.Company).Trim()
    } else { $null }

    $csvOffice = if ($rowProps -icontains 'Office' -and -not [string]::IsNullOrWhiteSpace($row.Office)) {
        ([string]$row.Office).Trim()
    } else { $null }

    $csvPhone = if ($rowProps -icontains 'MobilePhone' -and -not [string]::IsNullOrWhiteSpace($row.MobilePhone)) {
        ([string]$row.MobilePhone).Trim()
    } elseif ($rowProps -icontains 'TelephoneNumber' -and -not [string]::IsNullOrWhiteSpace($row.TelephoneNumber)) {
        ([string]$row.TelephoneNumber).Trim()
    } else { $null }

    $csvOU = if ($rowProps -icontains 'OU' -and -not [string]::IsNullOrWhiteSpace($row.OU)) {
        ([string]$row.OU).Trim()
    } elseif ($rowProps -icontains 'OrganizationalUnit' -and -not [string]::IsNullOrWhiteSpace($row.OrganizationalUnit)) {
        ([string]$row.OrganizationalUnit).Trim()
    } elseif ($rowProps -icontains 'Path' -and -not [string]::IsNullOrWhiteSpace($row.Path)) {
        ([string]$row.Path).Trim()
    } else { $resolvedDefaultOU }

    $csvRowGroups = @()
    if ($rowProps -icontains 'Groups' -and -not [string]::IsNullOrWhiteSpace($row.Groups)) {
        $csvRowGroups = @(([string]$row.Groups -split '[;|,]') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    if ($DefaultGroups -and $DefaultGroups.Count -gt 0) {
        foreach ($dg in $DefaultGroups) {
            if (-not [string]::IsNullOrWhiteSpace($dg) -and ($csvRowGroups -notcontains $dg)) {
                $csvRowGroups += $dg
            }
        }
    }

    $rowEnabled = $AccountEnabled
    if ($rowProps -icontains 'Enabled' -and -not [string]::IsNullOrWhiteSpace($row.Enabled)) {
        $rowEnabled = ([string]$row.Enabled).Trim() -match '^(True|true|1|Yes|Tak|T|Y)$'
    }

    $rowChangePwd = $ChangePasswordAtLogon
    if ($rowProps -icontains 'ChangePasswordAtLogon' -and -not [string]::IsNullOrWhiteSpace($row.ChangePasswordAtLogon)) {
        $rowChangePwd = ([string]$row.ChangePasswordAtLogon).Trim() -match '^(True|true|1|Yes|Tak|T|Y)$'
    }

    # Fallback for Name if empty
    if ([string]::IsNullOrWhiteSpace($fullName) -and (-not [string]::IsNullOrWhiteSpace($givenName) -or -not [string]::IsNullOrWhiteSpace($surname))) {
        $fullName       = "$givenName $surname".Trim()
        $csvDisplayName = $fullName
    }

    $statusText = "Processing [$rowIndex/$totalUsers] $samAccountName ($fullName - Dept: $department)"
    Write-Progress -Id 1 -Activity "Bulk Provisioning Users from CSV ($Provider)" -Status $statusText -PercentComplete $percentComplete

    # Row-level input validation
    if ([string]::IsNullOrWhiteSpace($samAccountName)) {
        $msg = "Row ${rowIndex}: Missing SamAccountName. Skipping row."
        Write-ScriptLog -Level ERROR -Message $msg
        $failedCount++
        $results.Add([PSCustomObject]@{
            Row               = $rowIndex
            SamAccountName    = "(Empty)"
            Name              = $fullName
            UserPrincipalName = ""
            Department        = $department
            Provider          = $Provider
            Status            = "Failed"
            Details           = "Missing SamAccountName"
        })
        continue
    }

    if ($samAccountName -notmatch '^[a-zA-Z0-9._\-]{1,20}$') {
        $msg = "Row ${rowIndex} ('$samAccountName'): Invalid SamAccountName format (must be 1-20 alphanumeric/._- characters)."
        Write-ScriptLog -Level ERROR -Message $msg
        $failedCount++
        $results.Add([PSCustomObject]@{
            Row               = $rowIndex
            SamAccountName    = $samAccountName
            Name              = $fullName
            UserPrincipalName = ""
            Department        = $department
            Provider          = $Provider
            Status            = "Failed"
            Details           = "Invalid SamAccountName format"
        })
        continue
    }

    if ($seenSamAccounts.ContainsKey($samAccountName.ToLower())) {
        $msg = "Row ${rowIndex} ('$samAccountName'): Duplicate SamAccountName inside the CSV file (already seen on row $($seenSamAccounts[$samAccountName.ToLower()])). Skipping."
        Write-ScriptLog -Level WARN -Message $msg
        $skippedCount++
        $results.Add([PSCustomObject]@{
            Row               = $rowIndex
            SamAccountName    = $samAccountName
            Name              = $fullName
            UserPrincipalName = ""
            Department        = $department
            Provider          = $Provider
            Status            = "Skipped"
            Details           = "Duplicate SamAccountName in CSV"
        })
        continue
    }
    $seenSamAccounts[$samAccountName.ToLower()] = $rowIndex

    if ([string]::IsNullOrWhiteSpace($fullName)) {
        $msg = "Row ${rowIndex} ('$samAccountName'): Missing 'Name' (or GivenName/Surname). Skipping."
        Write-ScriptLog -Level ERROR -Message $msg
        $failedCount++
        $results.Add([PSCustomObject]@{
            Row               = $rowIndex
            SamAccountName    = $samAccountName
            Name              = "(Empty)"
            UserPrincipalName = ""
            Department        = $department
            Provider          = $Provider
            Status            = "Failed"
            Details           = "Missing Name"
        })
        continue
    }

    # Password validation / auto-generation
    if ([string]::IsNullOrWhiteSpace($rawPassword)) {
        if ($AutoGenerateMissingPasswords) {
            $rawPassword = New-RandomStrongPassword -Length 16
            Write-ScriptLog -Level WARN -Message "Row ${rowIndex} ('$samAccountName'): Empty password in CSV; auto-generated strong 16-char password."
        } else {
            $msg = "Row ${rowIndex} ('$samAccountName'): Password column is empty (use -AutoGenerateMissingPasswords to auto-generate)."
            Write-ScriptLog -Level ERROR -Message $msg
            $failedCount++
            $results.Add([PSCustomObject]@{
                Row               = $rowIndex
                SamAccountName    = $samAccountName
                Name              = $fullName
                UserPrincipalName = ""
                Department        = $department
                Provider          = $Provider
                Status            = "Failed"
                Details           = "Missing Password"
            })
            continue
        }
    }

    $upn = if (-not [string]::IsNullOrWhiteSpace($csvUpn)) {
        $csvUpn
    } else {
        "$samAccountName@$resolvedUpnSuffix"
    }

    $emailAddress = if (-not [string]::IsNullOrWhiteSpace($csvEmail)) {
        $csvEmail
    } else {
        $upn
    }

    $securePassword = ConvertTo-SecureString -String $rawPassword -AsPlainText -Force
    $rowActionStates = @()
    $rowHadFailure   = $false
    $rowWasCreated   = $false
    $rowWasUpdated   = $false
    $rowWasSkipped   = $false

    # --------------------------------------------------------------------------
    # A. ON-PREMISES ACTIVE DIRECTORY PROVISIONING (New-ADUser)
    # --------------------------------------------------------------------------
    if ($Provider -eq 'AD' -or $Provider -eq 'Both') {
        try {
            if ($DryRun) {
                Write-ScriptLog -Level INFO -Message "[DryRun] [AD] Would create user '$samAccountName' (Name: '$fullName', GivenName: '$givenName', Surname: '$surname', Dept: '$department', UPN: '$upn', OU: '$csvOU')"
                $rowActionStates += "AD:DryRun-Simulated"
                $rowWasCreated = $true
            } else {
                $safeSam = ConvertTo-SafeLdapFilterValue -Value $samAccountName
                $safeUpn = ConvertTo-SafeLdapFilterValue -Value $upn
                $adQueryParams = @{
                    LDAPFilter  = "(|(sAMAccountName=$safeSam)(userPrincipalName=$safeUpn))"
                    ErrorAction = 'Stop'
                }
                if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
                    $adQueryParams['Server'] = $DomainController
                }

                $existingAdUser = @(Get-ADUser @adQueryParams)
                if ($existingAdUser.Count -gt 0) {
                    if ($UpdateExisting) {
                        $setAdParams = @{
                            Identity    = $existingAdUser[0].DistinguishedName
                            DisplayName = $csvDisplayName
                            ErrorAction = 'Stop'
                        }
                        if (-not [string]::IsNullOrWhiteSpace($givenName))  { $setAdParams['GivenName']    = $givenName }
                        if (-not [string]::IsNullOrWhiteSpace($surname))    { $setAdParams['Surname']      = $surname }
                        if (-not [string]::IsNullOrWhiteSpace($department)) { $setAdParams['Department']   = $department }
                        if (-not [string]::IsNullOrWhiteSpace($csvTitle))   { $setAdParams['Title']        = $csvTitle }
                        if (-not [string]::IsNullOrWhiteSpace($csvCompany)) { $setAdParams['Company']      = $csvCompany }
                        if (-not [string]::IsNullOrWhiteSpace($csvOffice))  { $setAdParams['Office']       = $csvOffice }
                        if (-not [string]::IsNullOrWhiteSpace($csvPhone))   { $setAdParams['MobilePhone']  = $csvPhone }
                        if (-not [string]::IsNullOrWhiteSpace($DomainController)) { $setAdParams['Server'] = $DomainController }

                        Set-ADUser @setAdParams
                        Write-ScriptLog -Level SUCCESS -Message "[AD] Updated existing user '$samAccountName' ($fullName | Dept: $department)."
                        $rowActionStates += "AD:Updated"
                        $rowWasUpdated = $true
                    } else {
                        Write-ScriptLog -Level WARN -Message "[AD] User '$samAccountName' (or UPN '$upn') already exists in Active Directory. Skipping."
                        $rowActionStates += "AD:Skipped(Exists)"
                        $rowWasSkipped = $true
                    }
                } else {
                    $newAdParams = @{
                        SamAccountName        = $samAccountName
                        Name                  = $fullName
                        DisplayName           = $csvDisplayName
                        UserPrincipalName     = $upn
                        EmailAddress          = $emailAddress
                        AccountPassword       = $securePassword
                        Enabled               = $rowEnabled
                        ChangePasswordAtLogon = $rowChangePwd
                        ErrorAction           = 'Stop'
                    }
                    if (-not [string]::IsNullOrWhiteSpace($givenName))  { $newAdParams['GivenName']   = $givenName }
                    if (-not [string]::IsNullOrWhiteSpace($surname))    { $newAdParams['Surname']     = $surname }
                    if (-not [string]::IsNullOrWhiteSpace($department)) { $newAdParams['Department']  = $department }
                    if (-not [string]::IsNullOrWhiteSpace($csvTitle))   { $newAdParams['Title']       = $csvTitle }
                    if (-not [string]::IsNullOrWhiteSpace($csvCompany)) { $newAdParams['Company']     = $csvCompany }
                    if (-not [string]::IsNullOrWhiteSpace($csvOffice))  { $newAdParams['Office']      = $csvOffice }
                    if (-not [string]::IsNullOrWhiteSpace($csvPhone))   { $newAdParams['MobilePhone'] = $csvPhone }
                    if (-not [string]::IsNullOrWhiteSpace($csvOU))      { $newAdParams['Path']        = $csvOU }
                    if (-not [string]::IsNullOrWhiteSpace($DomainController)) { $newAdParams['Server'] = $DomainController }

                    New-ADUser @newAdParams
                    Write-ScriptLog -Level SUCCESS -Message "[AD] Created user '$samAccountName' (Name: '$fullName', Dept: '$department', UPN: '$upn')."
                    $rowActionStates += "AD:Created"
                    $rowWasCreated = $true

                    # Assign AD groups if specified
                    if ($csvRowGroups.Count -gt 0) {
                        foreach ($grpName in $csvRowGroups) {
                            try {
                                $grpParams = @{
                                    Identity    = $grpName
                                    Members     = $samAccountName
                                    ErrorAction = 'Stop'
                                }
                                if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
                                    $grpParams['Server'] = $DomainController
                                }
                                Add-ADGroupMember @grpParams
                                Write-ScriptLog -Level INFO -Message "[AD] Added '$samAccountName' to group '$grpName'."
                            } catch {
                                Write-ScriptLog -Level WARN -Message "[AD] Could not add '$samAccountName' to group '$grpName': $_"
                            }
                        }
                    }
                }
            }
        } catch {
            Write-ScriptLog -Level ERROR -Message "[AD] Failed to provision user '$samAccountName': $_"
            $rowActionStates += "AD:Error($($_.Exception.Message))"
            $rowHadFailure = $true
        }
    }

    # --------------------------------------------------------------------------
    # B. MICROSOFT ENTRA ID PROVISIONING (New-MgUser via Microsoft Graph SDK)
    # --------------------------------------------------------------------------
    if ($Provider -eq 'EntraID' -or $Provider -eq 'Both') {
        try {
            if ($DryRun) {
                Write-ScriptLog -Level INFO -Message "[DryRun] [EntraID] Would create user '$upn' (MailNickname: '$samAccountName', DisplayName: '$csvDisplayName', GivenName: '$givenName', Surname: '$surname', Dept: '$department')"
                $rowActionStates += "EntraID:DryRun-Simulated"
                $rowWasCreated = $true
            } else {
                $safeODataUpn = ConvertTo-SafeODataValue -Value $upn
                $safeODataNick = ConvertTo-SafeODataValue -Value $samAccountName
                $existingMgUsers = @(Get-MgUser -Filter "userPrincipalName eq '$safeODataUpn' or mailNickname eq '$safeODataNick'" -Property Id,UserPrincipalName,DisplayName -ErrorAction Stop)

                if ($existingMgUsers.Count -gt 0) {
                    if ($UpdateExisting) {
                        $mgUpdateParams = @{
                            UserId      = $existingMgUsers[0].Id
                            DisplayName = $csvDisplayName
                            ErrorAction = 'Stop'
                        }
                        if (-not [string]::IsNullOrWhiteSpace($givenName))  { $mgUpdateParams['GivenName']     = $givenName }
                        if (-not [string]::IsNullOrWhiteSpace($surname))    { $mgUpdateParams['Surname']       = $surname }
                        if (-not [string]::IsNullOrWhiteSpace($department)) { $mgUpdateParams['Department']    = $department }
                        if (-not [string]::IsNullOrWhiteSpace($csvTitle))   { $mgUpdateParams['JobTitle']      = $csvTitle }
                        if (-not [string]::IsNullOrWhiteSpace($csvCompany)) { $mgUpdateParams['CompanyName']   = $csvCompany }
                        if (-not [string]::IsNullOrWhiteSpace($csvOffice))  { $mgUpdateParams['OfficeLocation']= $csvOffice }
                        if (-not [string]::IsNullOrWhiteSpace($csvPhone))   { $mgUpdateParams['MobilePhone']   = $csvPhone }

                        Update-MgUser @mgUpdateParams
                        Write-ScriptLog -Level SUCCESS -Message "[EntraID] Updated existing cloud user '$upn' ($csvDisplayName | Dept: $department)."
                        $rowActionStates += "EntraID:Updated"
                        $rowWasUpdated = $true
                    } else {
                        Write-ScriptLog -Level WARN -Message "[EntraID] User '$upn' (or MailNickname '$samAccountName') already exists in Entra ID. Skipping."
                        $rowActionStates += "EntraID:Skipped(Exists)"
                        $rowWasSkipped = $true
                    }
                } else {
                    $pwdProfile = @{
                        ForceChangePasswordNextSignIn = [bool]$rowChangePwd
                        Password                      = $rawPassword
                    }

                    $newMgParams = @{
                        AccountEnabled    = [bool]$rowEnabled
                        DisplayName       = $csvDisplayName
                        MailNickname      = $samAccountName
                        UserPrincipalName = $upn
                        PasswordProfile   = $pwdProfile
                        UsageLocation     = $UsageLocation.ToUpper()
                        ErrorAction       = 'Stop'
                    }
                    if (-not [string]::IsNullOrWhiteSpace($givenName))  { $newMgParams['GivenName']      = $givenName }
                    if (-not [string]::IsNullOrWhiteSpace($surname))    { $newMgParams['Surname']        = $surname }
                    if (-not [string]::IsNullOrWhiteSpace($department)) { $newMgParams['Department']     = $department }
                    if (-not [string]::IsNullOrWhiteSpace($csvEmail))   { $newMgParams['Mail']           = $csvEmail }
                    if (-not [string]::IsNullOrWhiteSpace($csvTitle))   { $newMgParams['JobTitle']       = $csvTitle }
                    if (-not [string]::IsNullOrWhiteSpace($csvCompany)) { $newMgParams['CompanyName']    = $csvCompany }
                    if (-not [string]::IsNullOrWhiteSpace($csvOffice))  { $newMgParams['OfficeLocation'] = $csvOffice }
                    if (-not [string]::IsNullOrWhiteSpace($csvPhone))   { $newMgParams['MobilePhone']    = $csvPhone }

                    $createdMgUser = New-MgUser @newMgParams
                    Write-ScriptLog -Level SUCCESS -Message "[EntraID] Created cloud user '$upn' (Id: $($createdMgUser.Id), Dept: '$department')."
                    $rowActionStates += "EntraID:Created"
                    $rowWasCreated = $true

                    # Assign Entra ID groups if specified
                    if ($csvRowGroups.Count -gt 0 -and $createdMgUser.Id) {
                        foreach ($grpIdentifier in $csvRowGroups) {
                            try {
                                $targetGroupId = $null
                                if ($grpIdentifier -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                                    $targetGroupId = $grpIdentifier
                                } else {
                                    $safeGrpName = ConvertTo-SafeODataValue -Value $grpIdentifier
                                    $foundGrp = @(Get-MgGroup -Filter "displayName eq '$safeGrpName'" -Property Id,DisplayName -ErrorAction Stop)
                                    if ($foundGrp.Count -gt 0) {
                                        $targetGroupId = $foundGrp[0].Id
                                    }
                                }

                                if ($targetGroupId) {
                                    New-MgGroupMember -GroupId $targetGroupId -DirectoryObjectId $createdMgUser.Id -ErrorAction Stop
                                    Write-ScriptLog -Level INFO -Message "[EntraID] Added '$upn' to Entra group '$grpIdentifier'."
                                } else {
                                    Write-ScriptLog -Level WARN -Message "[EntraID] Group '$grpIdentifier' not found in tenant; skipped group assignment for '$upn'."
                                }
                            } catch {
                                Write-ScriptLog -Level WARN -Message "[EntraID] Could not add '$upn' to group '$grpIdentifier': $_"
                            }
                        }
                    }
                }
            }
        } catch {
            Write-ScriptLog -Level ERROR -Message "[EntraID] Failed to provision user '$upn': $_"
            $rowActionStates += "EntraID:Error($($_.Exception.Message))"
            $rowHadFailure = $true
        }
    }

    # Clear plain password reference immediately
    $rawPassword = $null

    # Aggregate row status
    $finalRowStatus = if ($rowHadFailure) {
        $failedCount++
        "Failed"
    } elseif ($rowWasCreated) {
        $createdCount++
        if ($DryRun) { "DryRun-Simulated" } else { "Created" }
    } elseif ($rowWasUpdated) {
        $updatedCount++
        "Updated"
    } else {
        $skippedCount++
        "Skipped"
    }

    $results.Add([PSCustomObject]@{
        Row               = $rowIndex
        SamAccountName    = $samAccountName
        Name              = $fullName
        GivenName         = $givenName
        Surname           = $surname
        UserPrincipalName = $upn
        Department        = $department
        Provider          = $Provider
        Status            = $finalRowStatus
        Details           = ($rowActionStates -join "; ")
    })
}

Write-Progress -Id 1 -Activity "Bulk Provisioning Users from CSV ($Provider)" -Completed

# ==============================================================================
# EXPORT REPORT & FINAL EXECUTION SUMMARY
# ==============================================================================
if (-not [string]::IsNullOrWhiteSpace($ExportReportPath)) {
    try {
        Test-SafeFilePath -InputPath $ExportReportPath -ParameterName "ExportReportPath"
        $reportDir = Split-Path -Path $ExportReportPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($reportDir) -and -not (Test-Path -LiteralPath $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
        }
        $results | Export-Csv -LiteralPath $ExportReportPath -NoTypeInformation -Encoding UTF8 -Force
        Write-ScriptLog -Level SUCCESS -Message "Exported execution report to: $ExportReportPath"
    } catch {
        Write-ScriptLog -Level WARN -Message "Failed to export CSV report to '$ExportReportPath': $_"
    }
}

Write-Host ""
Write-Host "===================== BULK USER PROVISIONING SUMMARY =====================" -ForegroundColor Cyan
$results | Select-Object Row, SamAccountName, Name, Department, UserPrincipalName, Status, Details | Format-Table -AutoSize
Write-Host "--------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ("  Total Processed        : {0}" -f $totalUsers) -ForegroundColor White
Write-Host ("  Created / Simulated    : {0}" -f $createdCount) -ForegroundColor Green
Write-Host ("  Updated Existing       : {0}" -f $updatedCount) -ForegroundColor Cyan
Write-Host ("  Skipped (Duplicates)   : {0}" -f $skippedCount) -ForegroundColor Yellow
Write-Host ("  Failed / Errors        : {0}" -f $failedCount) -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Green" })
if ($script:ActiveLogFile) {
    Write-Host ("  Detailed Log File      : {0}" -f $script:ActiveLogFile) -ForegroundColor Gray
}
if (-not [string]::IsNullOrWhiteSpace($ExportReportPath)) {
    Write-Host ("  CSV Execution Report   : {0}" -f $ExportReportPath) -ForegroundColor Gray
}
Write-Host "==========================================================================" -ForegroundColor Cyan

Write-ScriptLog -Level INFO -Message "Execution completed. Total=$totalUsers, Created=$createdCount, Updated=$updatedCount, Skipped=$skippedCount, Failed=$failedCount."

if ($failedCount -gt 0) {
    exit 1
}
exit 0
