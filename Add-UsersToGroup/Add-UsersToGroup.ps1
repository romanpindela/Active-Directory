<#
================================================================================
  Script Name : Add-UsersToGroup.ps1
  Author      : Roman Pindela
  Contact     : roman.pindela@gmail.com
  Version     : 1.2.0
  Release Date: 2026-10-17
  License     : MIT
  Repository  : https://github.com/romanpindela

  DESCRIPTION:
    Enterprise-grade PowerShell automation script for bulk assigning users
    (e.g., from a plain text file containing logins such as nowi_ksiegowi.txt,
    a CSV file, or an array of usernames) to a target security or distribution
    group — for example, granting access to network file shares or cloud resources.

    Supports both:
    - Local Mode (AD / OnPremises): Windows Server Active Directory Domain Services
      (via ActiveDirectory module: Add-ADGroupMember, Get-ADGroup, Get-ADUser)
    - Cloud Mode (EntraID / Cloud / AzureAD): Microsoft Entra ID cloud directory
      (via Microsoft Graph PowerShell SDK: New-MgGroupMemberByRef, Get-MgGroup,
      Get-MgUser, supporting both interactive sign-in and non-interactive App-Only
      authentication using Client Secret or X.509 Certificate)
    - Hybrid Mode (Both): Assigns users to matching groups in both Local AD and
      Cloud Entra ID in a single execution.

    Key Capabilities:
    1. Zero-Parameter Interactive Help (-Help / -h):
       Displays complete usage instructions, examples, input file formats,
       Entra ID non-interactive setup guide, version, and author details when
       launched without parameters.
    2. Input Sanitization & Defensive Validation:
       Protects against malicious input, path traversal, LDAP injection (RFC 4515),
       and OData filter injection.
    3. Language-Independent UAC Auto-Elevation:
       Verifies Administrator privileges via well-known Windows SID
       (S-1-5-32-544 / BuiltInAdministratorsSid) for full compatibility across
       Polish ("Administratorzy") and English ("Administrators") Windows systems.
    4. Pre-Flight Identity & Membership Verification:
       Verifies target group existence (with optional -CreateGroupIfMissing),
       resolves each user account, skips users who are already members of the
       group (idempotent execution), and tracks per-user status.
    5. Real-Time Granular Progress Bar (Write-Progress):
       Displays live progress, percentage completed, active user login, and
       target group.
    6. Detailed Audit Logging (Enabled by Default):
       Writes UTF-8 timestamped execution logs to:
       C:\Logs\<yyyyMMdd_HHmmss>-Add-UsersToGroup-<ComputerName>-<UserName>.logs
================================================================================
.SYNOPSIS
    Bulk adds users from a text/CSV file or parameter list to a target group in
    Local Active Directory (AD DS) and/or Cloud Microsoft Entra ID (Azure AD).

.DESCRIPTION
    Designed for IT Administrators who need to quickly and reliably assign multiple
    users (for instance, from a text file containing user logins like
    "C:\skrypty\nowi_ksiegowi.txt") to a specific security or distribution group,
    such as a network drive access group ("Dzial_Ksiegowosci").

    Enhances the classic Add-ADGroupMember loop with dual-mode support (Local AD
    and Cloud Entra ID), defensive input validation, duplicate membership checks,
    dry-run simulation (-DryRun / -WhatIf), CSV audit reporting (-ExportReportPath),
    bilingual confirmation prompts (EN Y/N, PL T/N), automatic UAC elevation, and
    detailed logging to C:\Logs.

.PARAMETER Group
    Name, SamAccountName, DistinguishedName, GUID, MailNickname, or ObjectId of
    the target group (e.g., "Dzial_Ksiegowosci").
    Aliases: -Identity, -GroupName, -GroupIdentity, -Grupa, -g

.PARAMETER UsersFile
    Path to a text file (.txt) with one login/UPN per line (e.g.,
    "C:\skrypty\nowi_ksiegowi.txt") or a CSV file (.csv) containing user logins.
    Blank lines and lines starting with '#' are automatically ignored.
    Aliases: -FilePath, -Path, -InputFile, -LoginyFile, -f

.PARAMETER Users
    Direct array of user logins (SamAccountName, UserPrincipalName, Mail, or ObjectId)
    to add to the target group when not reading from a file.
    Aliases: -Members, -Loginy, -UserIdentity, -u

.PARAMETER Mode
    Target directory environment mode:
      - 'Local'   (or 'AD', 'OnPremises')      : Local Active Directory Domain Services (Default).
      - 'Cloud'   (or 'EntraID', 'AzureAD')    : Microsoft Entra ID cloud directory via Graph SDK.
      - 'Both'                                 : Adds users to the group in both Local AD and Cloud Entra ID.
    Aliases: -Provider, -Environment, -Target, -Directory

.PARAMETER CsvColumn
    When -UsersFile points to a .csv file, specifies the column name containing
    user logins. If omitted, automatically detects 'SamAccountName', 'Login',
    'UserPrincipalName', 'UPN', 'User', 'Username', or 'Mail'.

.PARAMETER UpnSuffix
    Optional UPN domain suffix (e.g., "contoso.com"). In Cloud (Entra ID) mode,
    if the input file contains short logins without '@domain' (e.g., "jkowalski"),
    this suffix is appended ("jkowalski@contoso.com") to resolve the cloud user.
    Aliases: -Domain, -DomainSuffix

.PARAMETER DomainController
    Optional specific Active Directory Domain Controller FQDN or IP address to
    target in Local AD mode.
    Aliases: -Server, -DC

.PARAMETER Credential
    Optional PSCredential object for authenticating against Local Active Directory.

.PARAMETER CreateGroupIfMissing
    Switch parameter. Automatically creates the target security group if it does
    not exist in the target directory.

.PARAMETER GroupOU
    Optional Organizational Unit Distinguished Name (DN) where the group should
    be created if -CreateGroupIfMissing is used in Local AD mode.

.PARAMETER GroupScope
    Group scope when creating a missing group in Local AD mode.
    Valid values: 'Global' (default), 'Universal', 'DomainLocal'.

.PARAMETER GenerateSampleFile
    Switch parameter. Generates a ready-to-use sample user logins file
    (default: ".\nowi_ksiegowi.txt") and exits.
    Aliases: -CreateTemplate, -Sample

.PARAMETER ExportReportPath
    Optional file path to export a UTF-8 CSV report summarizing the membership
    assignment result for each processed user.
    Aliases: -ExportCsv, -ReportPath

.PARAMETER TenantId
    Microsoft Entra ID Directory (Tenant) ID for Cloud mode authentication.
    Aliases: -Tenant, -DirectoryId

.PARAMETER ClientId
    Microsoft Entra ID Application (Client) ID for non-interactive Cloud authentication.
    Aliases: -AppId, -ApplicationId

.PARAMETER ClientSecret
    Microsoft Entra ID Client Secret string for non-interactive Cloud authentication.
    Aliases: -Secret

.PARAMETER ClientSecretSecure
    Optional SecureString containing the Microsoft Entra ID Client Secret.

.PARAMETER CertificateThumbprint
    Thumbprint of an X.509 Certificate installed in Cert:\CurrentUser\My or
    Cert:\LocalMachine\My for non-interactive Cloud authentication.
    Aliases: -Thumbprint

.PARAMETER AdminUserPrincipalName
    Optional administrator UPN to pre-populate interactive Microsoft Graph sign-in.
    Aliases: -AdminUPN

.PARAMETER DryRun
    Switch parameter. Simulates adding users to the group (validating group and
    user existence and checking current membership) without modifying AD or Entra ID.
    Aliases: -Simulate, -Preview

.PARAMETER SkipAdminCheck
    Switch parameter. Skips automatic UAC Administrator privilege elevation check.

.PARAMETER PassThru
    Switch parameter. Outputs detailed per-user result objects to the PowerShell pipeline.

.PARAMETER LogPath
    Custom path for the execution log file.
    Default: C:\Logs\<yyyyMMdd_HHmmss>-Add-UsersToGroup-<ComputerName>-<UserName>.logs
    Aliases: -l, -Log

.PARAMETER NoLog
    Switch parameter. Disables writing execution logs to disk.

.PARAMETER Force
    Switch parameter. Bypasses interactive confirmation prompts (Y/N / T/N) for
    unattended automation.

.PARAMETER Help
    Displays detailed script help, examples, Entra ID non-interactive configuration
    guide, version, and author information.
    Aliases: -h

.EXAMPLE
    .\Add-UsersToGroup.ps1
    Displays the built-in help screen, usage examples, version, and author info.

.EXAMPLE
    .\Add-UsersToGroup.ps1 -GenerateSampleFile -UsersFile ".\nowi_ksiegowi.txt"
    Generates a sample text file 'nowi_ksiegowi.txt' with example user logins.

.EXAMPLE
    .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile "C:\skrypty\nowi_ksiegowi.txt"
    Reads user logins from "C:\skrypty\nowi_ksiegowi.txt" and adds each user to
    the Local Active Directory group "Dzial_Ksiegowosci" with detailed logging.

.EXAMPLE
    .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -Users "jkowalski","anowak","pwisniewski" -Mode Local -Force
    Adds the specified user logins directly to the Local AD group "Dzial_Ksiegowosci"
    without interactive confirmation prompts.

.EXAMPLE
    .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" -Mode Cloud -UpnSuffix "firma.pl"
    Adds users from nowi_ksiegowi.txt to the Microsoft Entra ID (Cloud) group
    "Dzial_Ksiegowosci" using interactive Microsoft Graph administrator login.

.EXAMPLE
    .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" `
        -Mode Cloud -UpnSuffix "firma.pl" `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -ClientSecret "YourClientSecretValue" -Force
    Adds users to the Cloud (Entra ID) group non-interactively (unattended mode)
    using an Entra ID App Registration and Client Secret.

.EXAMPLE
    .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" `
        -Mode Cloud -UpnSuffix "firma.pl" `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -CertificateThumbprint "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" -Force
    Adds users to the Cloud (Entra ID) group non-interactively using an X.509 certificate.

.NOTES
    Author  : Roman Pindela
    Email   : roman.pindela@gmail.com
    GitHub  : https://github.com/romanpindela
    Version : 1.2.0
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'AddUsers')]
param(
    [Parameter(ParameterSetName = 'AddUsers', Mandatory = $false, Position = 0)]
    [Alias('Identity', 'GroupName', 'GroupIdentity', 'Grupa', 'g')]
    [string]$Group,

    [Parameter(ParameterSetName = 'AddUsers', Mandatory = $false, Position = 1)]
    [Parameter(ParameterSetName = 'Sample', Mandatory = $false, Position = 0)]
    [Alias('FilePath', 'Path', 'InputFile', 'LoginyFile', 'f')]
    [string]$UsersFile,

    [Parameter(ParameterSetName = 'AddUsers', Mandatory = $false)]
    [Alias('Members', 'Loginy', 'UserIdentity', 'u')]
    [string[]]$Users,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('Provider', 'Environment', 'Target', 'Directory')]
    [ValidateSet('Local', 'AD', 'OnPremises', 'Cloud', 'EntraID', 'AzureAD', 'Both')]
    [string]$Mode = 'Local',

    [Parameter(ParameterSetName = 'AddUsers')]
    [string]$CsvColumn,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('Domain', 'DomainSuffix')]
    [string]$UpnSuffix,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('Server', 'DC')]
    [string]$DomainController,

    [Parameter(ParameterSetName = 'AddUsers')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(ParameterSetName = 'AddUsers')]
    [switch]$CreateGroupIfMissing,

    [Parameter(ParameterSetName = 'AddUsers')]
    [string]$GroupOU,

    [Parameter(ParameterSetName = 'AddUsers')]
    [ValidateSet('Global', 'Universal', 'DomainLocal')]
    [string]$GroupScope = 'Global',

    [Parameter(ParameterSetName = 'Sample', Mandatory = $true)]
    [Alias('CreateTemplate', 'Sample')]
    [switch]$GenerateSampleFile,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('ExportCsv', 'ReportPath')]
    [string]$ExportReportPath,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('Tenant', 'DirectoryId')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('AppId', 'ApplicationId')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('Secret')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'AddUsers')]
    [System.Security.SecureString]$ClientSecretSecure,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('Thumbprint')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('AdminUPN')]
    [string]$AdminUserPrincipalName,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Alias('Simulate', 'Preview')]
    [switch]$DryRun,

    [Parameter(ParameterSetName = 'AddUsers')]
    [switch]$SkipAdminCheck,

    [Parameter(ParameterSetName = 'AddUsers')]
    [switch]$PassThru,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Parameter(ParameterSetName = 'Sample')]
    [Alias('l', 'Log')]
    [string]$LogPath,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Parameter(ParameterSetName = 'Sample')]
    [switch]$NoLog,

    [Parameter(ParameterSetName = 'AddUsers')]
    [Parameter(ParameterSetName = 'Sample')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Help', Mandatory = $true)]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ==============================================================================
# GLOBAL METADATA & STATE
# ==============================================================================
$script:ScriptName    = "Add-UsersToGroup"
$script:ScriptVersion = "1.2.0"
$script:ScriptDate    = "2026-10-17"
$script:ScriptAuthor  = "Roman Pindela"
$script:ScriptEmail   = "roman.pindela@gmail.com"
$script:ScriptGitHub  = "https://github.com/romanpindela"
$script:ActiveLogFile = $null
$script:AuthMode      = "Interactive"

# Normalize Mode ('Local'/'AD'/'OnPremises' -> 'Local', 'Cloud'/'EntraID'/'AzureAD' -> 'Cloud', 'Both' -> 'Both')
$script:NormalizedMode = switch ($Mode.ToUpperInvariant()) {
    'LOCAL'      { 'Local' }
    'AD'         { 'Local' }
    'ONPREMISES' { 'Local' }
    'CLOUD'      { 'Cloud' }
    'ENTRAID'    { 'Cloud' }
    'AZUREAD'    { 'Cloud' }
    'BOTH'       { 'Both' }
    default      { 'Local' }
}

# ==============================================================================
# HELP & DOCUMENTATION DISPLAY (-Help / -h / Zero-Parameters)
# ==============================================================================
function Show-ScriptHelp {
    $helpText = @"
================================================================================
  SCRIPT  : Add-UsersToGroup.ps1
  VERSION : $script:ScriptVersion ($script:ScriptDate)
  AUTHOR  : $script:ScriptAuthor
  CONTACT : $script:ScriptEmail | $script:ScriptGitHub
================================================================================

DESCRIPTION:
    Enterprise PowerShell utility to bulk assign multiple users (e.g., from a
    plain text file containing logins such as nowi_ksiegowi.txt, a CSV file, or
    a command-line array) to a selected security or distribution group (for
    example, granting access to shared network drives like "Dzial_Ksiegowosci").

    Supports three operational modes (-Mode / -Provider):
      1. Local (AD / OnPremises) : Local Active Directory Domain Services
                                   (via ActiveDirectory module: Add-ADGroupMember).
      2. Cloud (EntraID / Cloud) : Microsoft Entra ID / Azure AD cloud directory
                                   (via Microsoft Graph SDK: New-MgGroupMemberByRef).
      3. Both                    : Assigns users to the target group in both
                                   Local Active Directory and Cloud Entra ID.

INPUT FILE FORMAT (e.g. nowi_ksiegowi.txt):
    Plain text file (.txt) with one user login (SamAccountName or UPN) per line.
    Blank lines and comment lines starting with '#' are automatically ignored:
      # New Accounting Department Employees
      jkowalski
      anowak
      pwisniewski
      mkaminska

    Also supports CSV files (.csv) with comma (',') or semicolon (';') delimiters
    and columns such as SamAccountName, Login, UserPrincipalName, UPN, or Mail.

--------------------------------------------------------------------------------
HOW TO CONFIGURE ENTRA ID FOR NON-INTERACTIVE / UNATTENDED AUTHENTICATION:
(Only via API Keys / Credentials and Entra ID Microsoft Graph SDK Permissions)
--------------------------------------------------------------------------------
To run this script in unattended / non-interactive Cloud mode against Microsoft
Entra ID (e.g., in Windows Task Scheduler, HR onboarding pipelines, or CI/CD)
without any interactive browser prompts:

Step 1: Register an Application in Microsoft Entra ID
    1. Sign in to the Microsoft Entra admin center (https://entra.microsoft.com).
    2. Navigate to: Identity > Applications > App registrations > New registration.
    3. Name: 'AD-Group-Membership-Automation'.
    4. Supported account types: 'Accounts in this organizational directory only'.
    5. Click 'Register' and copy:
       - Application (client) ID  -> pass to -ClientId
       - Directory (tenant) ID    -> pass to -TenantId

Step 2: Grant Microsoft Graph API Application Permissions (App-Only)
    1. In the App Registration, go to: Manage > API permissions > Add a permission.
    2. Select 'Microsoft Graph' > 'Application permissions' (NOT Delegated).
    3. Search for and check the following permissions:
       * GroupMember.ReadWrite.All  (Required to read and add group members)
       * Group.ReadWrite.All        (Required if using -CreateGroupIfMissing)
       * User.Read.All              (Required to resolve user logins/UPNs to ObjectIds)
    4. Click 'Add permissions'.
    5. Click 'Grant admin consent for <Your Tenant>' and confirm green checkmarks.
       (Note: For role-assignable security groups in Entra ID, also assign the
       App Registration Service Principal to the 'Groups Administrator' role).

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
         -Mode Cloud -TenantId '<TenantId>' -ClientId '<ClientId>' -ClientSecret '<SecretValue>'

    Option B: X.509 Certificate (Recommended for Production Automation)
      1. Generate a self-signed certificate in PowerShell:
         `$cert = New-SelfSignedCertificate -Subject 'CN=EntraGroupAutomation' ``
             -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable ``
             -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
         Export-Certificate -Cert `$cert -FilePath 'C:\Logs\EntraGroupAutomation.cer'
      2. In Entra Admin Center: Manage > Certificates & secrets > Certificates > Upload certificate.
         Upload 'EntraGroupAutomation.cer'.
      3. Connect non-interactively via Microsoft Graph SDK:
         Connect-MgGraph -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint `$cert.Thumbprint -NoWelcome
      4. Or pass directly to this script:
         -Mode Cloud -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint `$cert.Thumbprint

--------------------------------------------------------------------------------
USAGE EXAMPLES:
--------------------------------------------------------------------------------
  # 1. Generate a ready-to-use sample logins file (nowi_ksiegowi.txt):
  .\Add-UsersToGroup.ps1 -GenerateSampleFile -UsersFile ".\nowi_ksiegowi.txt"

  # 2. Add users from a text file to a Local Active Directory group:
  .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile "C:\skrypty\nowi_ksiegowi.txt"

  # 3. Add explicit user logins to a Local AD group without confirmation prompts:
  .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -Users "jkowalski","anowak" -Mode Local -Force

  # 4. Preview (Dry-Run) adding users to a group without making directory changes:
  .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" -DryRun

  # 5. Add users to a Cloud (Microsoft Entra ID) group (Interactive Admin Sign-In):
  .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" ``
      -Mode Cloud -UpnSuffix "firma.pl"

  # 6. Add users to a Cloud (Entra ID) group Non-Interactively via Client Secret:
  .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" ``
      -Mode Cloud ``
      -UpnSuffix "contoso.com" ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -ClientSecret "YourClientSecretValueHere" ``
      -Force

  # 7. Add users to a Cloud (Entra ID) group Non-Interactively via X.509 Certificate:
  .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" ``
      -Mode Cloud ``
      -UpnSuffix "contoso.com" ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -CertificateThumbprint "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" ``
      -Force

  # 8. Hybrid Mode (Both Local AD and Cloud Entra ID) with CSV audit report export:
  .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile ".\nowi_ksiegowi.txt" ``
      -Mode Both -UpnSuffix "contoso.com" ``
      -ExportReportPath "C:\Logs\Dzial_Ksiegowosci_Report.csv" -Force

--------------------------------------------------------------------------------
PARAMETERS:
--------------------------------------------------------------------------------
  -Group, -Identity, -Grupa     Target group name, SamAccountName, DN, GUID, or ObjectId.
  -UsersFile, -FilePath, -Path  Path to .txt or .csv file containing user logins.
  -Users, -Members, -Loginy     Array of user logins passed directly via CLI.
  -Mode, -Provider              Directory mode: 'Local' ('AD'), 'Cloud' ('EntraID'), or 'Both'.
  -CsvColumn                    Column name if -UsersFile is a CSV file.
  -UpnSuffix, -Domain           Domain suffix appended to short logins in Cloud mode.
  -DomainController, -Server    Specific AD Domain Controller to target in Local mode.
  -Credential                   PSCredential for Local Active Directory operations.
  -CreateGroupIfMissing         Automatically create the group if it does not exist.
  -GroupOU                      Target OU DN when creating a missing group in Local AD.
  -GroupScope                   Group scope when creating a group ('Global', 'Universal', 'DomainLocal').
  -GenerateSampleFile, -Sample  Generate a sample logins text file (nowi_ksiegowi.txt) and exit.
  -ExportReportPath, -ExportCsv Export per-user execution results to a UTF-8 CSV file.
  -TenantId                     Entra ID Tenant ID (for non-interactive Cloud auth).
  -ClientId                     Entra ID App Client ID (for non-interactive Cloud auth).
  -ClientSecret                 Entra ID Client Secret (for non-interactive Cloud auth).
  -CertificateThumbprint        X.509 Certificate thumbprint (for non-interactive Cloud auth).
  -AdminUserPrincipalName       Admin UPN hint for interactive Cloud sign-in.
  -DryRun, -Simulate            Validate and simulate group membership changes without applying.
  -SkipAdminCheck               Skip automatic UAC administrator elevation check.
  -PassThru                     Output result objects to the PowerShell pipeline.
  -LogPath, -Log                Custom log path (Default: C:\Logs\<timestamp>-Add-UsersToGroup-<PC>-<User>.logs).
  -NoLog                        Disable file logging.
  -Force                        Bypass interactive confirmation prompts (Y/N / T/N).
  -Help, -h                     Display this help manual.

LOGGING:
  Detailed execution logs are automatically written by default to:
  C:\Logs\<yyyyMMdd_HHmmss>-Add-UsersToGroup-<ComputerName>-<UserName>.logs

SECURITY & UNBLOCKING:
  After downloading this script from GitHub, unblock the file before execution:
  Unblock-File -Path .\Add-UsersToGroup.ps1
================================================================================
"@
    Write-Host $helpText -ForegroundColor Cyan
}

# ==============================================================================
# LOGGING ENGINE (Default: C:\Logs\<DateTime>-Add-UsersToGroup-<PC>-<User>.logs)
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
  Mode          : $script:NormalizedMode ($Mode)
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
            } elseif ($val -isnot [System.Security.SecureString] -and $val -isnot [System.Management.Automation.PSCredential]) {
                $escapedArgs += "-$key `"$val`""
            }
        }
        Start-Process powershell.exe -ArgumentList ($escapedArgs -join " ") -Verb RunAs
        Exit
    }
}

if (-not $GenerateSampleFile -and -not $SkipAdminCheck -and -not $DryRun -and ($script:NormalizedMode -eq 'Local' -or $script:NormalizedMode -eq 'Both')) {
    Assert-AdministratorPrivileges
}

# Initialize logging
Initialize-ScriptLogging
Write-ScriptLog -Level INFO -Message "Initialized $script:ScriptName v$script:ScriptVersion in '$script:NormalizedMode' mode."
if ($script:ActiveLogFile) {
    Write-ScriptLog -Level INFO -Message "Active log file: $script:ActiveLogFile"
}

# ==============================================================================
# DEFENSIVE INPUT SANITIZATION & SECURITY HELPERS
# ==============================================================================
function Assert-SafeInput {
    param(
        [Parameter(Mandatory = $false)]
        [string]$InputValue,
        [Parameter(Mandatory = $true)]
        [string]$ParameterName,
        [int]$MaxLength = 512
    )

    if ([string]::IsNullOrWhiteSpace($InputValue)) { return }

    if ($InputValue.Length -gt $MaxLength) {
        throw "Security Validation Failed: Parameter '-$ParameterName' exceeds maximum allowed length ($MaxLength characters)."
    }

    # Block null bytes and command/script injection tokens
    if ($InputValue -match '[\x00;`$\|<>&\r\n]') {
        throw "Security Validation Failed: Parameter '-$ParameterName' contains illegal or potentially dangerous characters: '$InputValue'."
    }
}

function Test-SafeFilePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputPath,
        [string]$ParameterName = "UsersFile"
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        throw "Parameter '-$ParameterName' cannot be empty or whitespace."
    }

    if ($InputPath -match '[\x00\|<>\?\*]') {
        throw "Security Validation Failed: Parameter '-$ParameterName' contains illegal path characters: '$InputPath'."
    }
}

function ConvertTo-SafeLdapFilterValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return "" }
    # RFC 4515 LDAP filter escaping
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace("`0", '\00')
}

function ConvertTo-SafeODataValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return "" }
    return $Value.Replace("'", "''")
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
# SAMPLE LOGINS FILE GENERATOR (-GenerateSampleFile)
# ==============================================================================
if ($GenerateSampleFile) {
    $targetSampleFile = if ([string]::IsNullOrWhiteSpace($UsersFile)) {
        Join-Path -Path (Get-Location).Path -ChildPath "nowi_ksiegowi.txt"
    } else {
        $UsersFile
    }

    Test-SafeFilePath -InputPath $targetSampleFile -ParameterName "UsersFile"

    if ((Test-Path -LiteralPath $targetSampleFile) -and -not $Force) {
        $overwriteChoice = Read-Host "[?] File '$targetSampleFile' already exists. Overwrite? [Y/T = Yes/Tak, N = No/Nie]"
        if ($overwriteChoice -notmatch '^(Y|y|T|t|Yes|yes|Tak|tak)$') {
            Write-ScriptLog -Level WARN -Message "Sample file generation cancelled by user."
            exit 0
        }
    }

    $sampleText = @"
# Sample user logins list for Add-UsersToGroup.ps1
# Group example: Dzial_Ksiegowosci
# Specify one SamAccountName or UserPrincipalName per line:
jkowalski
anowak
pwisniewski
mkaminska
tzelazny
"@

    $parentDir = Split-Path -Path $targetSampleFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
    }

    Set-Content -LiteralPath $targetSampleFile -Value $sampleText -Encoding UTF8 -Force
    Write-ScriptLog -Level SUCCESS -Message "Sample logins file created successfully at: $targetSampleFile"
    exit 0
}

# ==============================================================================
# PARAMETER & INPUT VALIDATION
# ==============================================================================
if ([string]::IsNullOrWhiteSpace($Group)) {
    Write-ScriptLog -Level ERROR -Message "Missing required parameter: -Group (e.g., -Group 'Dzial_Ksiegowosci'). Run with -Help (-h) for usage examples."
    exit 1
}

Assert-SafeInput -InputValue $Group -ParameterName "Group" -MaxLength 256
Assert-SafeInput -InputValue $UpnSuffix -ParameterName "UpnSuffix" -MaxLength 255
Assert-SafeInput -InputValue $DomainController -ParameterName "DomainController" -MaxLength 255
Assert-SafeInput -InputValue $GroupOU -ParameterName "GroupOU" -MaxLength 512
Assert-SafeInput -InputValue $TenantId -ParameterName "TenantId" -MaxLength 128
Assert-SafeInput -InputValue $ClientId -ParameterName "ClientId" -MaxLength 128
Assert-SafeInput -InputValue $CertificateThumbprint -ParameterName "CertificateThumbprint" -MaxLength 128
Assert-SafeInput -InputValue $AdminUserPrincipalName -ParameterName "AdminUserPrincipalName" -MaxLength 256

if ([string]::IsNullOrWhiteSpace($UsersFile) -and ($null -eq $Users -or $Users.Count -eq 0)) {
    Write-ScriptLog -Level ERROR -Message "No user logins provided! Specify either -UsersFile (e.g., 'C:\skrypty\nowi_ksiegowi.txt') or -Users ('login1','login2')."
    exit 1
}

# ==============================================================================
# LOAD & SANITIZE USER LOGINS (FROM .TXT, .CSV, OR -Users ARRAY)
# ==============================================================================
$userLoginsList = New-Object System.Collections.Generic.List[string]

if (-not [string]::IsNullOrWhiteSpace($UsersFile)) {
    Test-SafeFilePath -InputPath $UsersFile -ParameterName "UsersFile"

    if (-not (Test-Path -LiteralPath $UsersFile -PathType Leaf)) {
        Write-ScriptLog -Level ERROR -Message "Input file not found: '$UsersFile'. Verify the path or generate a sample file with -GenerateSampleFile."
        exit 1
    }

    $resolvedFile = (Resolve-Path -LiteralPath $UsersFile).Path
    $extension    = [System.IO.Path]::GetExtension($resolvedFile).ToLowerInvariant()
    Write-ScriptLog -Level STEP -Message "Loading user logins from file: $resolvedFile"

    if ($extension -eq '.csv') {
        $firstLine = Get-Content -LiteralPath $resolvedFile -TotalCount 1 -Encoding UTF8
        $detectedDelimiter = if ($firstLine -and ($firstLine.Split(';').Count -gt $firstLine.Split(',').Count)) { ';' } else { ',' }
        $csvRows = @(Import-Csv -LiteralPath $resolvedFile -Delimiter $detectedDelimiter -Encoding UTF8)

        if ($csvRows.Count -eq 0) {
            Write-ScriptLog -Level WARN -Message "CSV file '$resolvedFile' contains no rows."
        } else {
            $availableCols = @($csvRows[0].PSObject.Properties.Name)
            $selectedCol = $null

            if (-not [string]::IsNullOrWhiteSpace($CsvColumn)) {
                $selectedCol = $availableCols | Where-Object { $_ -ieq $CsvColumn } | Select-Object -First 1
                if (-not $selectedCol) {
                    Write-ScriptLog -Level ERROR -Message "Specified column '$CsvColumn' not found in CSV. Available columns: $($availableCols -join ', ')"
                    exit 1
                }
            } else {
                $candidateCols = @('SamAccountName', 'Login', 'Loginy', 'UserPrincipalName', 'UPN', 'User', 'Username', 'Mail', 'EmailAddress', 'Name')
                foreach ($cand in $candidateCols) {
                    $matchCol = $availableCols | Where-Object { $_ -ieq $cand } | Select-Object -First 1
                    if ($matchCol) {
                        $selectedCol = $matchCol
                        break
                    }
                }
                if (-not $selectedCol) {
                    $selectedCol = $availableCols[0]
                }
            }

            Write-ScriptLog -Level INFO -Message "Detected CSV delimiter '$detectedDelimiter' and login column '$selectedCol'."
            foreach ($row in $csvRows) {
                $rawVal = [string]$row.$selectedCol
                if (-not [string]::IsNullOrWhiteSpace($rawVal)) {
                    $trimmed = $rawVal.Trim()
                    if (-not $trimmed.StartsWith('#')) {
                        $userLoginsList.Add($trimmed)
                    }
                }
            }
        }
    } else {
        # Plain text file (.txt) - e.g. Get-Content "C:\skrypty\nowi_ksiegowi.txt"
        $rawLines = @(Get-Content -LiteralPath $resolvedFile -Encoding UTF8)
        foreach ($line in $rawLines) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                $trimmed = $line.Trim()
                # Ignore comment lines starting with '#' or '//'
                if (-not $trimmed.StartsWith('#') -and -not $trimmed.StartsWith('//')) {
                    $userLoginsList.Add($trimmed)
                }
            }
        }
    }
}

if ($null -ne $Users -and $Users.Count -gt 0) {
    foreach ($u in $Users) {
        if (-not [string]::IsNullOrWhiteSpace($u)) {
            foreach ($splitItem in ($u -split '[,;]')) {
                $trimmed = $splitItem.Trim()
                if (-not [string]::IsNullOrWhiteSpace($trimmed)) {
                    $userLoginsList.Add($trimmed)
                }
            }
        }
    }
}

# Deduplicate while preserving order and validate each login
$uniqueLogins = New-Object System.Collections.Generic.List[string]
$seenSet      = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

foreach ($loginItem in $userLoginsList) {
    Assert-SafeInput -InputValue $loginItem -ParameterName "UserLogin" -MaxLength 256
    if ($seenSet.Add($loginItem)) {
        $uniqueLogins.Add($loginItem)
    } else {
        Write-ScriptLog -Level WARN -Message "Skipping duplicate login entry in input list: '$loginItem'"
    }
}

if ($uniqueLogins.Count -eq 0) {
    Write-ScriptLog -Level ERROR -Message "No valid user logins found after parsing input. Nothing to process."
    exit 1
}

Write-ScriptLog -Level INFO -Message "Target Group : $Group"
Write-ScriptLog -Level INFO -Message "Target Mode  : $script:NormalizedMode"
Write-ScriptLog -Level INFO -Message "Total Users  : $($uniqueLogins.Count) unique user login(s) queued for assignment."

# ==============================================================================
# INTERACTIVE CONFIRMATION PROMPT (Bilingual English Y/N & Polish T/N)
# ==============================================================================
if (-not $Force -and -not $DryRun) {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Yellow
    Write-Host "  CONFIRMATION REQUIRED / WYMAGANE POTWIERDZENIE" -ForegroundColor Yellow
    Write-Host "  Target Group (Grupa) : $Group" -ForegroundColor White
    Write-Host "  Directory Mode       : $script:NormalizedMode" -ForegroundColor White
    Write-Host "  Users to Add         : $($uniqueLogins.Count) user(s) ($($uniqueLogins[0..([Math]::Min(4, $uniqueLogins.Count - 1))] -join ', ')...)" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Yellow
    $confirmInput = Read-Host "Do you want to proceed with adding users to '$Group'? [Y/T = Yes/Tak, N = No/Nie]"
    if ($confirmInput -notmatch '^(Y|y|T|t|Yes|yes|Tak|tak)$') {
        Write-ScriptLog -Level WARN -Message "Operation cancelled by user at confirmation prompt."
        exit 0
    }
}

# ==============================================================================
# LOCAL ACTIVE DIRECTORY ENGINE (Mode: Local / Both)
# ==============================================================================
function Initialize-LocalADEnvironment {
    Write-ScriptLog -Level STEP -Message "Initializing Local Active Directory environment (ActiveDirectory module)..."
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory PowerShell module (RSAT-AD-PowerShell) is not installed on this machine. Install RSAT or use '-Mode Cloud' for Microsoft Entra ID."
        }
        Import-Module -Name ActiveDirectory -ErrorAction Stop
    }

    $adCommonParams = @{}
    if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
        $adCommonParams['Server'] = $DomainController
    }
    if ($null -ne $Credential) {
        $adCommonParams['Credential'] = $Credential
    }

    try {
        $domainInfo = Get-ADDomain @adCommonParams -ErrorAction Stop
        Write-ScriptLog -Level SUCCESS -Message "Connected to Local Active Directory Domain: $($domainInfo.DNSRoot) (Domain Controller: $($domainInfo.PDCEmulator))"
    } catch {
        throw "Failed to contact Local Active Directory Domain Controller: $($_.Exception.Message)"
    }

    return $adCommonParams
}

function Resolve-LocalADGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $true)]
        [hashtable]$AdParams
    )

    $adGroup = $null
    try {
        $adGroup = Get-ADGroup -Identity $GroupName @AdParams -ErrorAction Stop
    } catch {
        $safeVal = ConvertTo-SafeLdapFilterValue -Value $GroupName
        $ldapFilter = "(|(sAMAccountName=$safeVal)(name=$safeVal)(displayName=$safeVal)(mail=$safeVal))"
        $matched = @(Get-ADGroup -LDAPFilter $ldapFilter @AdParams -ErrorAction SilentlyContinue)
        if ($matched.Count -eq 1) {
            $adGroup = $matched[0]
        } elseif ($matched.Count -gt 1) {
            throw "Multiple Local AD groups matched '$GroupName'. Please specify the exact SamAccountName or DistinguishedName."
        }
    }

    if ($null -eq $adGroup) {
        if ($CreateGroupIfMissing) {
            if ($DryRun) {
                Write-ScriptLog -Level WARN -Message "[DRY-RUN] Would create missing Local AD Security Group '$GroupName' (Scope: $GroupScope)."
                return [PSCustomObject]@{
                    Name              = $GroupName
                    SamAccountName    = $GroupName
                    DistinguishedName = "CN=$GroupName,CN=Users,DC=dryrun,DC=local"
                    IsSimulated       = $true
                }
            }
            Write-ScriptLog -Level WARN -Message "Local AD group '$GroupName' not found. Creating new Security Group (Scope: $GroupScope)..."
            $newGroupParams = @{
                Name          = $GroupName
                SamAccountName = $GroupName
                GroupCategory = 'Security'
                GroupScope    = $GroupScope
                Description   = "Created automatically by Add-UsersToGroup.ps1 on $((Get-Date).ToString('yyyy-MM-dd'))"
                PassThru      = $true
            }
            if (-not [string]::IsNullOrWhiteSpace($GroupOU)) {
                $newGroupParams['Path'] = $GroupOU
            }
            foreach ($k in $AdParams.Keys) { $newGroupParams[$k] = $AdParams[$k] }
            $adGroup = New-ADGroup @newGroupParams -ErrorAction Stop
            Write-ScriptLog -Level SUCCESS -Message "Created Local AD group '$($adGroup.Name)' ($($adGroup.DistinguishedName))."
        } else {
            throw "Local Active Directory group '$GroupName' does not exist. Verify the group name or pass -CreateGroupIfMissing."
        }
    }

    Write-ScriptLog -Level INFO -Message "Resolved Local AD Group: $($adGroup.Name) (SamAccountName: $($adGroup.SamAccountName), DN: $($adGroup.DistinguishedName))"
    return $adGroup
}

function Invoke-LocalADGroupAssignment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Logins
    )

    $results = New-Object System.Collections.Generic.List[object]
    $adParams = Initialize-LocalADEnvironment
    $targetAdGroup = Resolve-LocalADGroup -GroupName $GroupName -AdParams $adParams

    # Retrieve existing group members for idempotency check
    $existingMembersSam = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $existingMembersDn  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    if (-not ($targetAdGroup.PSObject.Properties['IsSimulated'] -and $targetAdGroup.IsSimulated)) {
        try {
            $currentMembers = @(Get-ADGroupMember -Identity $targetAdGroup.DistinguishedName @adParams -ErrorAction Stop)
            foreach ($m in $currentMembers) {
                if ($m.SamAccountName) { [void]$existingMembersSam.Add($m.SamAccountName) }
                if ($m.distinguishedName) { [void]$existingMembersDn.Add($m.distinguishedName) }
            }
            Write-ScriptLog -Level INFO -Message "Group '$($targetAdGroup.Name)' currently has $($currentMembers.Count) direct member(s)."
        } catch {
            Write-ScriptLog -Level WARN -Message "Could not pre-fetch existing members for '$($targetAdGroup.Name)': $($_.Exception.Message)"
        }
    }

    $total = $Logins.Count
    $index = 0

    foreach ($Login in $Logins) {
        $index++
        $percent = [int](($index / $total) * 100)
        Write-Progress -Id 1 -Activity "Local Active Directory: Adding Users to Group '$($targetAdGroup.Name)'" `
            -Status "[$index/$total] Processing user: $Login ($percent%)" -PercentComplete $percent

        $status  = "Pending"
        $details = ""
        $resolvedSam = $Login
        $resolvedUpn = ""

        try {
            # Resolve AD user by Identity or LDAP filter (SamAccountName, UPN, Mail, Name)
            $adUser = $null
            try {
                $adUser = Get-ADUser -Identity $Login -Properties SamAccountName, UserPrincipalName, DisplayName, Enabled @adParams -ErrorAction Stop
            } catch {
                $safeLogin = ConvertTo-SafeLdapFilterValue -Value $Login
                $shortLogin = if ($Login -match '^([^@]+)@') { ConvertTo-SafeLdapFilterValue -Value $Matches[1] } else { $safeLogin }
                $ldapQuery = "(|(sAMAccountName=$safeLogin)(userPrincipalName=$safeLogin)(mail=$safeLogin)(sAMAccountName=$shortLogin))"
                $foundUsers = @(Get-ADUser -LDAPFilter $ldapQuery -Properties SamAccountName, UserPrincipalName, DisplayName, Enabled @adParams -ErrorAction SilentlyContinue)
                if ($foundUsers.Count -eq 1) {
                    $adUser = $foundUsers[0]
                } elseif ($foundUsers.Count -gt 1) {
                    throw "Ambiguous login '$Login': matched $($foundUsers.Count) AD user accounts."
                }
            }

            if ($null -eq $adUser) {
                $status  = "UserNotFound"
                $details = "User '$Login' was not found in Local Active Directory."
                Write-ScriptLog -Level ERROR -Message "[Local AD] $details"
            } else {
                $resolvedSam = $adUser.SamAccountName
                $resolvedUpn = [string]$adUser.UserPrincipalName

                if ($existingMembersSam.Contains($adUser.SamAccountName) -or $existingMembersDn.Contains($adUser.DistinguishedName)) {
                    $status  = "AlreadyMember"
                    $details = "User '$resolvedSam' is already a member of group '$($targetAdGroup.Name)'."
                    Write-ScriptLog -Level WARN -Message "[Local AD] $details"
                } elseif ($DryRun -or -not $PSCmdlet.ShouldProcess("User '$resolvedSam' -> Group '$($targetAdGroup.Name)'", "Add-ADGroupMember")) {
                    $status  = "Simulated"
                    $details = "[DRY-RUN] Would add user '$resolvedSam' to Local AD group '$($targetAdGroup.Name)'."
                    Write-ScriptLog -Level INFO -Message "[Local AD] $details"
                } else {
                    Add-ADGroupMember -Identity $targetAdGroup.DistinguishedName -Members $adUser.DistinguishedName @adParams -ErrorAction Stop
                    [void]$existingMembersSam.Add($adUser.SamAccountName)
                    [void]$existingMembersDn.Add($adUser.DistinguishedName)

                    # Core confirmation output requested by specification
                    Write-Host "Dodano użytkownika: $Login do grupy $($targetAdGroup.Name)" -ForegroundColor Green
                    Write-ScriptLog -Level SUCCESS -Message "[Local AD] Added user: $Login (SamAccountName: $resolvedSam) to group '$($targetAdGroup.Name)'." -NoConsole

                    $status  = "Added"
                    $details = "Successfully added '$resolvedSam' to Local AD group '$($targetAdGroup.Name)'."
                }
            }
        } catch {
            $status  = "Failed"
            $details = $_.Exception.Message
            Write-ScriptLog -Level ERROR -Message "[Local AD] Failed to add user '$Login' to group '$($targetAdGroup.Name)': $details"
        }

        $results.Add([PSCustomObject]@{
            Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Environment       = "LocalAD"
            Group             = $targetAdGroup.Name
            InputLogin        = $Login
            ResolvedAccount   = $resolvedSam
            UserPrincipalName = $resolvedUpn
            Status            = $status
            Details           = $details
        })
    }

    Write-Progress -Id 1 -Activity "Local Active Directory: Adding Users to Group '$($targetAdGroup.Name)'" -Completed
    return $results
}

# ==============================================================================
# CLOUD MICROSOFT ENTRA ID ENGINE (Mode: Cloud / Both)
# ==============================================================================
function Connect-EntraIDDirectory {
    Write-ScriptLog -Level STEP -Message "Initializing Cloud Microsoft Entra ID connection (Microsoft Graph SDK)..."

    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups')
    foreach ($mod in $requiredModules) {
        if (-not (Get-Module -Name $mod -ErrorAction SilentlyContinue)) {
            if (-not (Get-Module -ListAvailable -Name $mod)) {
                throw "Required Microsoft Graph SDK module '$mod' is not installed. Install it via: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups -Scope CurrentUser"
            }
            Import-Module -Name $mod -ErrorAction Stop
        }
    }

    $plainSecret = if ($null -ne $ClientSecretSecure) {
        Convert-SecureStringToPlain -SecureValue $ClientSecretSecure
    } else {
        $ClientSecret
    }

    # Mode 1: Non-Interactive App-Only via Client Secret
    if (-not [string]::IsNullOrWhiteSpace($TenantId) -and -not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($plainSecret)) {
        $script:AuthMode = "AppOnly-ClientSecret"
        Write-ScriptLog -Level INFO -Message "Authenticating to Microsoft Graph non-interactively using Client Secret (AppId: $ClientId, TenantId: $TenantId)..."
        $secString = ConvertTo-SecureString -String $plainSecret -AsPlainText -Force
        $clientCred = New-Object System.Management.Automation.PSCredential($ClientId, $secString)
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $clientCred -NoWelcome -ErrorAction Stop
    }
    # Mode 2: Non-Interactive App-Only via X.509 Certificate Thumbprint
    elseif (-not [string]::IsNullOrWhiteSpace($TenantId) -and -not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        $script:AuthMode = "AppOnly-Certificate"
        Write-ScriptLog -Level INFO -Message "Authenticating to Microsoft Graph non-interactively using Certificate Thumbprint '$CertificateThumbprint' (AppId: $ClientId)..."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    # Mode 3: Interactive Delegated Admin Sign-In (or reuse active session)
    else {
        $script:AuthMode = "Interactive-Delegated"
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        $scopes = @("GroupMember.ReadWrite.All", "Group.ReadWrite.All", "User.Read.All")

        if ($null -eq $ctx -or [string]::IsNullOrWhiteSpace($ctx.Account)) {
            Write-ScriptLog -Level INFO -Message "Launching interactive Microsoft Entra ID administrator login..."
            $connectParams = @{
                Scopes      = $scopes
                NoWelcome   = $true
                ErrorAction = 'Stop'
            }
            if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
                $connectParams['TenantId'] = $TenantId
            }
            Connect-MgGraph @connectParams
        } else {
            Write-ScriptLog -Level INFO -Message "Reusing active Microsoft Graph session (Account: $($ctx.Account), Tenant: $($ctx.TenantId))."
        }
    }

    $activeCtx = Get-MgContext -ErrorAction Stop
    Write-ScriptLog -Level SUCCESS -Message "Connected to Microsoft Entra ID (TenantId: $($activeCtx.TenantId), AuthMode: $script:AuthMode)."
}

function Resolve-CloudEntraGroup {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    $mgGroup = $null
    $guidParsed = [Guid]::Empty
    if ([Guid]::TryParse($GroupName, [ref]$guidParsed)) {
        try {
            $mgGroup = Get-MgGroup -GroupId $GroupName -ErrorAction Stop
        } catch {}
    }

    if ($null -eq $mgGroup) {
        $safeOData = ConvertTo-SafeODataValue -Value $GroupName
        $filterStr = "displayName eq '$safeOData' or mailNickname eq '$safeOData' or mail eq '$safeOData'"
        $matchedGroups = @(Get-MgGroup -Filter $filterStr -ErrorAction Stop)
        if ($matchedGroups.Count -eq 1) {
            $mgGroup = $matchedGroups[0]
        } elseif ($matchedGroups.Count -gt 1) {
            throw "Multiple Microsoft Entra ID groups matched '$GroupName' ($($matchedGroups.Count) matches). Please specify the exact Group ObjectId (GUID)."
        }
    }

    if ($null -eq $mgGroup) {
        if ($CreateGroupIfMissing) {
            $mailNick = ($GroupName -replace '[^a-zA-Z0-9_-]', '')
            if ([string]::IsNullOrWhiteSpace($mailNick)) { $mailNick = "group-" + (Get-Random -Minimum 1000 -Maximum 9999) }

            if ($DryRun) {
                Write-ScriptLog -Level WARN -Message "[DRY-RUN] Would create missing Microsoft Entra ID Security Group '$GroupName' (MailNickname: $mailNick)."
                return [PSCustomObject]@{
                    Id          = "00000000-0000-0000-0000-000000000000"
                    DisplayName = $GroupName
                    IsSimulated = $true
                }
            }

            Write-ScriptLog -Level WARN -Message "Cloud Entra ID group '$GroupName' not found. Creating new Cloud Security Group..."
            $mgGroup = New-MgGroup -DisplayName $GroupName `
                -MailEnabled:$false `
                -MailNickname $mailNick `
                -SecurityEnabled:$true `
                -Description "Created automatically by Add-UsersToGroup.ps1 on $((Get-Date).ToString('yyyy-MM-dd'))" `
                -ErrorAction Stop
            Write-ScriptLog -Level SUCCESS -Message "Created Cloud Entra ID Security Group '$($mgGroup.DisplayName)' (ObjectId: $($mgGroup.Id))."
        } else {
            throw "Cloud Microsoft Entra ID group '$GroupName' does not exist. Verify the group DisplayName/ObjectId or pass -CreateGroupIfMissing."
        }
    }

    Write-ScriptLog -Level INFO -Message "Resolved Cloud Entra ID Group: $($mgGroup.DisplayName) (ObjectId: $($mgGroup.Id))"
    return $mgGroup
}

function Resolve-CloudEntraUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Login
    )

    $mgUser = $null
    $candidateIdentity = $Login
    if ($Login -notmatch '@' -and -not [Guid]::TryParse($Login, [ref]([Guid]::Empty)) -and -not [string]::IsNullOrWhiteSpace($UpnSuffix)) {
        $candidateIdentity = "$Login@$($UpnSuffix.TrimStart('@'))"
    }

    try {
        $mgUser = Get-MgUser -UserId $candidateIdentity -Property Id, UserPrincipalName, DisplayName, Mail, MailNickname, AccountEnabled -ErrorAction Stop
        if ($null -ne $mgUser) { return $mgUser }
    } catch {}

    $safeLogin = ConvertTo-SafeODataValue -Value $Login
    $safeCand  = ConvertTo-SafeODataValue -Value $candidateIdentity
    $filterQuery = "userPrincipalName eq '$safeCand' or mail eq '$safeCand' or mailNickname eq '$safeLogin' or onPremisesSamAccountName eq '$safeLogin'"

    try {
        $matched = @(Get-MgUser -Filter $filterQuery -Property Id, UserPrincipalName, DisplayName, Mail, MailNickname, AccountEnabled -ErrorAction Stop)
        if ($matched.Count -eq 1) {
            return $matched[0]
        } elseif ($matched.Count -gt 1) {
            throw "Ambiguous login '$Login': matched $($matched.Count) accounts in Microsoft Entra ID."
        }
    } catch {
        # Fallback if onPremisesSamAccountName filter is not supported without ConsistencyLevel eventual
        $fallbackFilter = "userPrincipalName eq '$safeCand' or mail eq '$safeCand' or mailNickname eq '$safeLogin'"
        $matched = @(Get-MgUser -Filter $fallbackFilter -Property Id, UserPrincipalName, DisplayName, Mail, MailNickname, AccountEnabled -ErrorAction SilentlyContinue)
        if ($matched.Count -eq 1) {
            return $matched[0]
        }
    }

    return $null
}

function Invoke-CloudEntraGroupAssignment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$Logins
    )

    $results = New-Object System.Collections.Generic.List[object]
    Connect-EntraIDDirectory
    $targetCloudGroup = Resolve-CloudEntraGroup -GroupName $GroupName

    # Pre-fetch existing Cloud group member ObjectIds for idempotency check
    $existingMemberIds = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    if (-not ($targetCloudGroup.PSObject.Properties['IsSimulated'] -and $targetCloudGroup.IsSimulated)) {
        try {
            $currentCloudMembers = @(Get-MgGroupMember -GroupId $targetCloudGroup.Id -All -ErrorAction Stop)
            foreach ($cm in $currentCloudMembers) {
                if ($cm.Id) { [void]$existingMemberIds.Add($cm.Id) }
            }
            Write-ScriptLog -Level INFO -Message "Cloud Group '$($targetCloudGroup.DisplayName)' currently has $($currentCloudMembers.Count) direct member(s)."
        } catch {
            Write-ScriptLog -Level WARN -Message "Could not pre-fetch existing Cloud group members for '$($targetCloudGroup.DisplayName)': $($_.Exception.Message)"
        }
    }

    $total = $Logins.Count
    $index = 0

    foreach ($Login in $Logins) {
        $index++
        $percent = [int](($index / $total) * 100)
        Write-Progress -Id 2 -Activity "Cloud Entra ID: Adding Users to Group '$($targetCloudGroup.DisplayName)'" `
            -Status "[$index/$total] Processing user: $Login ($percent%)" -PercentComplete $percent

        $status      = "Pending"
        $details     = ""
        $resolvedAcc = $Login
        $resolvedUpn = ""

        try {
            $cloudUser = Resolve-CloudEntraUser -Login $Login

            if ($null -eq $cloudUser) {
                $status  = "UserNotFound"
                $hint    = if ($Login -notmatch '@' -and [string]::IsNullOrWhiteSpace($UpnSuffix)) { " (Tip: provide -UpnSuffix 'yourdomain.com' when using short logins in Cloud mode)" } else { "" }
                $details = "User '$Login' was not found in Microsoft Entra ID.$hint"
                Write-ScriptLog -Level ERROR -Message "[Cloud Entra ID] $details"
            } else {
                $resolvedAcc = $cloudUser.Id
                $resolvedUpn = [string]$cloudUser.UserPrincipalName

                if ($existingMemberIds.Contains($cloudUser.Id)) {
                    $status  = "AlreadyMember"
                    $details = "User '$resolvedUpn' (ObjectId: $($cloudUser.Id)) is already a member of Cloud group '$($targetCloudGroup.DisplayName)'."
                    Write-ScriptLog -Level WARN -Message "[Cloud Entra ID] $details"
                } elseif ($DryRun -or -not $PSCmdlet.ShouldProcess("User '$resolvedUpn' -> Cloud Group '$($targetCloudGroup.DisplayName)'", "New-MgGroupMemberByRef")) {
                    $status  = "Simulated"
                    $details = "[DRY-RUN] Would add user '$resolvedUpn' to Cloud Entra ID group '$($targetCloudGroup.DisplayName)'."
                    Write-ScriptLog -Level INFO -Message "[Cloud Entra ID] $details"
                } else {
                    $odataRef = @{
                        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($cloudUser.Id)"
                    }
                    New-MgGroupMemberByRef -GroupId $targetCloudGroup.Id -BodyParameter $odataRef -ErrorAction Stop
                    [void]$existingMemberIds.Add($cloudUser.Id)

                    # Core confirmation output requested by specification
                    Write-Host "Dodano użytkownika: $Login do grupy $($targetCloudGroup.DisplayName)" -ForegroundColor Green
                    Write-ScriptLog -Level SUCCESS -Message "[Cloud Entra ID] Added user: $Login (UPN: $resolvedUpn, ObjectId: $($cloudUser.Id)) to group '$($targetCloudGroup.DisplayName)'." -NoConsole

                    $status  = "Added"
                    $details = "Successfully added '$resolvedUpn' to Cloud Entra ID group '$($targetCloudGroup.DisplayName)'."
                }
            }
        } catch {
            $status  = "Failed"
            $details = $_.Exception.Message
            Write-ScriptLog -Level ERROR -Message "[Cloud Entra ID] Failed to add user '$Login' to group '$($targetCloudGroup.DisplayName)': $details"
        }

        $results.Add([PSCustomObject]@{
            Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Environment       = "CloudEntraID"
            Group             = $targetCloudGroup.DisplayName
            InputLogin        = $Login
            ResolvedAccount   = $resolvedAcc
            UserPrincipalName = $resolvedUpn
            Status            = $status
            Details           = $details
        })
    }

    Write-Progress -Id 2 -Activity "Cloud Entra ID: Adding Users to Group '$($targetCloudGroup.DisplayName)'" -Completed
    return $results
}

# ==============================================================================
# MAIN EXECUTION ORCHESTRATOR
# ==============================================================================
$allResults = New-Object System.Collections.Generic.List[object]
$startTime  = Get-Date

try {
    if ($script:NormalizedMode -eq 'Local' -or $script:NormalizedMode -eq 'Both') {
        $localResults = Invoke-LocalADGroupAssignment -GroupName $Group -Logins $uniqueLogins
        foreach ($r in $localResults) { $allResults.Add($r) }
    }

    if ($script:NormalizedMode -eq 'Cloud' -or $script:NormalizedMode -eq 'Both') {
        $cloudResults = Invoke-CloudEntraGroupAssignment -GroupName $Group -Logins $uniqueLogins
        foreach ($r in $cloudResults) { $allResults.Add($r) }
    }
} catch {
    Write-ScriptLog -Level ERROR -Message "Fatal execution error: $($_.Exception.Message)"
    exit 1
}

$duration = (Get-Date) - $startTime
$addedCount     = @($allResults | Where-Object { $_.Status -eq 'Added' }).Count
$alreadyCount   = @($allResults | Where-Object { $_.Status -eq 'AlreadyMember' }).Count
$simulatedCount = @($allResults | Where-Object { $_.Status -eq 'Simulated' }).Count
$notFoundCount  = @($allResults | Where-Object { $_.Status -eq 'UserNotFound' }).Count
$failedCount    = @($allResults | Where-Object { $_.Status -eq 'Failed' }).Count

Write-Host ""
Write-ScriptLog -Level STEP -Message "================================================================================"
Write-ScriptLog -Level INFO -Message "EXECUTION SUMMARY ($script:ScriptName v$script:ScriptVersion)"
Write-ScriptLog -Level STEP -Message "================================================================================"
Write-ScriptLog -Level INFO -Message "  Target Group        : $Group"
Write-ScriptLog -Level INFO -Message "  Execution Mode      : $script:NormalizedMode"
Write-ScriptLog -Level INFO -Message "  Total Processed     : $($allResults.Count)"
Write-ScriptLog -Level SUCCESS -Message "  Added Successfully  : $addedCount"
Write-ScriptLog -Level WARN -Message "  Already a Member    : $alreadyCount"
if ($simulatedCount -gt 0) {
    Write-ScriptLog -Level INFO -Message "  Simulated (Dry-Run) : $simulatedCount"
}
if ($notFoundCount -gt 0) {
    Write-ScriptLog -Level ERROR -Message "  Users Not Found     : $notFoundCount"
}
if ($failedCount -gt 0) {
    Write-ScriptLog -Level ERROR -Message "  Failed Operations   : $failedCount"
}
Write-ScriptLog -Level INFO -Message "  Elapsed Time        : $($duration.ToString('hh\:mm\:ss\.fff'))"
if ($script:ActiveLogFile) {
    Write-ScriptLog -Level INFO -Message "  Log File Saved To   : $script:ActiveLogFile"
}
Write-ScriptLog -Level STEP -Message "================================================================================"

if (-not [string]::IsNullOrWhiteSpace($ExportReportPath)) {
    try {
        Test-SafeFilePath -InputPath $ExportReportPath -ParameterName "ExportReportPath"
        $reportDir = Split-Path -Path $ExportReportPath -Parent
        if (-not [string]::IsNullOrWhiteSpace($reportDir) -and -not (Test-Path -LiteralPath $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
        }
        $allResults | Export-Csv -LiteralPath $ExportReportPath -NoTypeInformation -Encoding UTF8 -Force
        Write-ScriptLog -Level SUCCESS -Message "Exported execution report to CSV: $ExportReportPath"
    } catch {
        Write-ScriptLog -Level ERROR -Message "Failed to export CSV report to '$ExportReportPath': $($_.Exception.Message)"
    }
}

if ($PassThru) {
    Write-Output $allResults
}
