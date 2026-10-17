<#
================================================================================
  Script Name : Disable-StaleComputers.ps1
  Author      : Roman Pindela
  Contact     : roman.pindela@gmail.com
  Version     : 1.2.0
  Release Date: 2026-10-17
  License     : MIT
  Repository  : https://github.com/romanpindela

  DESCRIPTION:
    Enterprise-grade PowerShell automation script for bulk disabling or removing
    stale/inactive computer accounts (workstations and devices) that have not
    reported their presence in the domain or cloud tenant for an extended period
    (default: 180 days).

    Core Local AD logic implemented:
      # Find computers that have not authenticated / updated password for 180 days
      $StareDni = (Get-Date).AddDays(-180)
      Get-ADComputer -Filter {PasswordLastSet -lt $StareDni} -Properties PasswordLastSet |
      ForEach-Object {
          # Disable-ADAccount (or Set-ADComputer / Remove-ADComputer)
          Disable-ADAccount -Identity $_.DistinguishedName
          Write-Host "Wyłączono nieaktywny komputer: $($_.Name)" -ForegroundColor Yellow
      }

    Supports Dual Directory Modes (-Mode / -Provider):
    1. Local Active Directory Mode (-Mode Local / AD / LocalAD / OnPremises):
       Queries On-Premises Windows Server Active Directory Domain Services (AD DS)
       using Get-ADComputer (PasswordLastSet -lt $StareDni and/or LastLogonDate)
       and disables accounts via Disable-ADAccount (or Set-ADComputer) or deletes
       them via Remove-ADComputer, with optional quarantine OU move (-TargetOU).
    2. Cloud Active Directory Mode (-Mode Cloud / EntraID / CloudAD / AzureAD):
       Queries Microsoft Entra ID (Azure AD) devices via Microsoft Graph PowerShell
       SDK (Get-MgDevice, filtering ApproximateLastSignInDateTime -lt $StareDni)
       and disables devices via Update-MgDevice (-AccountEnabled:$false) or removes
       them via Remove-MgDevice. Supports both interactive sign-in and unattended
       App-Only authentication using Client Secret or X.509 Certificate.
    3. Hybrid Mode (-Mode Both):
       Cleans up stale computers across both Local AD DS and Cloud Entra ID in one run.

    Default Execution Log Path:
      C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-<ComputerName>-<UserName>.logs
================================================================================
.SYNOPSIS
    Bulk disables or removes stale computer accounts (default: >180 days inactive)
    in Local Active Directory (AD DS) and/or Cloud Microsoft Entra ID (Azure AD).

.DESCRIPTION
    When replacing workstations in a local network or managing cloud-joined endpoints,
    stale computer accounts accumulate in Active Directory and Microsoft Entra ID.
    Disable-StaleComputers.ps1 identifies computers that have not rotated their
    machine account password (PasswordLastSet) or signed in (LastLogonDate /
    ApproximateLastSignInDateTime) for more than a configurable number of days
    (default: 180 days) and safely disables them (default) or removes them.

    Key Features:
    - Zero-Parameter Help (-Help / -h): Displays full usage instructions, examples,
      Entra ID non-interactive setup guide, version, and author details when run
      without parameters.
    - Dual Directory Support (-Mode Local | Cloud | Both): Supports On-Premises
      Active Directory (Get-ADComputer / Disable-ADAccount / Remove-ADComputer) and
      Cloud Microsoft Entra ID (Get-MgDevice / Update-MgDevice / Remove-MgDevice).
    - Built-in Safety Guardrails: Automatically protects Domain Controllers
      (PrimaryGroupID 516) from accidental disabling/deletion, excludes Server OS
      accounts by default (unless -IncludeServers is specified), and supports custom
      exclusion lists (-ExcludeComputers).
    - Language-Independent UAC Auto-Elevation: Uses well-known Windows SID
      S-1-5-32-544 (BuiltInAdministratorsSid) for full compatibility across Polish
      ("Administratorzy") and English ("Administrators") Windows systems.
    - Real-Time Progress Bar (Write-Progress) & CSV Audit Report Export.
    - Detailed Audit Logging: Writes timestamped UTF-8 execution logs to
      C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-<ComputerName>-<UserName>.logs.

.PARAMETER Run
    Switch parameter. Executes the stale computers cleanup with default settings
    (180 days threshold, Disable action, Local AD mode).
    Aliases: -Execute, -Cleanup

.PARAMETER StaleDays
    Number of days of inactivity (since PasswordLastSet / LastLogonDate /
    ApproximateLastSignInDateTime) required to classify a computer as stale.
    Calculates $StareDni = (Get-Date).AddDays(-$StaleDays). Default: 180.
    Aliases: -InactiveDays, -Days, -ThresholdDays

.PARAMETER Mode
    Target directory environment mode:
      - 'Local'   (or 'AD', 'LocalAD', 'OnPremises') : Local Active Directory (AD DS). Default.
      - 'Cloud'   (or 'EntraID', 'CloudAD', 'AzureAD'): Cloud Microsoft Entra ID (Graph SDK).
      - 'Both'                                        : Both Local AD and Cloud Entra ID.
    Aliases: -Provider, -Environment, -Target, -Directory

.PARAMETER Action
    Operation to perform on discovered stale computer accounts:
      - 'Disable'   : Safely disables the computer account (Default).
                      Uses Disable-ADAccount (or Set-ADComputer) in Local AD and
                      Update-MgDevice -AccountEnabled:$false in Cloud Entra ID.
      - 'Remove'    : Permanently deletes the computer account from the directory
                      (Aliases: 'Delete'). Uses Remove-ADComputer / Remove-MgDevice.
      - 'AuditOnly' : Read-only discovery mode; logs and exports stale computers
                      without modifying or disabling any accounts (Aliases: 'ReportOnly').

.PARAMETER FilterProperty
    Timestamp property used in Local AD to evaluate computer staleness:
      - 'PasswordLastSet' : Evaluates PasswordLastSet -lt $StareDni (Default).
      - 'LastLogonDate'   : Evaluates LastLogonDate -lt $StareDni.
      - 'Both'            : Requires both PasswordLastSet and LastLogonDate < $StareDni.

.PARAMETER UseSetADComputer
    Switch parameter. When -Action is 'Disable' in Local AD mode, uses
    Set-ADComputer -Identity $_.DistinguishedName -Enabled $false instead of
    Disable-ADAccount -Identity $_.DistinguishedName.

.PARAMETER SearchBase
    Optional Distinguished Name (DN) of an Organizational Unit (OU) to scope the
    Local Active Directory computer search (e.g., "OU=Workstations,DC=firma,DC=local").
    Aliases: -OU, -OrganizationalUnit

.PARAMETER TargetOU
    Optional Distinguished Name (DN) of a quarantine/disabled computers OU
    (e.g., "OU=Disabled_Computers,DC=firma,DC=local"). When specified in Local AD
    mode with -Action Disable, disabled computers are moved to this OU via Move-ADObject.
    Aliases: -MoveToOU, -QuarantineOU

.PARAMETER StampDescription
    Switch parameter. Appends an audit note (e.g., "[Disabled by Disable-StaleComputers
    on yyyy-MM-dd]") to the computer's Description attribute in Local AD when disabling.

.PARAMETER DomainController
    Optional specific Active Directory Domain Controller FQDN or IP address to query.
    Aliases: -Server, -DC

.PARAMETER Credential
    Optional PSCredential object for Local Active Directory authentication.

.PARAMETER IncludeServers
    Switch parameter. Includes Windows Server computer accounts in the cleanup.
    By default, computers with 'Server' in OperatingSystem are excluded as a safety
    measure so only workstations/client devices are targeted. Domain Controllers
    are always excluded.

.PARAMETER IncludeAlreadyDisabled
    Switch parameter. Includes computer accounts that are already disabled.
    By default, when -Action is 'Disable', already-disabled accounts are skipped;
    when -Action is 'Remove' or 'AuditOnly', both enabled and disabled stale
    computers can be processed.

.PARAMETER ExcludeComputers
    Optional list of computer names (SamAccountName, Name, or wildcard pattern such
    as "SRV-*", "KIOSK-*") to exclude from disabling or removal.
    Aliases: -Exclude

.PARAMETER OutputPath
    Optional custom file path for the exported UTF-8 CSV report.
    If omitted, automatically exports a CSV summary to:
    C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-Report.csv
    Aliases: -CsvPath, -ExportCsv, -ExportReportPath

.PARAMETER Delimiter
    CSV field delimiter character (',' or ';' or Tab). Default: ','.

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

.PARAMETER DryRun
    Switch parameter. Runs in simulation mode without modifying Active Directory or
    Entra ID (can also run with simulated sample workstation data when testing
    outside a live domain environment).
    Aliases: -Simulate, -Preview

.PARAMETER Force
    Switch parameter. Bypasses interactive confirmation prompts (Y/N / T/N) for
    unattended execution.

.PARAMETER SkipAdminCheck
    Switch parameter. Skips the automatic UAC Administrator privilege check.

.PARAMETER PassThru
    Switch parameter. Outputs the processed stale computer result objects to the
    PowerShell pipeline.

.PARAMETER LogPath
    Custom file path for the execution log file.
    Default: C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-<ComputerName>-<UserName>.logs
    Aliases: -l, -Log

.PARAMETER NoLog
    Switch parameter. Disables writing execution logs to disk.

.PARAMETER Help
    Displays the interactive help screen, usage examples, Entra ID setup guide,
    author information, and script version.
    Aliases: -h

.EXAMPLE
    .\Disable-StaleComputers.ps1
    Displays the help screen, usage examples, version, and author details.

.EXAMPLE
    .\Disable-StaleComputers.ps1 -Run
    Finds all Local Active Directory computers whose PasswordLastSet is older than
    180 days, disables each account using Disable-ADAccount, prints:
    "Wyłączono nieaktywny komputer: <Name>" in Yellow, and writes logs to C:\Logs\.

.EXAMPLE
    .\Disable-StaleComputers.ps1 -StaleDays 180 -SearchBase "OU=StacjeRobocze,DC=firma,DC=local" -TargetOU "OU=WylaczoneKomputery,DC=firma,DC=local" -StampDescription -Force
    Disables workstations in "OU=StacjeRobocze" that have not updated their machine
    password in 180+ days, stamps their AD Description with the disable date, and
    moves them to the quarantine OU "OU=WylaczoneKomputery".

.EXAMPLE
    .\Disable-StaleComputers.ps1 -StaleDays 365 -Action Remove -IncludeAlreadyDisabled -Force
    Permanently removes computer accounts from Local AD that have been inactive for
    more than 365 days.

.EXAMPLE
    .\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable
    Connects interactively to Microsoft Entra ID (Cloud AD) via Microsoft Graph SDK
    and disables cloud devices that have not signed in for more than 180 days.

.EXAMPLE
    .\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -ClientSecret "YourClientSecretValue" -Force
    Disables stale Microsoft Entra ID devices non-interactively (unattended mode)
    using an Entra ID App Registration and Client Secret.

.NOTES
    Author  : Roman Pindela
    Email   : roman.pindela@gmail.com
    GitHub  : https://github.com/romanpindela
    Version : 1.2.0
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Cleanup')]
param(
    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Execute', 'Cleanup')]
    [switch]$Run,

    [Parameter(ParameterSetName = 'Cleanup', Position = 0)]
    [Alias('InactiveDays', 'Days', 'ThresholdDays')]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 180,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Provider', 'Environment', 'Target', 'Directory')]
    [ValidateSet('Local', 'AD', 'LocalAD', 'OnPrem', 'OnPremises', 'Cloud', 'EntraID', 'CloudAD', 'AzureAD', 'Both')]
    [string]$Mode = 'Local',

    [Parameter(ParameterSetName = 'Cleanup')]
    [ValidateSet('Disable', 'Remove', 'Delete', 'AuditOnly', 'ReportOnly')]
    [string]$Action = 'Disable',

    [Parameter(ParameterSetName = 'Cleanup')]
    [ValidateSet('PasswordLastSet', 'LastLogonDate', 'Both')]
    [string]$FilterProperty = 'PasswordLastSet',

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$UseSetADComputer,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('OU', 'OrganizationalUnit')]
    [string]$SearchBase,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('MoveToOU', 'QuarantineOU')]
    [string]$TargetOU,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$StampDescription,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Server', 'DC')]
    [string]$DomainController,

    [Parameter(ParameterSetName = 'Cleanup')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$IncludeServers,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$IncludeAlreadyDisabled,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Exclude')]
    [string[]]$ExcludeComputers,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('CsvPath', 'ExportCsv', 'ExportReportPath')]
    [string]$OutputPath,

    [Parameter(ParameterSetName = 'Cleanup')]
    [ValidateSet(',', ';', "`t")]
    [string]$Delimiter = ',',

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Tenant', 'DirectoryId')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('AppId', 'ApplicationId')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Secret')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'Cleanup')]
    [System.Security.SecureString]$ClientSecretSecure,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Thumbprint')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('Simulate', 'Preview')]
    [switch]$DryRun,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$SkipAdminCheck,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$PassThru,

    [Parameter(ParameterSetName = 'Cleanup')]
    [Alias('l', 'Log')]
    [string]$LogPath,

    [Parameter(ParameterSetName = 'Cleanup')]
    [switch]$NoLog,

    [Parameter(ParameterSetName = 'Help', Mandatory = $true)]
    [Alias('h')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

# ==============================================================================
# GLOBAL SCRIPT METADATA & STATE
# ==============================================================================
$script:ScriptName      = "Disable-StaleComputers"
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
  SCRIPT  : Disable-StaleComputers.ps1
  VERSION : $script:ScriptVersion ($script:ScriptDate)
  AUTHOR  : $script:ScriptAuthor
  CONTACT : $script:ScriptEmail | $script:ScriptGitHub
================================================================================

DESCRIPTION:
    When replacing workstations on a local network or managing cloud devices,
    stale computer accounts often remain in Active Directory and Microsoft Entra ID.
    This script discovers computers that have not reported their presence in the
    domain or cloud tenant for an extended period (default: 180 days) and safely
    disables them (or optionally removes them).

    Core Local Active Directory Logic:
      # Find computers that have not logged on / rotated password for 180 days
      `$StareDni = (Get-Date).AddDays(-180)
      Get-ADComputer -Filter {PasswordLastSet -lt `$StareDni} -Properties PasswordLastSet |
      ForEach-Object {
          # Disable-ADAccount (or Set-ADComputer / Remove-ADComputer)
          Disable-ADAccount -Identity `$_.DistinguishedName
          Write-Host "Wyłączono nieaktywny komputer: `$(`$_.Name)" -ForegroundColor Yellow
      }

    Supports Three Operational Directory Modes (-Mode / -Provider):
      1. Local Active Directory (-Mode Local / AD / LocalAD / OnPremises):
         Uses Get-ADComputer against On-Premises Windows Server Active Directory
         and disables stale computers via Disable-ADAccount (or Set-ADComputer)
         or removes them via Remove-ADComputer.
      2. Cloud Active Directory (-Mode Cloud / EntraID / CloudAD / AzureAD):
         Uses Microsoft Graph PowerShell SDK (Get-MgDevice / Update-MgDevice /
         Remove-MgDevice) to disable or remove inactive devices in Microsoft Entra ID.
      3. Hybrid Mode (-Mode Both):
         Processes stale computer accounts in both Local AD and Cloud Entra ID.

--------------------------------------------------------------------------------
HOW TO CONFIGURE ENTRA ID FOR NON-INTERACTIVE / UNATTENDED AUTHENTICATION:
(Only via API Keys / Credentials and Entra ID Microsoft Graph SDK Permissions)
--------------------------------------------------------------------------------
To run this script in unattended / non-interactive Cloud mode against Microsoft
Entra ID (e.g., Windows Task Scheduler, Intune/Entra cleanup jobs, CI/CD) without
interactive browser prompts:

Step 1: Register an Application in Microsoft Entra ID
    1. Sign in to Microsoft Entra admin center (https://entra.microsoft.com).
    2. Navigate to: Identity > Applications > App registrations > New registration.
    3. Name: 'EntraID-StaleDevices-Cleanup'.
    4. Supported account types: 'Accounts in this organizational directory only'.
    5. Click 'Register' and copy:
       - Application (client) ID  -> pass to -ClientId
       - Directory (tenant) ID    -> pass to -TenantId

Step 2: Grant Microsoft Graph API Application Permissions (App-Only)
    1. In the App Registration, go to: Manage > API permissions > Add a permission.
    2. Select 'Microsoft Graph' > 'Application permissions' (NOT Delegated).
    3. Search for and check the following permissions required for device cleanup:
       * Device.ReadWrite.All     (Required to read, disable, or delete devices)
       * Directory.ReadWrite.All  (Required for full directory device operations)
    4. Click 'Add permissions'.
    5. Click 'Grant admin consent for <Your Tenant>' and verify green checkmarks.
       (Note: For deleting devices in Entra ID via App-Only auth, also assign the
       App Registration Service Principal to the 'Cloud Device Administrator' role
       under Identity > Roles & admins > Cloud Device Administrator).

Step 3: Configure Non-Interactive Credentials (Choose Option A or Option B)
    Option A: Client Secret (API Key / Secret)
      1. Go to: Manage > Certificates & secrets > Client secrets > New client secret.
      2. Enter a description, select expiration, and click 'Add'.
      3. Copy the secret 'Value' immediately (not the Secret ID).
      4. Run the script non-interactively:
         .\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable ``
             -TenantId "<TenantId>" -ClientId "<ClientId>" -ClientSecret "<SecretValue>" -Force

    Option B: X.509 Certificate (Recommended for Production Scheduled Tasks)
      1. Generate a self-signed certificate in PowerShell:
         `$cert = New-SelfSignedCertificate -Subject "CN=EntraStaleDevicesCleanup" ``
             -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable ``
             -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
         Export-Certificate -Cert `$cert -FilePath "C:\Logs\EntraStaleDevicesCleanup.cer"
      2. Upload 'EntraStaleDevicesCleanup.cer' in Entra Admin Center under:
         Manage > Certificates & secrets > Certificates > Upload certificate.
      3. Run the script non-interactively:
         .\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable ``
             -TenantId "<TenantId>" -ClientId "<ClientId>" -CertificateThumbprint `$cert.Thumbprint -Force

--------------------------------------------------------------------------------
USAGE EXAMPLES:
--------------------------------------------------------------------------------
  # 1. Disable Local AD computers inactive for >180 days (default settings):
  .\Disable-StaleComputers.ps1 -Run

  # 2. Disable Local AD computers inactive >180 days within a specific OU and move to Quarantine OU:
  .\Disable-StaleComputers.ps1 -StaleDays 180 ``
      -SearchBase "OU=Workstations,DC=firma,DC=local" ``
      -TargetOU "OU=Disabled_Computers,DC=firma,DC=local" ``
      -StampDescription -Force

  # 3. Audit-only mode (discover and export CSV report without disabling anything):
  .\Disable-StaleComputers.ps1 -StaleDays 180 -Action AuditOnly

  # 4. Permanently remove Local AD computers inactive for >365 days:
  .\Disable-StaleComputers.ps1 -StaleDays 365 -Action Remove -IncludeAlreadyDisabled -Force

  # 5. Disable Cloud Microsoft Entra ID devices inactive >180 days (Interactive Sign-In):
  .\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable

  # 6. Disable Cloud Microsoft Entra ID devices non-interactively via Client Secret:
  .\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -ClientSecret "YourClientSecretValue" -Force

  # 7. Run in Dry-Run simulation mode (previews execution with sample data if outside AD):
  .\Disable-StaleComputers.ps1 -Run -DryRun

--------------------------------------------------------------------------------
PARAMETERS:
--------------------------------------------------------------------------------
  -Run, -Execute, -Cleanup      Run with default settings (180 days, Disable, Local AD).
  -StaleDays, -InactiveDays     Inactivity threshold in days (Default: 180).
  -Mode, -Provider              Target directory: 'Local'/'AD' (default), 'Cloud'/'EntraID', 'Both'.
  -Action                       Operation: 'Disable' (default), 'Remove'/'Delete', 'AuditOnly'.
  -FilterProperty               Local AD property: 'PasswordLastSet' (default), 'LastLogonDate', 'Both'.
  -UseSetADComputer             Use Set-ADComputer -Enabled `$false instead of Disable-ADAccount.
  -SearchBase, -OU              Organizational Unit DN to scope Local AD computer search.
  -TargetOU, -MoveToOU          Quarantine OU DN to move disabled Local AD computers into.
  -StampDescription             Append disable timestamp note to computer Description in Local AD.
  -DomainController, -Server    Specific Active Directory Domain Controller FQDN/IP.
  -Credential                   PSCredential for Local Active Directory authentication.
  -IncludeServers               Include Windows Server OS computers (excluded by default).
  -IncludeAlreadyDisabled       Include computers that are already disabled.
  -ExcludeComputers, -Exclude   Computer names or wildcard patterns to exclude (e.g. "SRV-*").
  -OutputPath, -CsvPath         Custom CSV report output path (Default: C:\Logs\...).
  -Delimiter                    CSV delimiter character: ',' (default), ';', or Tab.
  -TenantId                     Entra ID Tenant ID (for Cloud AD mode).
  -ClientId                     Entra ID App Client ID (for non-interactive Cloud AD auth).
  -ClientSecret                 Entra ID Client Secret (for non-interactive Cloud AD auth).
  -CertificateThumbprint        X.509 Certificate thumbprint (for non-interactive Cloud AD auth).
  -DryRun, -Simulate            Run simulation mode without modifying AD or Entra ID.
  -Force                        Bypass interactive confirmation prompts (Y/N / T/N).
  -SkipAdminCheck               Skip automatic UAC Administrator privilege elevation.
  -PassThru                     Return processed computer objects to the PowerShell pipeline.
  -LogPath, -Log                Custom execution log path.
  -NoLog                        Disable file logging.
  -Help, -h                     Display this help screen and exit.

LOGGING:
  Detailed execution logs are automatically written by default to:
  C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-<ComputerName>-<UserName>.logs

SECURITY & UNBLOCKING:
  After downloading this script from GitHub, unblock the file before execution:
  Unblock-File -Path .\Disable-StaleComputers.ps1
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
# NORMALIZE MODE ('Local', 'Cloud', 'Both') & ACTION ('Disable', 'Remove', 'AuditOnly')
# ==============================================================================
$normalizedMode = switch ($Mode.ToUpperInvariant()) {
    { $_ -in @('LOCAL', 'AD', 'LOCALAD', 'ONPREM', 'ONPREMISES') } { 'Local' }
    { $_ -in @('CLOUD', 'ENTRAID', 'CLOUDAD', 'AZUREAD') }         { 'Cloud' }
    'BOTH'                                                         { 'Both' }
    default                                                        { 'Local' }
}

$normalizedAction = switch ($Action.ToUpperInvariant()) {
    'DISABLE'    { 'Disable' }
    'REMOVE'     { 'Remove' }
    'DELETE'     { 'Remove' }
    'AUDITONLY'  { 'AuditOnly' }
    'REPORTONLY' { 'AuditOnly' }
    default      { 'Disable' }
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

if (-not $SkipAdminCheck -and -not $DryRun -and ($normalizedMode -eq 'Local' -or $normalizedMode -eq 'Both')) {
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
  Mode          : $normalizedMode ($Mode)
  Action        : $normalizedAction
  Stale Days    : $StaleDays
  Filter Prop   : $FilterProperty
  DryRun        : $DryRun
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
Write-ScriptLog -Level INFO -Message "Starting $script:ScriptName v$script:ScriptVersion (Mode: $normalizedMode, Action: $normalizedAction, StaleDays: $StaleDays)."
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

function Test-IsComputerExcluded {
    param(
        [string]$ComputerName,
        [string[]]$ExclusionPatterns
    )
    if ([string]::IsNullOrWhiteSpace($ComputerName) -or $null -eq $ExclusionPatterns -or $ExclusionPatterns.Count -eq 0) {
        return $false
    }
    $cleanName = $ComputerName.TrimEnd('$')
    foreach ($pattern in $ExclusionPatterns) {
        if ([string]::IsNullOrWhiteSpace($pattern)) { continue }
        $cleanPattern = $pattern.Trim().TrimEnd('$')
        if ($cleanName -like $cleanPattern -or $ComputerName -like $pattern.Trim()) {
            return $true
        }
    }
    return $false
}

function Request-UserConfirmation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptMessage
    )
    if ($Force -or $DryRun -or $normalizedAction -eq 'AuditOnly') {
        return $true
    }
    Write-Host ""
    $response = Read-Host "$PromptMessage [Y/N / T/N]"
    if ($response -match '^(?i)(y|yes|t|tak)$') {
        return $true
    }
    return $false
}

Assert-SafeInputString -Value $DomainController -ParameterName "DomainController"
Assert-SafeInputString -Value $TenantId -ParameterName "TenantId"
Assert-SafeInputString -Value $ClientId -ParameterName "ClientId"
Assert-SafeInputString -Value $CertificateThumbprint -ParameterName "CertificateThumbprint"

if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    Assert-SafeInputString -Value $SearchBase -ParameterName "SearchBase"
    if ($SearchBase -notmatch '^(?i)(OU|CN|DC)=') {
        Write-ScriptLog -Level ERROR -Message "Invalid Distinguished Name in -SearchBase: '$SearchBase'. Expected format like 'OU=Computers,DC=domain,DC=local'."
        exit 1
    }
}

if (-not [string]::IsNullOrWhiteSpace($TargetOU)) {
    Assert-SafeInputString -Value $TargetOU -ParameterName "TargetOU"
    if ($TargetOU -notmatch '^(?i)(OU|CN|DC)=') {
        Write-ScriptLog -Level ERROR -Message "Invalid Distinguished Name in -TargetOU: '$TargetOU'. Expected format like 'OU=Disabled_Computers,DC=domain,DC=local'."
        exit 1
    }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Test-SafeFilePath -InputPath $OutputPath -ParameterName "OutputPath"
}

if ($null -ne $ExcludeComputers) {
    foreach ($ex in $ExcludeComputers) {
        Assert-SafeInputString -Value $ex -ParameterName "ExcludeComputers"
    }
}

# Calculate the staleness cutoff date ($StareDni)
# Znajdź komputery, które nie logowały się od $StaleDays (domyślnie 180) dni
$StareDni = (Get-Date).AddDays(-$StaleDays)
Write-ScriptLog -Level INFO -Message "Calculated staleness cutoff date (`$StareDni): $($StareDni.ToString('yyyy-MM-dd HH:mm:ss')) ($StaleDays days ago)."

$processedRecords = New-Object System.Collections.Generic.List[PSObject]
$stats = @{
    TotalDiscovered = 0
    Disabled        = 0
    Removed         = 0
    Audited         = 0
    Skipped         = 0
    Failed          = 0
}

# ==============================================================================
# MODE 1: LOCAL ON-PREMISES ACTIVE DIRECTORY (AD DS)
# ==============================================================================
if ($normalizedMode -eq 'Local' -or $normalizedMode -eq 'Both') {
    Write-ScriptLog -Level STEP -Message "Starting Local Active Directory (AD DS) stale computers discovery..."

    $adModuleAvailable = [bool](Get-Module -Name ActiveDirectory -ListAvailable)

    if (-not $adModuleAvailable -and $DryRun) {
        $adServerName = if (-not [string]::IsNullOrWhiteSpace($DomainController)) { $DomainController } elseif ($env:LOGONSERVER) { $env:LOGONSERVER.TrimStart('\') } else { "DC01.firma.local" }
        Write-ScriptLog -Level WARN -Message "[DryRun] 'ActiveDirectory' module not installed locally. Simulating Local AD computer discovery against '$adServerName'..."

        $simulatedAdComputers = @(
            [PSCustomObject]@{
                Name              = "PC-KSIEGOWOSC01"
                SamAccountName    = "PC-KSIEGOWOSC01$"
                DNSHostName       = "PC-KSIEGOWOSC01.firma.local"
                DistinguishedName = "CN=PC-KSIEGOWOSC01,OU=Workstations,DC=firma,DC=local"
                Enabled           = $true
                PasswordLastSet   = (Get-Date).AddDays(-($StaleDays + 35))
                LastLogonDate     = (Get-Date).AddDays(-($StaleDays + 32))
                OperatingSystem   = "Windows 10 Pro"
                PrimaryGroupID    = 515
                Description       = "Stacja robocza Dzial Ksiegowosci"
                WhenCreated       = (Get-Date).AddDays(-720)
            },
            [PSCustomObject]@{
                Name              = "PC-MAGAZYN04"
                SamAccountName    = "PC-MAGAZYN04$"
                DNSHostName       = "PC-MAGAZYN04.firma.local"
                DistinguishedName = "CN=PC-MAGAZYN04,OU=Workstations,DC=firma,DC=local"
                Enabled           = $true
                PasswordLastSet   = (Get-Date).AddDays(-($StaleDays + 90))
                LastLogonDate     = (Get-Date).AddDays(-($StaleDays + 88))
                OperatingSystem   = "Windows 11 Enterprise"
                PrimaryGroupID    = 515
                Description       = "Terminal magazynowy #4"
                WhenCreated       = (Get-Date).AddDays(-540)
            }
        )

        $now = Get-Date
        $totalSim = $simulatedAdComputers.Count
        $idx = 0

        foreach ($comp in $simulatedAdComputers) {
            $idx++
            $stats.TotalDiscovered++
            $pct = [math]::Min(100, [int](($idx / [math]::Max(1, $totalSim)) * 100))
            Write-Progress -Activity "Local AD Stale Computers Cleanup [DryRun]" -Status "Processing $($comp.Name) ($idx/$totalSim)" -PercentComplete $pct

            if (Test-IsComputerExcluded -ComputerName $comp.Name -ExclusionPatterns $ExcludeComputers) {
                Write-ScriptLog -Level WARN -Message "Skipping excluded computer '$($comp.Name)'."
                $stats.Skipped++
                continue
            }

            $daysStale = [math]::Round(($now - [datetime]$comp.PasswordLastSet).TotalDays, 0)
            $actionStatus = "DryRun-$normalizedAction"

            if ($normalizedAction -eq 'Disable') {
                Write-Host "[DryRun] Wyłączono nieaktywny komputer: $($comp.Name)" -ForegroundColor Yellow
                Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would disable stale AD computer '$($comp.Name)' (DN: $($comp.DistinguishedName), PasswordLastSet: $($comp.PasswordLastSet.ToString('yyyy-MM-dd')))." -NoConsole
                $stats.Disabled++
            } elseif ($normalizedAction -eq 'Remove') {
                Write-Host "[DryRun] Usunięto nieaktywny komputer: $($comp.Name)" -ForegroundColor Yellow
                Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would remove stale AD computer '$($comp.Name)' (DN: $($comp.DistinguishedName))." -NoConsole
                $stats.Removed++
            } else {
                Write-ScriptLog -Level INFO -Message "[DryRun] Audited stale AD computer '$($comp.Name)' ($daysStale days since PasswordLastSet)."
                $stats.Audited++
            }

            $processedRecords.Add([PSCustomObject]@{
                Name              = $comp.Name
                SamAccountName    = $comp.SamAccountName
                DNSHostName       = $comp.DNSHostName
                OperatingSystem   = $comp.OperatingSystem
                EnabledBefore     = $comp.Enabled
                PasswordLastSet   = $comp.PasswordLastSet
                LastLogonDate     = $comp.LastLogonDate
                DaysStale         = $daysStale
                ActionTaken       = $actionStatus
                DistinguishedName = $comp.DistinguishedName
                DirectorySource   = "LocalAD"
                ServerOrTenant    = $adServerName
                Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            })
        }
        Write-Progress -Activity "Local AD Stale Computers Cleanup [DryRun]" -Completed
    } else {
        if (-not $adModuleAvailable) {
            Write-ScriptLog -Level ERROR -Message "The 'ActiveDirectory' PowerShell module (RSAT-AD-PowerShell) is not installed on this machine."
            Write-ScriptLog -Level INFO  -Message "Install on Windows 10/11: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
            Write-ScriptLog -Level INFO  -Message "Install on Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell"
            Write-ScriptLog -Level INFO  -Message "Tip: Use '-Mode Cloud' for Microsoft Entra ID device cleanup or '-DryRun' for simulation."
            exit 1
        }

        Import-Module ActiveDirectory -ErrorAction Stop
        Write-ScriptLog -Level INFO -Message "Loaded 'ActiveDirectory' module successfully."

        $adCommonParams = @{
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
            $adCommonParams['Server'] = $DomainController
        }
        if ($null -ne $Credential) {
            $adCommonParams['Credential'] = $Credential
        }

        $adServerName = $DomainController
        if ([string]::IsNullOrWhiteSpace($adServerName)) {
            try {
                $dcObj = Get-ADDomainController -Discover @adCommonParams
                $adServerName = if ($dcObj.HostName) { [string]$dcObj.HostName } else { [string]$dcObj.Name }
            } catch {
                $adServerName = if ($env:LOGONSERVER) { $env:LOGONSERVER.TrimStart('\') } else { $env:COMPUTERNAME }
            }
        }
        Write-ScriptLog -Level INFO -Message "Target Active Directory Domain Controller: $adServerName"

        $adQueryParams = @{
            Properties  = @(
                'PasswordLastSet', 'LastLogonDate', 'OperatingSystem',
                'Description', 'Enabled', 'DistinguishedName',
                'DNSHostName', 'PrimaryGroupID', 'WhenCreated'
            )
            ErrorAction = 'Stop'
        }
        if (-not [string]::IsNullOrWhiteSpace($DomainController)) {
            $adQueryParams['Server'] = $DomainController
        }
        if ($null -ne $Credential) {
            $adQueryParams['Credential'] = $Credential
        }
        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $adQueryParams['SearchBase'] = $SearchBase
            Write-ScriptLog -Level INFO -Message "Scoping AD computer search to Organizational Unit: $SearchBase"
        }

        try {
            Write-ScriptLog -Level INFO -Message "Querying Active Directory computers with $FilterProperty < $($StareDni.ToString('yyyy-MM-dd'))..."

            # Execute Get-ADComputer using the requested filter
            $rawComputers = switch ($FilterProperty) {
                'PasswordLastSet' {
                    @(Get-ADComputer -Filter { PasswordLastSet -lt $StareDni } @adQueryParams)
                }
                'LastLogonDate' {
                    @(Get-ADComputer -Filter { LastLogonDate -lt $StareDni } @adQueryParams)
                }
                'Both' {
                    @(Get-ADComputer -Filter { PasswordLastSet -lt $StareDni -and LastLogonDate -lt $StareDni } @adQueryParams)
                }
            }

            Write-ScriptLog -Level INFO -Message "Initial AD query returned $($rawComputers.Count) computer object(s). Applying safety filters..."

            $candidateComputers = New-Object System.Collections.Generic.List[PSObject]
            foreach ($comp in $rawComputers) {
                # Safety Check 1: Never disable or delete Domain Controllers (PrimaryGroupID 516 or OU=Domain Controllers)
                if ($comp.PrimaryGroupID -eq 516 -or $comp.DistinguishedName -match '(?i)OU=Domain Controllers') {
                    Write-ScriptLog -Level WARN -Message "Skipping Domain Controller '$($comp.Name)' (protected system account)."
                    $stats.Skipped++
                    continue
                }

                # Safety Check 2: Skip Server OS accounts unless -IncludeServers is specified
                if (-not $IncludeServers -and -not [string]::IsNullOrWhiteSpace($comp.OperatingSystem) -and $comp.OperatingSystem -match '(?i)Server') {
                    Write-ScriptLog -Level WARN -Message "Skipping Windows Server computer '$($comp.Name)' ($($comp.OperatingSystem)). Use -IncludeServers to include servers."
                    $stats.Skipped++
                    continue
                }

                # Safety Check 3: Skip already disabled computers if -Action is Disable and -IncludeAlreadyDisabled is not set
                if (-not $IncludeAlreadyDisabled -and $normalizedAction -eq 'Disable' -and $comp.Enabled -eq $false) {
                    Write-ScriptLog -Level DEBUG -Message "Skipping already disabled computer '$($comp.Name)'." -NoConsole
                    $stats.Skipped++
                    continue
                }

                # Safety Check 4: Check user-supplied exclusion patterns (-ExcludeComputers)
                if ((Test-IsComputerExcluded -ComputerName $comp.Name -ExclusionPatterns $ExcludeComputers) -or
                    (Test-IsComputerExcluded -ComputerName $comp.SamAccountName -ExclusionPatterns $ExcludeComputers)) {
                    Write-ScriptLog -Level WARN -Message "Skipping excluded computer '$($comp.Name)' (matched -ExcludeComputers)."
                    $stats.Skipped++
                    continue
                }

                $candidateComputers.Add($comp)
            }

            $stats.TotalDiscovered += $candidateComputers.Count
            Write-ScriptLog -Level INFO -Message "Found $($candidateComputers.Count) eligible stale Local AD computer(s) to process (Action: $normalizedAction)."

            if ($candidateComputers.Count -gt 0) {
                $confirmPrompt = "Proceed with Action '$normalizedAction' on $($candidateComputers.Count) stale Local AD computer(s) (inactive > $StaleDays days)?"
                if (-not (Request-UserConfirmation -PromptMessage $confirmPrompt)) {
                    Write-ScriptLog -Level WARN -Message "Operation cancelled by user at confirmation prompt."
                } else {
                    $now = Get-Date
                    $totalCandidates = $candidateComputers.Count
                    $currentIdx = 0

                    foreach ($comp in $candidateComputers) {
                        $currentIdx++
                        $pct = [math]::Min(100, [int](($currentIdx / [math]::Max(1, $totalCandidates)) * 100))
                        Write-Progress -Activity "Local AD Stale Computers ($normalizedAction)" -Status "Processing $($comp.Name) ($currentIdx/$totalCandidates)" -PercentComplete $pct

                        $refDate = if ($null -ne $comp.PasswordLastSet) { [datetime]$comp.PasswordLastSet } elseif ($null -ne $comp.LastLogonDate) { [datetime]$comp.LastLogonDate } else { $null }
                        $daysStale = if ($null -ne $refDate) { [math]::Round(($now - $refDate).TotalDays, 0) } else { $StaleDays }
                        $statusText = "Unchanged"

                        try {
                            if ($normalizedAction -eq 'AuditOnly') {
                                $statusText = "Audited"
                                $stats.Audited++
                                Write-ScriptLog -Level INFO -Message "Audited stale computer: $($comp.Name) (PasswordLastSet: $($comp.PasswordLastSet), LastLogonDate: $($comp.LastLogonDate), Enabled: $($comp.Enabled))."
                            } elseif ($normalizedAction -eq 'Disable') {
                                if ($DryRun -or -not $PSCmdlet.ShouldProcess($comp.DistinguishedName, "Disable-ADAccount")) {
                                    $statusText = "DryRun-Disabled"
                                    $stats.Disabled++
                                    Write-Host "[DryRun] Wyłączono nieaktywny komputer: $($comp.Name)" -ForegroundColor Yellow
                                    Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would disable computer '$($comp.Name)' ($($comp.DistinguishedName))." -NoConsole
                                } else {
                                    # Core requirement: Disable-ADAccount -Identity $_.DistinguishedName (or Set-ADComputer)
                                    if ($UseSetADComputer) {
                                        Set-ADComputer -Identity $comp.DistinguishedName -Enabled $false @adCommonParams
                                    } else {
                                        Disable-ADAccount -Identity $comp.DistinguishedName @adCommonParams
                                    }

                                    Write-Host "Wyłączono nieaktywny komputer: $($comp.Name)" -ForegroundColor Yellow
                                    Write-ScriptLog -Level SUCCESS -Message "Disabled stale computer: $($comp.Name) ($($comp.DistinguishedName), PasswordLastSet: $($comp.PasswordLastSet))." -NoConsole
                                    $statusText = "Disabled"

                                    if ($StampDescription) {
                                        $stampNote = "[Disabled by Disable-StaleComputers on $((Get-Date).ToString('yyyy-MM-dd'))]"
                                        $newDesc = if ([string]::IsNullOrWhiteSpace($comp.Description)) { $stampNote } else { "$($comp.Description) $stampNote" }
                                        Set-ADComputer -Identity $comp.DistinguishedName -Description $newDesc @adCommonParams
                                        Write-ScriptLog -Level INFO -Message "Updated Description on '$($comp.Name)'." -NoConsole
                                    }

                                    if (-not [string]::IsNullOrWhiteSpace($TargetOU)) {
                                        Move-ADObject -Identity $comp.DistinguishedName -TargetPath $TargetOU @adCommonParams
                                        $statusText = "DisabledAndMoved"
                                        Write-ScriptLog -Level INFO -Message "Moved disabled computer '$($comp.Name)' to OU '$TargetOU'."
                                    }

                                    $stats.Disabled++
                                }
                            } elseif ($normalizedAction -eq 'Remove') {
                                if ($DryRun -or -not $PSCmdlet.ShouldProcess($comp.DistinguishedName, "Remove-ADComputer")) {
                                    $statusText = "DryRun-Removed"
                                    $stats.Removed++
                                    Write-Host "[DryRun] Usunięto nieaktywny komputer: $($comp.Name)" -ForegroundColor Yellow
                                    Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would remove computer '$($comp.Name)' ($($comp.DistinguishedName))." -NoConsole
                                } else {
                                    Remove-ADComputer -Identity $comp.DistinguishedName -Confirm:$false @adCommonParams
                                    Write-Host "Usunięto nieaktywny komputer: $($comp.Name)" -ForegroundColor Red
                                    Write-ScriptLog -Level SUCCESS -Message "Removed stale computer: $($comp.Name) ($($comp.DistinguishedName))." -NoConsole
                                    $statusText = "Removed"
                                    $stats.Removed++
                                }
                            }
                        } catch {
                            $statusText = "Failed: $($_.Exception.Message)"
                            $stats.Failed++
                            Write-ScriptLog -Level ERROR -Message "Failed to $normalizedAction computer '$($comp.Name)' ($($comp.DistinguishedName)): $_"
                        }

                        $processedRecords.Add([PSCustomObject]@{
                            Name              = $comp.Name
                            SamAccountName    = $comp.SamAccountName
                            DNSHostName       = $comp.DNSHostName
                            OperatingSystem   = $comp.OperatingSystem
                            EnabledBefore     = $comp.Enabled
                            PasswordLastSet   = $comp.PasswordLastSet
                            LastLogonDate     = $comp.LastLogonDate
                            DaysStale         = $daysStale
                            ActionTaken       = $statusText
                            DistinguishedName = $comp.DistinguishedName
                            DirectorySource   = "LocalAD"
                            ServerOrTenant    = $adServerName
                            Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        })
                    }
                    Write-Progress -Activity "Local AD Stale Computers ($normalizedAction)" -Completed
                }
            }
        } catch {
            Write-ScriptLog -Level ERROR -Message "Failed to query or process Local Active Directory computers on '$adServerName': $_"
            throw
        }
    }
}

# ==============================================================================
# MODE 2: CLOUD ACTIVE DIRECTORY (MICROSOFT ENTRA ID / AZURE AD VIA GRAPH SDK)
# ==============================================================================
if ($normalizedMode -eq 'Cloud' -or $normalizedMode -eq 'Both') {
    Write-ScriptLog -Level STEP -Message "Starting Cloud Active Directory (Microsoft Entra ID) stale device discovery..."

    $requiredGraphModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Identity.DirectoryManagement')
    $missingGraphModules = @()
    foreach ($mod in $requiredGraphModules) {
        if (-not (Get-Module -Name $mod -ListAvailable)) {
            $missingGraphModules += $mod
        }
    }

    if ($missingGraphModules.Count -gt 0 -and $DryRun) {
        $cloudTenantLabel = if (-not [string]::IsNullOrWhiteSpace($TenantId)) { $TenantId } else { "EntraID-CloudTenant" }
        Write-ScriptLog -Level WARN -Message "[DryRun] Microsoft Graph SDK modules ($($missingGraphModules -join ', ')) not installed locally. Simulating Cloud Entra ID device cleanup..."

        $simulatedCloudDevices = @(
            [PSCustomObject]@{
                Id                            = "d1111111-2222-3333-4444-555555555555"
                DisplayName                   = "LAPTOP-SPRZEDAZ02"
                DeviceId                      = "c1111111-2222-3333-4444-555555555555"
                OperatingSystem               = "Windows"
                OperatingSystemVersion        = "10.0.22631.4169"
                AccountEnabled                = $true
                ApproximateLastSignInDateTime = (Get-Date).AddDays(-($StaleDays + 42))
                RegistrationDateTime          = (Get-Date).AddDays(-480)
                TrustType                     = "AzureAd"
            }
        )

        $now = Get-Date
        foreach ($dev in $simulatedCloudDevices) {
            $stats.TotalDiscovered++
            $daysStale = [math]::Round(($now - [datetime]$dev.ApproximateLastSignInDateTime).TotalDays, 0)
            $actionStatus = "DryRun-$normalizedAction"

            if ($normalizedAction -eq 'Disable') {
                Write-Host "[DryRun] Wyłączono nieaktywny komputer (Entra ID): $($dev.DisplayName)" -ForegroundColor Yellow
                Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would disable Entra ID device '$($dev.DisplayName)' (ObjectId: $($dev.Id))." -NoConsole
                $stats.Disabled++
            } elseif ($normalizedAction -eq 'Remove') {
                Write-Host "[DryRun] Usunięto nieaktywny komputer (Entra ID): $($dev.DisplayName)" -ForegroundColor Yellow
                Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would remove Entra ID device '$($dev.DisplayName)' (ObjectId: $($dev.Id))." -NoConsole
                $stats.Removed++
            } else {
                $stats.Audited++
            }

            $processedRecords.Add([PSCustomObject]@{
                Name              = $dev.DisplayName
                SamAccountName    = $dev.DeviceId
                DNSHostName       = $dev.DisplayName
                OperatingSystem   = "$($dev.OperatingSystem) $($dev.OperatingSystemVersion)".Trim()
                EnabledBefore     = $dev.AccountEnabled
                PasswordLastSet   = $dev.RegistrationDateTime
                LastLogonDate     = $dev.ApproximateLastSignInDateTime
                DaysStale         = $daysStale
                ActionTaken       = $actionStatus
                DistinguishedName = "ObjectId=$($dev.Id)"
                DirectorySource   = "EntraID"
                ServerOrTenant    = $cloudTenantLabel
                Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            })
        }
    } else {
        if ($missingGraphModules.Count -gt 0) {
            Write-ScriptLog -Level ERROR -Message "Missing required Microsoft Graph PowerShell SDK module(s): $($missingGraphModules -join ', ')."
            Write-ScriptLog -Level INFO  -Message "Install via: Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Force"
            exit 1
        }

        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop

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
                $needsLogin = $true
                if ($null -ne $mgContext -and ($mgContext.Account -or $mgContext.AppName)) {
                    $needsLogin = $false
                }
                if ($needsLogin) {
                    Write-ScriptLog -Level INFO -Message "Connecting interactively to Microsoft Graph (Scopes: Device.ReadWrite.All, Directory.ReadWrite.All)..."
                    $connectParams = @{
                        Scopes      = @('Device.ReadWrite.All', 'Directory.ReadWrite.All')
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

            Write-ScriptLog -Level INFO -Message "Querying Microsoft Entra ID devices via Get-MgDevice..."
            $mgProps = @(
                'Id', 'DisplayName', 'DeviceId', 'OperatingSystem',
                'OperatingSystemVersion', 'AccountEnabled',
                'ApproximateLastSignInDateTime', 'RegistrationDateTime', 'TrustType'
            )

            $allCloudDevices = @(Get-MgDevice -All -Property $mgProps -ErrorAction Stop)
            Write-ScriptLog -Level INFO -Message "Retrieved $($allCloudDevices.Count) device(s) from Microsoft Entra ID. Filtering for ApproximateLastSignInDateTime < $($StareDni.ToString('yyyy-MM-dd'))..."

            $candidateDevices = New-Object System.Collections.Generic.List[PSObject]
            foreach ($dev in $allCloudDevices) {
                if (-not $IncludeServers -and -not [string]::IsNullOrWhiteSpace($dev.OperatingSystem) -and $dev.OperatingSystem -match '(?i)Server') {
                    $stats.Skipped++
                    continue
                }

                if (-not $IncludeAlreadyDisabled -and $normalizedAction -eq 'Disable' -and $dev.AccountEnabled -eq $false) {
                    $stats.Skipped++
                    continue
                }

                if (Test-IsComputerExcluded -ComputerName $dev.DisplayName -ExclusionPatterns $ExcludeComputers) {
                    Write-ScriptLog -Level WARN -Message "Skipping excluded Entra ID device '$($dev.DisplayName)'."
                    $stats.Skipped++
                    continue
                }

                $lastActivity = if ($null -ne $dev.ApproximateLastSignInDateTime) {
                    [datetime]$dev.ApproximateLastSignInDateTime
                } elseif ($null -ne $dev.RegistrationDateTime) {
                    [datetime]$dev.RegistrationDateTime
                } else {
                    $null
                }

                if ($null -ne $lastActivity -and $lastActivity -lt $StareDni) {
                    $candidateDevices.Add($dev)
                }
            }

            $stats.TotalDiscovered += $candidateDevices.Count
            Write-ScriptLog -Level INFO -Message "Found $($candidateDevices.Count) eligible stale Entra ID device(s) to process (Action: $normalizedAction)."

            if ($candidateDevices.Count -gt 0) {
                $confirmCloud = "Proceed with Action '$normalizedAction' on $($candidateDevices.Count) stale Microsoft Entra ID device(s) (inactive > $StaleDays days)?"
                if (-not (Request-UserConfirmation -PromptMessage $confirmCloud)) {
                    Write-ScriptLog -Level WARN -Message "Cloud Entra ID operation cancelled by user at confirmation prompt."
                } else {
                    $now = Get-Date
                    $totalDev = $candidateDevices.Count
                    $devIdx = 0

                    foreach ($dev in $candidateDevices) {
                        $devIdx++
                        $pct = [math]::Min(100, [int](($devIdx / [math]::Max(1, $totalDev)) * 100))
                        Write-Progress -Activity "Entra ID Stale Devices ($normalizedAction)" -Status "Processing $($dev.DisplayName) ($devIdx/$totalDev)" -PercentComplete $pct

                        $refDate = if ($null -ne $dev.ApproximateLastSignInDateTime) { [datetime]$dev.ApproximateLastSignInDateTime } else { [datetime]$dev.RegistrationDateTime }
                        $daysStale = if ($null -ne $refDate) { [math]::Round(($now - $refDate).TotalDays, 0) } else { $StaleDays }
                        $statusText = "Unchanged"

                        try {
                            if ($normalizedAction -eq 'AuditOnly') {
                                $statusText = "Audited"
                                $stats.Audited++
                                Write-ScriptLog -Level INFO -Message "Audited stale Entra ID device: $($dev.DisplayName) (ObjectId: $($dev.Id), LastSignIn: $($dev.ApproximateLastSignInDateTime))."
                            } elseif ($normalizedAction -eq 'Disable') {
                                if ($DryRun -or -not $PSCmdlet.ShouldProcess("$($dev.DisplayName) ($($dev.Id))", "Update-MgDevice -AccountEnabled:`$false")) {
                                    $statusText = "DryRun-Disabled"
                                    $stats.Disabled++
                                    Write-Host "[DryRun] Wyłączono nieaktywny komputer: $($dev.DisplayName)" -ForegroundColor Yellow
                                    Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would disable Entra ID device '$($dev.DisplayName)' ($($dev.Id))." -NoConsole
                                } else {
                                    Update-MgDevice -DeviceId $dev.Id -BodyParameter @{ accountEnabled = $false } -ErrorAction Stop
                                    Write-Host "Wyłączono nieaktywny komputer: $($dev.DisplayName)" -ForegroundColor Yellow
                                    Write-ScriptLog -Level SUCCESS -Message "Disabled stale Entra ID device: $($dev.DisplayName) (ObjectId: $($dev.Id), LastSignIn: $($dev.ApproximateLastSignInDateTime))." -NoConsole
                                    $statusText = "Disabled"
                                    $stats.Disabled++
                                }
                            } elseif ($normalizedAction -eq 'Remove') {
                                if ($DryRun -or -not $PSCmdlet.ShouldProcess("$($dev.DisplayName) ($($dev.Id))", "Remove-MgDevice")) {
                                    $statusText = "DryRun-Removed"
                                    $stats.Removed++
                                    Write-Host "[DryRun] Usunięto nieaktywny komputer: $($dev.DisplayName)" -ForegroundColor Yellow
                                    Write-ScriptLog -Level SUCCESS -Message "[DryRun] Would remove Entra ID device '$($dev.DisplayName)' ($($dev.Id))." -NoConsole
                                } else {
                                    Remove-MgDevice -DeviceId $dev.Id -ErrorAction Stop
                                    Write-Host "Usunięto nieaktywny komputer: $($dev.DisplayName)" -ForegroundColor Red
                                    Write-ScriptLog -Level SUCCESS -Message "Removed stale Entra ID device: $($dev.DisplayName) (ObjectId: $($dev.Id))." -NoConsole
                                    $statusText = "Removed"
                                    $stats.Removed++
                                }
                            }
                        } catch {
                            $statusText = "Failed: $($_.Exception.Message)"
                            $stats.Failed++
                            Write-ScriptLog -Level ERROR -Message "Failed to $normalizedAction Entra ID device '$($dev.DisplayName)' ($($dev.Id)): $_"
                        }

                        $processedRecords.Add([PSCustomObject]@{
                            Name              = $dev.DisplayName
                            SamAccountName    = $dev.DeviceId
                            DNSHostName       = $dev.DisplayName
                            OperatingSystem   = "$($dev.OperatingSystem) $($dev.OperatingSystemVersion)".Trim()
                            EnabledBefore     = $dev.AccountEnabled
                            PasswordLastSet   = $dev.RegistrationDateTime
                            LastLogonDate     = $dev.ApproximateLastSignInDateTime
                            DaysStale         = $daysStale
                            ActionTaken       = $statusText
                            DistinguishedName = "ObjectId=$($dev.Id)"
                            DirectorySource   = "EntraID"
                            ServerOrTenant    = $tenantIdentifier
                            Timestamp         = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        })
                    }
                    Write-Progress -Activity "Entra ID Stale Devices ($normalizedAction)" -Completed
                }
            }
        } catch {
            Write-ScriptLog -Level ERROR -Message "Failed to query or process Microsoft Entra ID devices via Microsoft Graph: $_"
            throw
        }
    }
}

# ==============================================================================
# EXPORT UTF-8 CSV AUDIT REPORT
# ==============================================================================
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
    Join-Path -Path $csvDir -ChildPath "$($script:StartTimestamp)-$($script:ScriptName)-Report.csv"
}

$csvParentDir = Split-Path -Path $finalCsvPath -Parent
if (-not [string]::IsNullOrWhiteSpace($csvParentDir) -and -not (Test-Path -LiteralPath $csvParentDir)) {
    New-Item -Path $csvParentDir -ItemType Directory -Force | Out-Null
}

$sortedRecords = @($processedRecords | Sort-Object -Property DaysStale -Descending)

try {
    $sortedRecords | Export-Csv -Path $finalCsvPath -Delimiter $Delimiter -NoTypeInformation -Encoding UTF8 -Force
    Write-ScriptLog -Level SUCCESS -Message "Exported $($sortedRecords.Count) processed computer record(s) to CSV: $finalCsvPath"
} catch {
    Write-ScriptLog -Level WARN -Message "Could not export CSV report to '$finalCsvPath': $_"
}

# ==============================================================================
# CONSOLE SUMMARY TABLE & EXECUTION STATISTICS
# ==============================================================================
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  STALE COMPUTERS CLEANUP SUMMARY ($script:ScriptName v$script:ScriptVersion)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ("  Directory Mode        : {0}" -f $normalizedMode) -ForegroundColor White
Write-Host ("  Action Mode           : {0}" -f $normalizedAction) -ForegroundColor White
Write-Host ("  Staleness Threshold   : > {0} days (Cutoff: {1})" -f $StaleDays, $StareDni.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor White
Write-Host ("  Stale Computers Found : {0}" -f $stats.TotalDiscovered) -ForegroundColor Yellow
Write-Host ("  Accounts Disabled     : {0}" -f $stats.Disabled) -ForegroundColor Green
Write-Host ("  Accounts Removed      : {0}" -f $stats.Removed) -ForegroundColor $(if ($stats.Removed -gt 0) { "Magenta" } else { "White" })
Write-Host ("  Accounts Audited Only : {0}" -f $stats.Audited) -ForegroundColor Cyan
Write-Host ("  Accounts Skipped      : {0}" -f $stats.Skipped) -ForegroundColor Gray
Write-Host ("  Accounts Failed       : {0}" -f $stats.Failed) -ForegroundColor $(if ($stats.Failed -gt 0) { "Red" } else { "Green" })
Write-Host ("  CSV Report Path       : {0}" -f $finalCsvPath) -ForegroundColor Green
if ($script:ActiveLogFile) {
    Write-Host ("  Execution Log File    : {0}" -f $script:ActiveLogFile) -ForegroundColor Gray
}
Write-Host "================================================================================" -ForegroundColor Cyan

if ($sortedRecords.Count -gt 0) {
    Write-Host ""
    $sortedRecords | Select-Object Name, OperatingSystem, PasswordLastSet, DaysStale, ActionTaken, DirectorySource | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor White
}

Write-ScriptLog -Level INFO -Message "Execution completed. Discovered=$($stats.TotalDiscovered), Disabled=$($stats.Disabled), Removed=$($stats.Removed), Audited=$($stats.Audited), Skipped=$($stats.Skipped), Failed=$($stats.Failed)."

if ($PassThru) {
    Write-Output $sortedRecords
}
