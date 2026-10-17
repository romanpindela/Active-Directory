<#
================================================================================
  Script Name : User-LogonScript.ps1
  Author      : Roman Pindela
  Contact     : roman.pindela@gmail.com
  Version     : 1.2.0
  Release Date: 2026-10-17
  License     : MIT
  Repository  : https://github.com/romanpindela

  DESCRIPTION:
    Enterprise-grade PowerShell User Logon Script & Group Policy (GPO) / Cloud
    Deployment Automation Tool for Windows Server Active Directory (AD DS) and
    Microsoft Entra ID (Azure AD / Microsoft Intune).

    Addresses the complete lifecycle of an Active Directory & Cloud PowerShell
    User Logon Script:
      - Step 1 (Prepare & Execute Logon Script):
        Maps persistent network drives (e.g., Z: -> \\serwer\zasob) after
        verifying if the drive is already mapped, validates optional AD/Entra ID
        group membership, and writes logon confirmation entries to both the
        local status file (C:\Temp\LogonStatus.txt) and the centralized audit
        log in C:\Logs. Can also generate a standalone LogonScript.ps1 file.
      - Step 2 (Publish to SYSVOL Share):
        Automatically resolves and copies the logon script to the domain-wide
        replicated SYSVOL share (\\<domain>\sysvol\<domain>\scripts) and
        verifies UNC accessibility from client workstations.
      - Step 3 (Configure Group Policy Object / Cloud Policy):
        Creates or updates an Active Directory GPO (e.g., Skrypty_Logowania_GPO),
        configures the PowerShell User Logon Script in SYSVOL (psscripts.ini /
        GPT.ini), links the GPO to the target Organizational Unit (OU), and
        optionally configures the GPO PowerShell ExecutionPolicy setting.
        In Cloud mode, deploys the PowerShell logon script to Microsoft Entra ID
        / Intune via Microsoft Graph SDK.
      - Step 4 (Verify & Force Policy Refresh):
        Executes 'gpupdate /force' on demand, verifies that the mapped network
        drive (e.g., Z:) is mounted, checks C:\Temp\LogonStatus.txt, and
        validates SYSVOL & GPO configuration health.

    Supports three operational directory modes (-Mode / -Provider):
      - Local (AD / OnPremises) : Local Active Directory Domain Services & GPO.
      - Cloud (EntraID / Cloud) : Microsoft Entra ID & Microsoft Graph SDK
                                  (supports both interactive sign-in and
                                  non-interactive App-Only authentication via
                                  Client Secret or X.509 Certificate).
      - Both                    : Hybrid execution across both Local AD and
                                  Cloud Microsoft Entra ID.

    Key Standards & Security Capabilities:
      1. Zero-Parameter Interactive Help (-Help / -h):
         Displays complete usage instructions, step-by-step GPO configuration
         guide (Steps 1-4 + ExecutionPolicy in GPO), Entra ID non-interactive
         authentication guide, examples, version, and author details when
         launched without parameters.
      2. Defensive Input Sanitization:
         Protects against malicious input, path traversal, command injection,
         LDAP filter injection (RFC 4515), and OData filter injection.
      3. Language-Independent UAC Auto-Elevation:
         Verifies Administrator privileges via well-known Windows SID
         (S-1-5-32-544 / BuiltInAdministratorsSid) for full compatibility across
         Polish ("Administratorzy") and English ("Administrators") Windows OS.
      4. Real-Time Granular Progress Bar (Write-Progress):
         Tracks multi-step logon and GPO/Cloud deployment phases.
      5. Detailed Audit Logging (Enabled by Default):
         Writes UTF-8 timestamped execution logs to:
         C:\Logs\<yyyyMMdd_HHmmss>-User-LogonScript-<ComputerName>-<UserName>.logs
         and logon verification entries to C:\Temp\LogonStatus.txt.
================================================================================
.SYNOPSIS
    Executes, generates, deploys (via SYSVOL & GPO or Microsoft Entra ID / Graph),
    and verifies PowerShell User Logon Scripts in Local AD and Cloud environments.

.DESCRIPTION
    Provides both a production-ready PowerShell User Logon Script (mapping
    network drives such as Z: -> \\serwer\zasob and logging logon timestamps to
    C:\Temp\LogonStatus.txt and C:\Logs) and an automated deployment toolkit
    for publishing the script to the Active Directory SYSVOL share
    (\\domain.local\sysvol\domain.local\scripts), linking it via Group Policy
    (GPO) to an Organizational Unit (OU), configuring GPO PowerShell
    ExecutionPolicy, and managing Cloud logon scripts in Microsoft Entra ID.

.PARAMETER Action
    Operational workflow to perform:
      - 'ExecuteLogon'   : (Default) Runs the user logon workflow: maps the
                           configured network drive(s), optionally checks AD or
                           Entra ID group membership, and writes logon status to
                           C:\Temp\LogonStatus.txt and C:\Logs.
      - 'GenerateScript' : Generates a standalone LogonScript.ps1 file ready for
                           SYSVOL / GPO deployment.
      - 'DeployGPO'      : Copies the logon script to \\<domain>\sysvol\<domain>\scripts,
                           creates/updates the GPO (or Cloud Intune script policy),
                           configures the PowerShell Logon Script setting, and
                           links the GPO to -TargetOU.
      - 'Verify'         : Verifies mapped network drive status, checks
                           C:\Temp\LogonStatus.txt, validates SYSVOL UNC access,
                           and optionally triggers 'gpupdate /force'.
    Aliases: -Operation, -Task

.PARAMETER Mode
    Target directory environment mode:
      - 'Local'   (or 'AD', 'OnPremises')   : Local Active Directory & GPO (Default).
      - 'Cloud'   (or 'EntraID', 'AzureAD') : Microsoft Entra ID / Cloud via Graph SDK.
      - 'Both'                              : Hybrid Local AD + Cloud Entra ID mode.
    Aliases: -Provider, -Environment, -Target, -Directory

.PARAMETER DriveLetter
    Drive letter to map for the user (e.g., "Z:" or "Z"). Default: "Z:".
    Aliases: -Drive, -d

.PARAMETER NetworkPath
    UNC network share path to map to the drive letter (e.g., "\\serwer\zasob").
    Aliases: -SharePath, -UncPath, -Root, -s

.PARAMETER StatusLogPath
    Local file path used to record user logon confirmation messages (Step 1 & 4).
    Default: "C:\Temp\LogonStatus.txt".
    Aliases: -LogonStatusFile, -StatusFile

.PARAMETER ScriptOutputPath
    Target file path when generating a standalone LogonScript.ps1 file
    (via -Action GenerateScript or -GenerateLogonScript) or source script path
    when deploying to SYSVOL. Default: ".\LogonScript.ps1".
    Aliases: -ScriptPath, -LogonScriptPath

.PARAMETER DomainName
    DNS name of the Active Directory domain (e.g., "twojadomena.local").
    If omitted in Local AD mode, it is automatically detected via Get-ADDomain
    or $env:USERDNSDOMAIN.
    Aliases: -Domain, -DnsRoot

.PARAMETER SysvolScriptsPath
    Explicit UNC path to the domain SYSVOL scripts directory
    (e.g., "\\twojadomena.local\sysvol\twojadomena.local\scripts").
    If omitted, it is built automatically from -DomainName.

.PARAMETER GpoName
    Name of the Group Policy Object to create or update when deploying the
    logon script (e.g., "Skrypty_Logowania_GPO").
    Default: "Skrypty_Logowania_GPO".
    Aliases: -GPO, -PolicyName

.PARAMETER TargetOU
    Distinguished Name (DN) of the Active Directory Organizational Unit (OU)
    where the GPO should be linked (e.g., "OU=Pracownicy,DC=twojadomena,DC=local").
    Aliases: -OU, -SearchBase

.PARAMETER ConfigureExecutionPolicy
    Switch parameter. When used with -Action DeployGPO (or -DeployGPO), configures
    the Group Policy setting 'Turn on Script Execution' (ExecutionPolicy) to allow
    PowerShell logon scripts to run on domain workstations.

.PARAMETER ExecutionPolicyLevel
    ExecutionPolicy mode to set in GPO when -ConfigureExecutionPolicy is specified:
      - 'RemoteSigned' : Allow local scripts and remote signed scripts (Recommended).
      - 'AllSigned'    : Allow only signed scripts.
      - 'Unrestricted' : Allow all scripts.
    Default: 'RemoteSigned'.

.PARAMETER RequiredGroup
    Optional Active Directory or Microsoft Entra ID security group name/ObjectId.
    If specified during logon execution, the network drive is mapped only if the
    current user (or -UserPrincipalName) is a member of this group.
    Aliases: -Group, -GroupName

.PARAMETER UserPrincipalName
    Optional user login / UPN to evaluate in Cloud Entra ID mode. Defaults to the
    currently signed-in user ($env:USERNAME / whoami /upn).
    Aliases: -UPN, -User

.PARAMETER RunGpUpdate
    Switch parameter. Runs 'gpupdate /force' during verification (-Action Verify)
    to immediately refresh Group Policy settings on the workstation.

.PARAMETER GenerateLogonScript
    Switch parameter shortcut for -Action GenerateScript.

.PARAMETER DeployGPO
    Switch parameter shortcut for -Action DeployGPO.

.PARAMETER Verify
    Switch parameter shortcut for -Action Verify.

.PARAMETER ExecuteLogon
    Switch parameter shortcut for -Action ExecuteLogon.

.PARAMETER DomainController
    Optional specific Active Directory Domain Controller FQDN or IP address.
    Aliases: -Server, -DC

.PARAMETER Credential
    Optional PSCredential object for Local Active Directory / SMB operations.

.PARAMETER TenantId
    Microsoft Entra ID Directory (Tenant) ID for Cloud mode authentication.
    Aliases: -Tenant, -DirectoryId

.PARAMETER ClientId
    Microsoft Entra ID Application (Client) ID for non-interactive Cloud auth.
    Aliases: -AppId, -ApplicationId

.PARAMETER ClientSecret
    Microsoft Entra ID Client Secret string for non-interactive Cloud auth.
    Aliases: -Secret

.PARAMETER ClientSecretSecure
    Optional SecureString containing the Microsoft Entra ID Client Secret.

.PARAMETER CertificateThumbprint
    Thumbprint of an X.509 Certificate installed in Cert:\CurrentUser\My or
    Cert:\LocalMachine\My for non-interactive Cloud authentication.
    Aliases: -Thumbprint

.PARAMETER ExportReportPath
    Optional file path to export a UTF-8 CSV report of all executed steps.
    Aliases: -ExportCsv, -ReportPath

.PARAMETER DryRun
    Switch parameter. Simulates drive mapping, SYSVOL copy, and GPO/Cloud
    deployment without making persistent changes.
    Aliases: -Simulate, -Preview

.PARAMETER RequireAdmin
    Switch parameter. Forces UAC Administrator privilege elevation even for
    standard user-context actions. (Admin elevation is triggered automatically
    for GPO deployment and policy configuration actions).

.PARAMETER SkipAdminCheck
    Switch parameter. Skips automatic UAC Administrator privilege elevation check.

.PARAMETER PassThru
    Switch parameter. Outputs structured execution result objects to the pipeline.

.PARAMETER LogPath
    Custom path for the execution log file.
    Default: C:\Logs\<yyyyMMdd_HHmmss>-User-LogonScript-<ComputerName>-<UserName>.logs
    Aliases: -l, -Log

.PARAMETER NoLog
    Switch parameter. Disables writing execution logs to C:\Logs.

.PARAMETER Force
    Switch parameter. Bypasses interactive confirmation prompts (Y/N / T/N) and
    remaps the drive if it is already mapped.

.PARAMETER Help
    Displays detailed script help, step-by-step GPO Logon Script tutorial,
    ExecutionPolicy GPO guide, Entra ID non-interactive configuration guide,
    examples, version, and author information.
    Aliases: -h

.EXAMPLE
    .\User-LogonScript.ps1
    Displays the built-in help screen, complete step-by-step GPO Logon Script
    guide, usage examples, version, and author information.

.EXAMPLE
    .\User-LogonScript.ps1 -DriveLetter "Z:" -NetworkPath "\\serwer\zasob"
    Runs the User Logon Script in Local AD mode: checks if drive Z: is already
    mapped, maps Z: persistently to \\serwer\zasob using New-PSDrive -Persist,
    appends "Zalogowano pomyślnie dnia <Data>" to C:\Temp\LogonStatus.txt, and
    writes a full execution log to C:\Logs.

.EXAMPLE
    .\User-LogonScript.ps1 -GenerateLogonScript -ScriptOutputPath ".\LogonScript.ps1" -DriveLetter "Z:" -NetworkPath "\\serwer\zasob"
    Generates a standalone 'LogonScript.ps1' file ready to copy to SYSVOL.

.EXAMPLE
    .\User-LogonScript.ps1 -DeployGPO -DomainName "twojadomena.local" -GpoName "Skrypty_Logowania_GPO" -TargetOU "OU=Pracownicy,DC=twojadomena,DC=local" -NetworkPath "\\serwer\zasob" -ConfigureExecutionPolicy
    Generates LogonScript.ps1, copies it to \\twojadomena.local\sysvol\twojadomena.local\scripts,
    creates GPO 'Skrypty_Logowania_GPO', assigns LogonScript.ps1 as a User Logon
    PowerShell script, enables GPO PowerShell ExecutionPolicy (RemoteSigned), and
    links the GPO to OU=Pracownicy.

.EXAMPLE
    .\User-LogonScript.ps1 -Verify -DriveLetter "Z:" -DomainName "twojadomena.local" -GpoName "Skrypty_Logowania_GPO" -RunGpUpdate
    Runs 'gpupdate /force' and verifies whether drive Z: is mapped, whether
    C:\Temp\LogonStatus.txt exists, and whether LogonScript.ps1 is accessible in SYSVOL.

.EXAMPLE
    .\User-LogonScript.ps1 -Mode Cloud -DriveLetter "Z:" -NetworkPath "\\storageaccount.file.core.windows.net\zasob" `
        -RequiredGroup "Dzial_Ksiegowosci" `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -ClientSecret "YourClientSecretValue" -Force
    Executes the logon script in Cloud (Microsoft Entra ID) mode using
    non-interactive App-Only authentication, verifies the user's Entra ID group
    membership, maps the cloud SMB share to Z:, and logs the status.

.NOTES
    Author  : Roman Pindela
    Email   : roman.pindela@gmail.com
    GitHub  : https://github.com/romanpindela
    Version : 1.2.0
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run', Position = 0)]
    [Alias('Operation', 'Task')]
    [ValidateSet('ExecuteLogon', 'GenerateScript', 'DeployGPO', 'Verify')]
    [string]$Action = 'ExecuteLogon',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Provider', 'Environment', 'Target', 'Directory')]
    [ValidateSet('Local', 'AD', 'OnPremises', 'Cloud', 'EntraID', 'AzureAD', 'Intune', 'Both')]
    [string]$Mode = 'Local',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Drive', 'd')]
    [string]$DriveLetter = 'Z:',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('SharePath', 'UncPath', 'Root', 's')]
    [string]$NetworkPath = '\\serwer\zasob',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('LogonStatusFile', 'StatusFile')]
    [string]$StatusLogPath = 'C:\Temp\LogonStatus.txt',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('ScriptPath', 'LogonScriptPath')]
    [string]$ScriptOutputPath = '.\LogonScript.ps1',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Domain', 'DnsRoot')]
    [string]$DomainName,

    [Parameter(ParameterSetName = 'Run')]
    [string]$SysvolScriptsPath,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('GPO', 'PolicyName')]
    [string]$GpoName = 'Skrypty_Logowania_GPO',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('OU', 'SearchBase')]
    [string]$TargetOU,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$ConfigureExecutionPolicy,

    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('RemoteSigned', 'AllSigned', 'Unrestricted')]
    [string]$ExecutionPolicyLevel = 'RemoteSigned',

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Group', 'GroupName')]
    [string]$RequiredGroup,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('UPN', 'User')]
    [string]$UserPrincipalName,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$RunGpUpdate,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$GenerateLogonScript,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$DeployGPO,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$Verify,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$ExecuteLogon,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Server', 'DC')]
    [string]$DomainController,

    [Parameter(ParameterSetName = 'Run')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Tenant', 'DirectoryId')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('AppId', 'ApplicationId')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Secret')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'Run')]
    [System.Security.SecureString]$ClientSecretSecure,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Thumbprint')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('ExportCsv', 'ReportPath')]
    [string]$ExportReportPath,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('Simulate', 'Preview')]
    [switch]$DryRun,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$RequireAdmin,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$SkipAdminCheck,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$PassThru,

    [Parameter(ParameterSetName = 'Run')]
    [Alias('l', 'Log')]
    [string]$LogPath,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$NoLog,

    [Parameter(ParameterSetName = 'Run')]
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
$script:ScriptName    = "User-LogonScript"
$script:ScriptVersion = "1.2.0"
$script:ScriptDate    = "2026-10-17"
$script:ScriptAuthor  = "Roman Pindela"
$script:ScriptEmail   = "roman.pindela@gmail.com"
$script:ScriptGitHub  = "https://github.com/romanpindela"
$script:ActiveLogFile = $null
$script:AuthMode      = "Interactive"

# Resolve shortcut switches into $Action
if ($GenerateLogonScript) { $Action = 'GenerateScript' }
elseif ($DeployGPO)      { $Action = 'DeployGPO' }
elseif ($Verify)         { $Action = 'Verify' }
elseif ($ExecuteLogon)   { $Action = 'ExecuteLogon' }

# Normalize Mode ('Local'/'AD'/'OnPremises' -> 'Local', 'Cloud'/'EntraID'/'AzureAD'/'Intune' -> 'Cloud', 'Both' -> 'Both')
$script:NormalizedMode = switch ($Mode.ToUpperInvariant()) {
    'LOCAL'      { 'Local' }
    'AD'         { 'Local' }
    'ONPREMISES' { 'Local' }
    'CLOUD'      { 'Cloud' }
    'ENTRAID'    { 'Cloud' }
    'AZUREAD'    { 'Cloud' }
    'INTUNE'     { 'Cloud' }
    'BOTH'       { 'Both' }
    default      { 'Local' }
}

# ==============================================================================
# HELP & DOCUMENTATION DISPLAY (-Help / -h / Zero-Parameters)
# ==============================================================================
function Show-ScriptHelp {
    $helpText = @"
================================================================================
  SCRIPT  : User-LogonScript.ps1
  VERSION : $script:ScriptVersion ($script:ScriptDate)
  AUTHOR  : $script:ScriptAuthor
  CONTACT : $script:ScriptEmail | $script:ScriptGitHub
================================================================================

DESCRIPTION:
    Enterprise-grade PowerShell User Logon Script & Group Policy (GPO) / Cloud
    Deployment Automation Tool for Windows Server Active Directory (AD DS) and
    Microsoft Entra ID (Azure AD / Microsoft Intune).

    Supports three operational directory modes (-Mode / -Provider):
      1. Local (AD / OnPremises) : Maps persistent network drives in Active
                                   Directory, logs logon status to C:\Temp\LogonStatus.txt
                                   and C:\Logs, publishes LogonScript.ps1 to
                                   SYSVOL, and links/configures Group Policy (GPO).
      2. Cloud (EntraID / Cloud) : Verifies cloud user identity & group memberships
                                   in Microsoft Entra ID via Microsoft Graph SDK,
                                   maps cloud/SMB shares, or deploys the logon
                                   script to Microsoft Intune / Entra ID.
      3. Both                    : Executes or deploys across both Local Active
                                   Directory (SYSVOL + GPO) and Cloud Entra ID.

--------------------------------------------------------------------------------
STEP-BY-STEP GUIDE: HOW TO CREATE & ASSIGN A POWERSHELL LOGON SCRIPT VIA AD GPO
--------------------------------------------------------------------------------
Step 1: Prepare the PowerShell Logon Script (LogonScript.ps1)
    Generate or execute a PowerShell script that maps a network drive (e.g. Z:
    to \\serwer\zasob) and writes verification output to C:\Temp\LogonStatus.txt:
      `$DriveLetter = "Z:"
      `$DriveName   = `$DriveLetter.TrimEnd(':')
      `$NetworkPath = "\\serwer\zasob"
      if (!(Test-Path `$DriveLetter)) {
          New-PSDrive -Name `$DriveName -PSProvider FileSystem -Root `$NetworkPath -Persist
      }
      `$LogPath = "C:\Temp\LogonStatus.txt"
      if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" | Out-Null }
      "Zalogowano pomyślnie dnia `$(Get-Date)" | Out-File -Append -FilePath `$LogPath -Encoding UTF8

Step 2: Place the Script in the Domain SYSVOL Share
    1. On a Domain Controller (or administrative workstation), open File Explorer
       and navigate to the domain SYSVOL scripts share:
       \\twojadomena.local\sysvol\twojadomena.local\scripts
       (Replace 'twojadomena.local' with your actual Active Directory DNS domain).
    2. Copy 'LogonScript.ps1' into this folder (or let this script do it
       automatically using -DeployGPO).
    3. Verification: Test UNC reachability from a client workstation via Win + R.

Step 3: Configure Group Policy Object (GPO) in Active Directory
    1. Press Win + R, type 'gpmc.msc' (Group Policy Management Console), press Enter.
    2. Expand your domain, right-click the target Organizational Unit (OU) containing
       your users (e.g., 'Pracownicy'), and select:
       'Create a GPO in this domain, and Link it here...' -> Name: 'Skrypty_Logowania_GPO'.
    3. Right-click 'Skrypty_Logowania_GPO' and select 'Edit'.
    4. Navigate to:
       User Configuration -> Policies -> Windows Settings -> Scripts (Logon/Logoff)
       (PL: Konfiguracja użytkownika -> Zasady -> Ustawienia systemu Windows -> Skrypty (Logowanie/Wylogowanie)).
    5. Double-click 'Logon' (PL: 'Logowanie') in the right pane.
    6. Select the 'PowerShell Scripts' tab (PL: 'Skrypty programu PowerShell') —
       CRITICAL: the standard 'Scripts' tab is for .bat/.cmd files, not .ps1!
    7. Click 'Add' (Dodaj) -> 'Browse' (Przeglądaj), select 'LogonScript.ps1' from
       the SYSVOL scripts folder, and click OK.

Step 4: Verification on Client Workstation
    1. Sign in to a domain-joined workstation as a user residing in the target OU.
    2. Force an immediate Group Policy update in an elevated PowerShell console:
       gpupdate /force
    3. Log off and log back on to trigger the User Logon Script.
    4. Verify that drive Z: is mapped in File Explorer and that
       'C:\Temp\LogonStatus.txt' contains "Zalogowano pomyślnie dnia ...".

Bonus: How to Configure PowerShell ExecutionPolicy via GPO
    In the GPO Editor (gpmc.msc), navigate to:
      Computer Configuration (or User Configuration) -> Policies ->
      Administrative Templates -> Windows Components -> Windows PowerShell ->
      'Turn on Script Execution' (Włącz wykonywanie skryptów) ->
      Set to 'Enabled' and choose:
      'Allow local scripts and remote signed scripts' (RemoteSigned) or
      'Allow all scripts' (Unrestricted).
    (You can automate this directly by passing -ConfigureExecutionPolicy to this script!).

--------------------------------------------------------------------------------
HOW TO CONFIGURE ENTRA ID FOR NON-INTERACTIVE / UNATTENDED AUTHENTICATION:
(Only via API Keys / Credentials and Entra ID Microsoft Graph SDK Permissions)
--------------------------------------------------------------------------------
To run this script in unattended Cloud mode (-Mode Cloud / -Mode Both) via
Microsoft Graph PowerShell SDK without interactive browser prompts:

Step 1: Register an Application in Microsoft Entra ID
    1. Sign in to Microsoft Entra Admin Center (https://entra.microsoft.com).
    2. Go to: Identity > Applications > App registrations > New registration.
    3. Name: 'AD-LogonScript-Automation'.
    4. Supported account types: 'Accounts in this organizational directory only'.
    5. Click 'Register' and copy:
       - Application (client) ID  -> pass to -ClientId
       - Directory (tenant) ID    -> pass to -TenantId

Step 2: Grant Microsoft Graph API Application Permissions (App-Only)
    1. Go to: Manage > API permissions > Add a permission > Microsoft Graph > Application permissions.
    2. Add the following permissions:
       * User.Read.All                               (Verify cloud user profile)
       * GroupMember.Read.All                        (Verify user security groups)
       * DeviceManagementConfiguration.ReadWrite.All (Required if deploying logon scripts to Intune)
    3. Click 'Add permissions' and click 'Grant admin consent for <Your Tenant>'.

Step 3: Configure Non-Interactive Credentials (Option A: Client Secret / Option B: Certificate)
    Option A: Client Secret (API Key)
      - Create a secret in: Manage > Certificates & secrets > Client secrets > New client secret.
      - Pass to script:
        -Mode Cloud -TenantId '<TenantId>' -ClientId '<ClientId>' -ClientSecret '<SecretValue>'
    Option B: X.509 Certificate (Recommended for Production)
      - Generate certificate:
        `$cert = New-SelfSignedCertificate -Subject 'CN=EntraLogonAutomation' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
        Export-Certificate -Cert `$cert -FilePath 'C:\Logs\EntraLogonAutomation.cer'
      - Upload .cer in Entra Admin Center > Certificates & secrets > Certificates.
      - Pass to script:
        -Mode Cloud -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint `$cert.Thumbprint

--------------------------------------------------------------------------------
USAGE EXAMPLES:
--------------------------------------------------------------------------------
  # 1. Execute User Logon Script (Map Z: to \\serwer\zasob & log to C:\Temp\LogonStatus.txt):
  .\User-LogonScript.ps1 -DriveLetter "Z:" -NetworkPath "\\serwer\zasob"

  # 2. Generate a standalone LogonScript.ps1 file ready for SYSVOL / GPO:
  .\User-LogonScript.ps1 -GenerateLogonScript -ScriptOutputPath ".\LogonScript.ps1" ``
      -DriveLetter "Z:" -NetworkPath "\\serwer\zasob"

  # 3. Full Automated AD SYSVOL + GPO Deployment (Steps 1, 2 & 3 + ExecutionPolicy):
  .\User-LogonScript.ps1 -DeployGPO ``
      -DomainName "twojadomena.local" ``
      -GpoName "Skrypty_Logowania_GPO" ``
      -TargetOU "OU=Pracownicy,DC=twojadomena,DC=local" ``
      -DriveLetter "Z:" -NetworkPath "\\serwer\zasob" ``
      -ConfigureExecutionPolicy -ExecutionPolicyLevel RemoteSigned -Force

  # 4. Verify Logon Script Execution, Mapped Drive, SYSVOL & Run gpupdate /force (Step 4):
  .\User-LogonScript.ps1 -Verify -DriveLetter "Z:" -DomainName "twojadomena.local" ``
      -GpoName "Skrypty_Logowania_GPO" -RunGpUpdate

  # 5. Conditional Group-Based Logon Drive Mapping in Local AD:
  .\User-LogonScript.ps1 -DriveLetter "Z:" -NetworkPath "\\serwer\ksiegowosc" ``
      -RequiredGroup "Dzial_Ksiegowosci" -Mode Local -Force

  # 6. Cloud Mode (Microsoft Entra ID) Non-Interactive User Logon & Group Check:
  .\User-LogonScript.ps1 -Mode Cloud -DriveLetter "Z:" ``
      -NetworkPath "\\storage.file.core.windows.net\zasob" ``
      -RequiredGroup "Dzial_Ksiegowosci" ``
      -UserPrincipalName "jkowalski@contoso.com" ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -ClientSecret "YourClientSecretValueHere" -Force

--------------------------------------------------------------------------------
PARAMETERS:
--------------------------------------------------------------------------------
  -Action, -Operation           Workflow: 'ExecuteLogon' (default), 'GenerateScript', 'DeployGPO', 'Verify'.
  -Mode, -Provider              Directory mode: 'Local' ('AD'), 'Cloud' ('EntraID'), or 'Both'.
  -DriveLetter, -Drive, -d      Drive letter to map (Default: 'Z:').
  -NetworkPath, -SharePath, -s  UNC path to map (Default: '\\serwer\zasob').
  -StatusLogPath                Logon status file path (Default: 'C:\Temp\LogonStatus.txt').
  -ScriptOutputPath             Path for standalone LogonScript.ps1 (Default: '.\LogonScript.ps1').
  -DomainName, -Domain          AD DNS domain name (e.g., 'twojadomena.local').
  -SysvolScriptsPath            Custom SYSVOL scripts UNC path.
  -GpoName, -GPO                GPO name (Default: 'Skrypty_Logowania_GPO').
  -TargetOU, -OU                Target OU DN to link the GPO (e.g., 'OU=Pracownicy,DC=firma,DC=local').
  -ConfigureExecutionPolicy     Configure PowerShell ExecutionPolicy inside the GPO.
  -ExecutionPolicyLevel         GPO ExecutionPolicy level ('RemoteSigned', 'AllSigned', 'Unrestricted').
  -RequiredGroup, -Group        Optional AD / Entra ID group required before mapping the drive.
  -UserPrincipalName, -UPN      Target user UPN for Cloud Entra ID verification.
  -RunGpUpdate                  Execute 'gpupdate /force' during -Verify.
  -GenerateLogonScript          Shortcut switch for -Action GenerateScript.
  -DeployGPO                    Shortcut switch for -Action DeployGPO.
  -Verify                       Shortcut switch for -Action Verify.
  -TenantId, -ClientId          Entra ID credentials for non-interactive Cloud mode.
  -ClientSecret, -Thumbprint    Entra ID Secret or Certificate Thumbprint for App-Only auth.
  -ExportReportPath             Export execution summary to a UTF-8 CSV file.
  -DryRun, -Simulate            Preview all actions without modifying drives, SYSVOL, or GPO.
  -LogPath, -NoLog              Custom log path or disable logging to C:\Logs.
  -Force                        Skip confirmation prompts (Y/N / T/N).
  -Help, -h                     Display this help manual.

LOGGING:
  1. Detailed execution audit logs are automatically written by default to:
     C:\Logs\<yyyyMMdd_HHmmss>-User-LogonScript-<ComputerName>-<UserName>.logs
  2. User logon verification entries are appended to:
     C:\Temp\LogonStatus.txt

SECURITY & UNBLOCKING:
  After downloading this script from GitHub, unblock the file before execution:
  Unblock-File -Path .\User-LogonScript.ps1
================================================================================
"@
    Write-Host $helpText -ForegroundColor Cyan
}

# ==============================================================================
# LOGGING ENGINE (Default: C:\Logs\<DateTime>-User-LogonScript-<PC>-<User>.logs)
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
  Action        : $Action
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

# Administrative elevation is required when deploying GPOs / SYSVOL scripts, configuring GPO ExecutionPolicy, or when explicitly requested via -RequireAdmin
$needsElevation = $RequireAdmin -or ($Action -eq 'DeployGPO' -and ($script:NormalizedMode -eq 'Local' -or $script:NormalizedMode -eq 'Both')) -or $ConfigureExecutionPolicy
if ($needsElevation -and -not $SkipAdminCheck -and -not $DryRun) {
    Assert-AdministratorPrivileges
}

# Initialize logging
Initialize-ScriptLogging
Write-ScriptLog -Level INFO -Message "Initialized $script:ScriptName v$script:ScriptVersion (Action: '$Action', Mode: '$script:NormalizedMode')."
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
        [string]$ParameterName = "Path"
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
# VALIDATE & NORMALIZE INPUT PARAMETERS
# ==============================================================================
Assert-SafeInput -InputValue $DriveLetter -ParameterName "DriveLetter" -MaxLength 10
Assert-SafeInput -InputValue $NetworkPath -ParameterName "NetworkPath" -MaxLength 512
Assert-SafeInput -InputValue $DomainName -ParameterName "DomainName" -MaxLength 255
Assert-SafeInput -InputValue $SysvolScriptsPath -ParameterName "SysvolScriptsPath" -MaxLength 512
Assert-SafeInput -InputValue $GpoName -ParameterName "GpoName" -MaxLength 256
Assert-SafeInput -InputValue $TargetOU -ParameterName "TargetOU" -MaxLength 512
Assert-SafeInput -InputValue $RequiredGroup -ParameterName "RequiredGroup" -MaxLength 256
Assert-SafeInput -InputValue $UserPrincipalName -ParameterName "UserPrincipalName" -MaxLength 256
Assert-SafeInput -InputValue $DomainController -ParameterName "DomainController" -MaxLength 255
Assert-SafeInput -InputValue $TenantId -ParameterName "TenantId" -MaxLength 128
Assert-SafeInput -InputValue $ClientId -ParameterName "ClientId" -MaxLength 128
Assert-SafeInput -InputValue $CertificateThumbprint -ParameterName "CertificateThumbprint" -MaxLength 128

Test-SafeFilePath -InputPath $StatusLogPath -ParameterName "StatusLogPath"
Test-SafeFilePath -InputPath $ScriptOutputPath -ParameterName "ScriptOutputPath"

# Normalize drive letter: e.g. "Z" or "Z:" -> DriveName = "Z", DriveRoot = "Z:"
$cleanDriveLetter = $DriveLetter.Trim().TrimEnd('\').TrimEnd(':')
if ($cleanDriveLetter -notmatch '^[a-zA-Z]$') {
    Write-ScriptLog -Level ERROR -Message "Invalid -DriveLetter '$DriveLetter'. Provide a single drive letter such as 'Z:' or 'Z'."
    exit 1
}
$normalizedDriveName = $cleanDriveLetter.ToUpperInvariant()
$normalizedDriveRoot = "${normalizedDriveName}:"

if ($NetworkPath -notmatch '^\\\\[^\\]+\\[^\\]+') {
    Write-ScriptLog -Level WARN -Message "Notice: -NetworkPath '$NetworkPath' does not follow standard UNC format (\\server\share)."
}

# ==============================================================================
# HELPER: BUILD STANDALONE LOGONSCRIPT.PS1 PAYLOAD (STEP 1)
# ==============================================================================
function Get-LogonScriptTemplateContent {
    param(
        [string]$TargetDriveRoot,
        [string]$TargetDriveName,
        [string]$TargetUncPath,
        [string]$TargetStatusFile
    )

    $template = @"
<#
================================================================================
  Script Name : LogonScript.ps1
  Generated By: User-LogonScript.ps1 v$script:ScriptVersion
  Author      : $script:ScriptAuthor ($script:ScriptEmail)
  Repository  : $script:ScriptGitHub
  Description : Active Directory / Entra ID PowerShell User Logon Script.
                Maps network drive $TargetDriveRoot to $TargetUncPath and writes
                logon confirmation to $TargetStatusFile and C:\Logs.
================================================================================
#>

# Przykład: Mapowanie dysku sieciowego dla użytkownika
`$DriveLetter = "$TargetDriveRoot"
`$DriveName   = "$TargetDriveName"
`$NetworkPath = "$TargetUncPath"

# Sprawdzenie czy dysk nie jest już zamapowany i mapowanie
if (!(Test-Path `$DriveLetter)) {
    New-PSDrive -Name `$DriveName -PSProvider FileSystem -Root `$NetworkPath -Persist -Scope Global -ErrorAction SilentlyContinue | Out-Null
}

# Weryfikacja sukcesu (zapis do logu lokalnego C:\Temp\LogonStatus.txt)
`$LogPath = "$TargetStatusFile"
`$LogDir  = Split-Path -Path `$LogPath -Parent
if (!(Test-Path `$LogDir)) {
    New-Item -ItemType Directory -Path `$LogDir -Force | Out-Null
}
"Zalogowano pomyślnie dnia `$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Użytkownik: `$env:USERDOMAIN\`$env:USERNAME | Komputer: `$env:COMPUTERNAME | Dysk: `$DriveLetter -> `$NetworkPath" | Out-File -Append -FilePath `$LogPath -Encoding UTF8

# Dodatkowy zapis do centralnego katalogu logów C:\Logs
`$CentralLogDir = "C:\Logs"
if (!(Test-Path `$CentralLogDir)) {
    New-Item -ItemType Directory -Path `$CentralLogDir -Force -ErrorAction SilentlyContinue | Out-Null
}
`$CentralLogFile = Join-Path -Path `$CentralLogDir -ChildPath "`$((Get-Date).ToString('yyyyMMdd_HHmmss'))-User-LogonScript-`$env:COMPUTERNAME-`$env:USERNAME.logs"
"[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')] [SUCCESS] Zalogowano pomyślnie dnia `$(Get-Date) (User: `$env:USERDOMAIN\`$env:USERNAME, Drive: `$DriveLetter -> `$NetworkPath)" | Out-File -Append -FilePath `$CentralLogFile -Encoding UTF8 -ErrorAction SilentlyContinue
"@
    return $template
}

# ==============================================================================
# CLOUD MICROSOFT ENTRA ID ENGINE (Microsoft Graph SDK)
# ==============================================================================
function Connect-EntraIDDirectory {
    Write-ScriptLog -Level STEP -Message "Initializing Cloud Microsoft Entra ID connection (Microsoft Graph SDK)..."

    $requiredModules = @('Microsoft.Graph.Authentication')
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
    # Mode 3: Interactive Delegated Sign-In (or reuse active session)
    else {
        $script:AuthMode = "Interactive-Delegated"
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        $scopes = @("User.Read.All", "GroupMember.Read.All")
        if ($Action -eq 'DeployGPO') {
            $scopes += "DeviceManagementConfiguration.ReadWrite.All"
        }

        if ($null -eq $ctx -or [string]::IsNullOrWhiteSpace($ctx.Account)) {
            Write-ScriptLog -Level INFO -Message "Launching interactive Microsoft Entra ID login..."
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

function Test-LocalADGroupMembership {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName
    )

    Write-ScriptLog -Level STEP -Message "[Local AD] Checking whether current user '$env:USERDOMAIN\$env:USERNAME' is a member of group '$GroupName'..."

    # First check current WindowsIdentity token SIDs / group names (fast, works on any domain workstation without RSAT)
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($groupSid in $identity.Groups) {
            try {
                $ntAccount = $groupSid.Translate([Security.Principal.NTAccount]).Value
                $shortGroup = ($ntAccount -split '\\')[-1]
                if ($shortGroup -ieq $GroupName -or $ntAccount -ieq $GroupName) {
                    Write-ScriptLog -Level SUCCESS -Message "[Local AD] Confirmed via Kerberos/NTLM token: User '$env:USERNAME' is a member of '$ntAccount'."
                    return $true
                }
            } catch {}
        }
    } catch {}

    # Fallback: Query ActiveDirectory module if available
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adParams = @{}
            if (-not [string]::IsNullOrWhiteSpace($DomainController)) { $adParams['Server'] = $DomainController }
            if ($null -ne $Credential) { $adParams['Credential'] = $Credential }

            $safeUser = ConvertTo-SafeLdapFilterValue -Value $env:USERNAME
            $adUser   = Get-ADUser -LDAPFilter "(sAMAccountName=$safeUser)" -Properties memberOf @adParams -ErrorAction Stop
            if ($adUser) {
                $safeGroup = ConvertTo-SafeLdapFilterValue -Value $GroupName
                $adGroup   = Get-ADGroup -LDAPFilter "(|(sAMAccountName=$safeGroup)(name=$safeGroup))" @adParams -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($adGroup) {
                    $members = @(Get-ADGroupMember -Identity $adGroup.DistinguishedName -Recursive @adParams -ErrorAction SilentlyContinue)
                    if ($members | Where-Object { $_.SamAccountName -ieq $env:USERNAME }) {
                        Write-ScriptLog -Level SUCCESS -Message "[Local AD] Confirmed via Get-ADGroupMember: User '$env:USERNAME' belongs to '$($adGroup.Name)'."
                        return $true
                    }
                }
            }
        } catch {
            Write-ScriptLog -Level WARN -Message "[Local AD] Could not query ActiveDirectory module for group check: $($_.Exception.Message)"
        }
    }

    Write-ScriptLog -Level WARN -Message "[Local AD] User '$env:USERNAME' is NOT a member of group '$GroupName'."
    return $false
}

function Test-CloudEntraGroupMembership {
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        [string]$TargetUpn
    )

    Connect-EntraIDDirectory

    $resolvedUpn = $TargetUpn
    if ([string]::IsNullOrWhiteSpace($resolvedUpn)) {
        try {
            $whoamiUpn = (& whoami.exe /upn 2>$null)
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($whoamiUpn)) {
                $resolvedUpn = $whoamiUpn.Trim()
            }
        } catch {}
    }
    if ([string]::IsNullOrWhiteSpace($resolvedUpn)) {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx -and -not [string]::IsNullOrWhiteSpace($ctx.Account)) {
            $resolvedUpn = $ctx.Account
        } else {
            $resolvedUpn = $env:USERNAME
        }
    }

    Write-ScriptLog -Level STEP -Message "[Cloud Entra ID] Verifying Entra ID user '$resolvedUpn' and group '$GroupName'..."

    $safeUpn = ConvertTo-SafeODataValue -Value $resolvedUpn
    $userUri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$safeUpn' or mail eq '$safeUpn' or mailNickname eq '$safeUpn'&`$select=id,displayName,userPrincipalName"
    $userResp = Invoke-MgGraphRequest -Method GET -Uri $userUri -ErrorAction Stop
    if (-not $userResp.value -or $userResp.value.Count -eq 0) {
        Write-ScriptLog -Level ERROR -Message "[Cloud Entra ID] User '$resolvedUpn' not found in Microsoft Entra ID."
        return $false
    }
    $cloudUser = $userResp.value[0]
    Write-ScriptLog -Level INFO -Message "[Cloud Entra ID] Resolved Cloud User: $($cloudUser.displayName) ($($cloudUser.userPrincipalName), ObjectId: $($cloudUser.id))"

    if ([string]::IsNullOrWhiteSpace($GroupName)) {
        return $true
    }

    $safeGrp = ConvertTo-SafeODataValue -Value $GroupName
    $grpUri  = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$safeGrp' or mailNickname eq '$safeGrp'&`$select=id,displayName"
    $grpResp = Invoke-MgGraphRequest -Method GET -Uri $grpUri -ErrorAction Stop
    if (-not $grpResp.value -or $grpResp.value.Count -eq 0) {
        Write-ScriptLog -Level ERROR -Message "[Cloud Entra ID] Group '$GroupName' not found in Microsoft Entra ID."
        return $false
    }
    $cloudGroup = $grpResp.value[0]

    $memberOfUri  = "https://graph.microsoft.com/v1.0/users/$($cloudUser.id)/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName"
    $memberOfResp = Invoke-MgGraphRequest -Method GET -Uri $memberOfUri -ErrorAction Stop
    $isMember = $false
    if ($memberOfResp.value) {
        foreach ($grp in $memberOfResp.value) {
            if ($grp.id -eq $cloudGroup.id -or $grp.displayName -ieq $GroupName) {
                $isMember = $true
                break
            }
        }
    }

    if ($isMember) {
        Write-ScriptLog -Level SUCCESS -Message "[Cloud Entra ID] User '$($cloudUser.userPrincipalName)' is a verified member of Entra ID group '$($cloudGroup.displayName)'."
    } else {
        Write-ScriptLog -Level WARN -Message "[Cloud Entra ID] User '$($cloudUser.userPrincipalName)' is NOT a member of Entra ID group '$($cloudGroup.displayName)'."
    }
    return $isMember
}

# ==============================================================================
# WORKFLOW 1: GENERATE STANDALONE LOGONSCRIPT.PS1 (Step 1)
# ==============================================================================
function Invoke-GenerateLogonScriptFile {
    param(
        [string]$OutputPath
    )

    Write-ScriptLog -Level STEP -Message "Step 1: Generating standalone PowerShell Logon Script at '$OutputPath'..."

    $scriptContent = Get-LogonScriptTemplateContent `
        -TargetDriveRoot $normalizedDriveRoot `
        -TargetDriveName $normalizedDriveName `
        -TargetUncPath $NetworkPath `
        -TargetStatusFile $StatusLogPath

    if ($DryRun) {
        Write-ScriptLog -Level INFO -Message "[DRY-RUN] Would generate LogonScript.ps1 at '$OutputPath' mapping '$normalizedDriveRoot' -> '$NetworkPath'."
        return [PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Step        = "Step1-GenerateLogonScript"
            Environment = $script:NormalizedMode
            Target      = $OutputPath
            Status      = "Simulated"
            Details     = "Dry-run generation of LogonScript.ps1 ($normalizedDriveRoot -> $NetworkPath)"
        }
    }

    if ((Test-Path -LiteralPath $OutputPath) -and -not $Force -and $Action -eq 'GenerateScript') {
        $overwrite = Read-Host "[?] File '$OutputPath' already exists. Overwrite? [Y/T = Yes/Tak, N = No/Nie]"
        if ($overwrite -notmatch '^(Y|y|T|t|Yes|yes|Tak|tak)$') {
            Write-ScriptLog -Level WARN -Message "Generation of '$OutputPath' cancelled by user."
            exit 0
        }
    }

    $parentDir = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
    }

    Set-Content -LiteralPath $OutputPath -Value $scriptContent -Encoding UTF8 -Force
    $resolvedOut = (Resolve-Path -LiteralPath $OutputPath).Path
    Write-ScriptLog -Level SUCCESS -Message "Generated PowerShell Logon Script: $resolvedOut"

    return [PSCustomObject]@{
        Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Step        = "Step1-GenerateLogonScript"
        Environment = $script:NormalizedMode
        Target      = $resolvedOut
        Status      = "Completed"
        Details     = "Generated LogonScript.ps1 ($normalizedDriveRoot -> $NetworkPath, Log: $StatusLogPath)"
    }
}

# ==============================================================================
# WORKFLOW 2: EXECUTE USER LOGON SCRIPT (Step 1 Runtime Execution)
# ==============================================================================
function Invoke-UserLogonExecution {
    $results = New-Object System.Collections.Generic.List[object]

    Write-Progress -Id 1 -Activity "Executing PowerShell User Logon Script" -Status "Step 1/3: Validating user & group requirements..." -PercentComplete 20
    Write-ScriptLog -Level STEP -Message "Executing User Logon Script workflow (Drive: '$normalizedDriveRoot' -> '$NetworkPath', Mode: '$script:NormalizedMode')..."

    # Optional group membership check in Local AD and/or Cloud Entra ID
    $allowedToMap = $true
    if (-not [string]::IsNullOrWhiteSpace($RequiredGroup)) {
        if ($script:NormalizedMode -eq 'Local' -or $script:NormalizedMode -eq 'Both') {
            $localMember = Test-LocalADGroupMembership -GroupName $RequiredGroup
            if (-not $localMember -and $script:NormalizedMode -eq 'Local') {
                $allowedToMap = $false
            }
        }
        if ($script:NormalizedMode -eq 'Cloud' -or $script:NormalizedMode -eq 'Both') {
            $cloudMember = Test-CloudEntraGroupMembership -GroupName $RequiredGroup -TargetUpn $UserPrincipalName
            if (-not $cloudMember -and $script:NormalizedMode -eq 'Cloud') {
                $allowedToMap = $false
            }
        }
    } elseif ($script:NormalizedMode -eq 'Cloud' -or $script:NormalizedMode -eq 'Both') {
        # Verify cloud identity in Cloud mode even if no specific group filter was requested
        [void](Test-CloudEntraGroupMembership -GroupName "" -TargetUpn $UserPrincipalName)
    }

    if (-not $allowedToMap) {
        $msg = "User '$env:USERDOMAIN\$env:USERNAME' does not belong to required group '$RequiredGroup'. Skipping drive mapping for '$normalizedDriveRoot'."
        Write-ScriptLog -Level WARN -Message $msg
        $results.Add([PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Step        = "Logon-GroupCheck"
            Environment = $script:NormalizedMode
            Target      = "$normalizedDriveRoot -> $NetworkPath"
            Status      = "SkippedByGroupFilter"
            Details     = $msg
        })
        Write-Progress -Id 1 -Activity "Executing PowerShell User Logon Script" -Completed
        return $results
    }

    # Step 2/3: Check if drive is already mapped and map using New-PSDrive -Persist
    Write-Progress -Id 1 -Activity "Executing PowerShell User Logon Script" -Status "Step 2/3: Mapping network drive $normalizedDriveRoot -> $NetworkPath..." -PercentComplete 60

    $driveExists = Test-Path -LiteralPath $normalizedDriveRoot
    $mapStatus   = "Pending"
    $mapDetails  = ""

    if ($driveExists -and -not $Force) {
        $mapStatus  = "AlreadyMapped"
        $mapDetails = "Drive '$normalizedDriveRoot' is already mapped on '$env:COMPUTERNAME'. (Use -Force to remap)."
        Write-ScriptLog -Level INFO -Message $mapDetails
    } elseif ($DryRun -or -not $PSCmdlet.ShouldProcess("$normalizedDriveRoot -> $NetworkPath", "New-PSDrive -Persist")) {
        $mapStatus  = "Simulated"
        $mapDetails = "[DRY-RUN] Would map persistent network drive '$normalizedDriveRoot' to '$NetworkPath'."
        Write-ScriptLog -Level INFO -Message $mapDetails
    } else {
        try {
            if ($driveExists -and $Force) {
                Write-ScriptLog -Level INFO -Message "Removing existing drive mapping '$normalizedDriveRoot' (-Force specified)..."
                Remove-PSDrive -Name $normalizedDriveName -Force -ErrorAction SilentlyContinue
                & net.exe use $normalizedDriveRoot /delete /y 2>&1 | Out-Null
            }

            $psDriveParams = @{
                Name        = $normalizedDriveName
                PSProvider  = 'FileSystem'
                Root        = $NetworkPath
                Persist     = $true
                Scope       = 'Global'
                ErrorAction = 'Stop'
            }
            if ($null -ne $Credential) {
                $psDriveParams['Credential'] = $Credential
            }

            New-PSDrive @psDriveParams | Out-Null
            $mapStatus  = "Mapped"
            $mapDetails = "Successfully mapped persistent network drive '$normalizedDriveRoot' to '$NetworkPath'."
            Write-ScriptLog -Level SUCCESS -Message $mapDetails
        } catch {
            $mapStatus  = "Failed"
            $mapDetails = "Failed to map network drive '$normalizedDriveRoot' to '$NetworkPath': $($_.Exception.Message)"
            Write-ScriptLog -Level ERROR -Message $mapDetails
        }
    }

    $results.Add([PSCustomObject]@{
        Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Step        = "Logon-MapNetworkDrive"
        Environment = $script:NormalizedMode
        Target      = "$normalizedDriveRoot -> $NetworkPath"
        Status      = $mapStatus
        Details     = $mapDetails
    })

    # Step 3/3: Write verification entry to local logon log (C:\Temp\LogonStatus.txt)
    Write-Progress -Id 1 -Activity "Executing PowerShell User Logon Script" -Status "Step 3/3: Recording logon status to $StatusLogPath..." -PercentComplete 90

    $statusParent = Split-Path -Path $StatusLogPath -Parent
    $logEntryLine = "Zalogowano pomyślnie dnia $(Get-Date)"

    if ($DryRun) {
        Write-ScriptLog -Level INFO -Message "[DRY-RUN] Would append '$logEntryLine' to '$StatusLogPath'."
        $results.Add([PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Step        = "Logon-WriteStatusLog"
            Environment = $script:NormalizedMode
            Target      = $StatusLogPath
            Status      = "Simulated"
            Details     = "[DRY-RUN] Would write '$logEntryLine'"
        })
    } else {
        try {
            if (-not [string]::IsNullOrWhiteSpace($statusParent) -and -not (Test-Path -LiteralPath $statusParent)) {
                New-Item -ItemType Directory -Path $statusParent -Force | Out-Null
            }
            $logEntryLine | Out-File -Append -FilePath $StatusLogPath -Encoding UTF8 -ErrorAction Stop
            Write-ScriptLog -Level SUCCESS -Message "Weryfikacja sukcesu: Zapisano '$logEntryLine' do pliku '$StatusLogPath'."
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Logon-WriteStatusLog"
                Environment = $script:NormalizedMode
                Target      = $StatusLogPath
                Status      = "Logged"
                Details     = $logEntryLine
            })
        } catch {
            Write-ScriptLog -Level ERROR -Message "Failed to write logon status to '$StatusLogPath': $($_.Exception.Message)"
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Logon-WriteStatusLog"
                Environment = $script:NormalizedMode
                Target      = $StatusLogPath
                Status      = "Failed"
                Details     = $_.Exception.Message
            })
        }
    }

    Write-Progress -Id 1 -Activity "Executing PowerShell User Logon Script" -Completed
    return $results
}

# ==============================================================================
# WORKFLOW 3: DEPLOY LOGON SCRIPT TO SYSVOL & CONFIGURE GPO / CLOUD (Steps 2 & 3)
# ==============================================================================
function Invoke-DeployLogonScriptAndPolicy {
    $results = New-Object System.Collections.Generic.List[object]

    # Confirmation prompt unless -Force or -DryRun
    if (-not $Force -and -not $DryRun) {
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor Yellow
        Write-Host "  CONFIRMATION REQUIRED / WYMAGANE POTWIERDZENIE (GPO / SYSVOL DEPLOYMENT)" -ForegroundColor Yellow
        Write-Host "  Directory Mode          : $script:NormalizedMode" -ForegroundColor White
        Write-Host "  GPO / Policy Name       : $GpoName" -ForegroundColor White
        Write-Host "  Target OU / Group       : $(if ($TargetOU) { $TargetOU } else { '(Not linked / Domain Root)' })" -ForegroundColor White
        Write-Host "  Network Drive Mapping   : $normalizedDriveRoot -> $NetworkPath" -ForegroundColor White
        Write-Host "  Configure ExecPolicy    : $ConfigureExecutionPolicy ($ExecutionPolicyLevel)" -ForegroundColor White
        Write-Host "================================================================================" -ForegroundColor Yellow
        $confirm = Read-Host "Do you want to proceed with deploying the Logon Script and Policy? [Y/T = Yes/Tak, N = No/Nie]"
        if ($confirm -notmatch '^(Y|y|T|t|Yes|yes|Tak|tak)$') {
            Write-ScriptLog -Level WARN -Message "Deployment cancelled by user at confirmation prompt."
            exit 0
        }
    }

    # Step 1: Ensure standalone LogonScript.ps1 exists
    $genResult = Invoke-GenerateLogonScriptFile -OutputPath $ScriptOutputPath
    $results.Add($genResult)
    $scriptFileName = [System.IO.Path]::GetFileName($ScriptOutputPath)

    # Local AD Deployment (SYSVOL + Group Policy Object)
    if ($script:NormalizedMode -eq 'Local' -or $script:NormalizedMode -eq 'Both') {
        Write-Progress -Id 2 -Activity "Deploying Logon Script to Local Active Directory" -Status "Step 2: Resolving domain SYSVOL share..." -PercentComplete 30

        # Resolve domain name
        $resolvedDomain = $DomainName
        if ([string]::IsNullOrWhiteSpace($resolvedDomain)) {
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $adDom = Get-ADDomain -ErrorAction Stop
                    $resolvedDomain = $adDom.DNSRoot
                } catch {}
            }
            if ([string]::IsNullOrWhiteSpace($resolvedDomain) -and -not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) {
                $resolvedDomain = $env:USERDNSDOMAIN
            }
        }

        if ([string]::IsNullOrWhiteSpace($resolvedDomain) -and [string]::IsNullOrWhiteSpace($SysvolScriptsPath)) {
            throw "Could not automatically detect Active Directory DNS domain name. Please specify -DomainName (e.g., 'twojadomena.local') or -SysvolScriptsPath."
        }

        $targetSysvolDir = if (-not [string]::IsNullOrWhiteSpace($SysvolScriptsPath)) {
            $SysvolScriptsPath.TrimEnd('\')
        } else {
            "\\$resolvedDomain\sysvol\$resolvedDomain\scripts"
        }
        $targetSysvolScriptPath = Join-Path -Path $targetSysvolDir -ChildPath $scriptFileName

        Write-ScriptLog -Level STEP -Message "Step 2: Copying '$scriptFileName' to SYSVOL share: $targetSysvolScriptPath"

        if ($DryRun) {
            Write-ScriptLog -Level INFO -Message "[DRY-RUN] Would copy '$ScriptOutputPath' to SYSVOL path '$targetSysvolScriptPath'."
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step2-CopyToSysvol"
                Environment = "LocalAD"
                Target      = $targetSysvolScriptPath
                Status      = "Simulated"
                Details     = "[DRY-RUN] Would copy script to SYSVOL share."
            })
        } else {
            if (-not (Test-Path -LiteralPath $targetSysvolDir)) {
                throw "SYSVOL scripts directory '$targetSysvolDir' is not accessible. Verify domain connectivity and permissions."
            }
            Copy-Item -LiteralPath $ScriptOutputPath -Destination $targetSysvolScriptPath -Force -ErrorAction Stop
            Write-ScriptLog -Level SUCCESS -Message "Copied '$scriptFileName' to SYSVOL: $targetSysvolScriptPath"
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step2-CopyToSysvol"
                Environment = "LocalAD"
                Target      = $targetSysvolScriptPath
                Status      = "Completed"
                Details     = "Verified UNC availability in SYSVOL."
            })
        }

        # Step 3: Create / Update GPO and configure PowerShell User Logon Script
        Write-Progress -Id 2 -Activity "Deploying Logon Script to Local Active Directory" -Status "Step 3: Configuring GPO '$GpoName'..." -PercentComplete 70
        Write-ScriptLog -Level STEP -Message "Step 3: Configuring Group Policy Object '$GpoName'..."

        if ($DryRun) {
            $ouText = if ($TargetOU) { $TargetOU } else { "(No OU specified)" }
            Write-ScriptLog -Level INFO -Message "[DRY-RUN] Would create/update GPO '$GpoName', assign PowerShell User Logon script '$scriptFileName', and link to OU '$ouText'."
            if ($ConfigureExecutionPolicy) {
                Write-ScriptLog -Level INFO -Message "[DRY-RUN] Would configure GPO PowerShell ExecutionPolicy to '$ExecutionPolicyLevel'."
            }
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step3-ConfigureGPO"
                Environment = "LocalAD"
                Target      = "$GpoName -> $ouText"
                Status      = "Simulated"
                Details     = "[DRY-RUN] Would configure GPO User Logon PowerShell script and link to OU."
            })
        } else {
            if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
                throw "GroupPolicy PowerShell module (GPMC / RSAT) is not installed. Install RSAT Group Policy Management Tools to automate GPO creation."
            }
            Import-Module GroupPolicy -ErrorAction Stop

            $gpParams = @{}
            if (-not [string]::IsNullOrWhiteSpace($resolvedDomain)) { $gpParams['Domain'] = $resolvedDomain }
            if (-not [string]::IsNullOrWhiteSpace($DomainController)) { $gpParams['Server'] = $DomainController }

            $gpoObj = Get-GPO -Name $GpoName @gpParams -ErrorAction SilentlyContinue
            if ($null -eq $gpoObj) {
                $gpoObj = New-GPO -Name $GpoName -Comment "PowerShell User Logon Script GPO managed by User-LogonScript.ps1" @gpParams -ErrorAction Stop
                Write-ScriptLog -Level SUCCESS -Message "Created new GPO '$GpoName' (ID: $($gpoObj.Id))."
            } else {
                Write-ScriptLog -Level INFO -Message "Using existing GPO '$GpoName' (ID: $($gpoObj.Id))."
            }

            # Configure User\Scripts\psscripts.ini inside GPO SYSVOL folder so GPMC registers the PowerShell Logon Script
            $gpoGuid = "{$($gpoObj.Id.ToString().ToUpperInvariant())}"
            $gpoUserScriptsDir = "\\$resolvedDomain\sysvol\$resolvedDomain\Policies\$gpoGuid\User\Scripts"
            $gpoUserLogonDir   = Join-Path -Path $gpoUserScriptsDir -ChildPath "Logon"
            if (-not (Test-Path -LiteralPath $gpoUserLogonDir)) {
                New-Item -Path $gpoUserLogonDir -ItemType Directory -Force | Out-Null
            }

            # Copy script also into GPO User\Scripts\Logon and write psscripts.ini
            Copy-Item -LiteralPath $ScriptOutputPath -Destination (Join-Path -Path $gpoUserLogonDir -ChildPath $scriptFileName) -Force
            $psScriptsIniPath = Join-Path -Path $gpoUserScriptsDir -ChildPath "psscripts.ini"
            $psScriptsIniContent = @"
[ScriptsConfig]
StartExecutePSFirst=true

[Logon]
0CmdLine=$targetSysvolScriptPath
0Parameters=
"@
            Set-Content -LiteralPath $psScriptsIniPath -Value $psScriptsIniContent -Encoding Unicode -Force
            Write-ScriptLog -Level SUCCESS -Message "Registered PowerShell User Logon script '$targetSysvolScriptPath' in GPO '$GpoName' (psscripts.ini)."

            # Optional: Configure PowerShell ExecutionPolicy inside GPO
            if ($ConfigureExecutionPolicy) {
                $execPolicyString = switch ($ExecutionPolicyLevel) {
                    'RemoteSigned' { ' Allow local scripts and remote signed scripts' }
                    'AllSigned'    { ' Allow only signed scripts' }
                    'Unrestricted' { ' Allow all scripts' }
                }
                Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell" `
                    -ValueName "EnableScripts" -Type DWord -Value 1 @gpParams -ErrorAction Stop | Out-Null
                Set-GPRegistryValue -Name $GpoName -Key "HKLM\Software\Policies\Microsoft\Windows\PowerShell" `
                    -ValueName "ExecutionPolicy" -Type String -Value $ExecutionPolicyLevel @gpParams -ErrorAction Stop | Out-Null
                Write-ScriptLog -Level SUCCESS -Message "Configured GPO PowerShell ExecutionPolicy: EnableScripts=1, ExecutionPolicy=$ExecutionPolicyLevel."
            }

            # Link GPO to TargetOU if provided
            if (-not [string]::IsNullOrWhiteSpace($TargetOU)) {
                try {
                    New-GPLink -Name $GpoName -Target $TargetOU -LinkEnabled Yes @gpParams -ErrorAction Stop | Out-Null
                    Write-ScriptLog -Level SUCCESS -Message "Linked GPO '$GpoName' to Organizational Unit: $TargetOU"
                } catch {
                    if ($_.Exception.Message -match 'already linked') {
                        Write-ScriptLog -Level INFO -Message "GPO '$GpoName' is already linked to '$TargetOU'."
                    } else {
                        throw $_
                    }
                }
            }

            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step3-ConfigureGPO"
                Environment = "LocalAD"
                Target      = "$GpoName ($gpoGuid)"
                Status      = "Completed"
                Details     = "Configured PowerShell User Logon Script '$targetSysvolScriptPath'$(if ($TargetOU) { " and linked to $TargetOU" })."
            })
        }
        Write-Progress -Id 2 -Activity "Deploying Logon Script to Local Active Directory" -Completed
    }

    # Cloud Entra ID / Microsoft Intune Deployment
    if ($script:NormalizedMode -eq 'Cloud' -or $script:NormalizedMode -eq 'Both') {
        Write-Progress -Id 3 -Activity "Deploying Logon Script to Cloud (Microsoft Entra ID / Intune)" -Status "Uploading PowerShell script to Microsoft Graph..." -PercentComplete 50
        Write-ScriptLog -Level STEP -Message "[Cloud Entra ID] Deploying User Logon PowerShell script '$GpoName' to Microsoft Intune / Entra ID..."

        if ($DryRun) {
            Write-ScriptLog -Level INFO -Message "[DRY-RUN] Would upload '$ScriptOutputPath' to Microsoft Graph (deviceManagementScripts, runAsAccount='user') as '$GpoName'."
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step3-CloudIntuneDeploy"
                Environment = "CloudEntraID"
                Target      = $GpoName
                Status      = "Simulated"
                Details     = "[DRY-RUN] Would deploy cloud logon script via Microsoft Graph API."
            })
        } else {
            Connect-EntraIDDirectory
            $rawBytes  = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $ScriptOutputPath).Path)
            $base64Str = [Convert]::ToBase64String($rawBytes)

            $intunePayload = @{
                displayName           = $GpoName
                description           = "Cloud User Logon Script ($normalizedDriveRoot -> $NetworkPath) deployed by User-LogonScript.ps1"
                scriptContent         = $base64Str
                runAsAccount          = "user"
                enforceSignatureCheck = $false
                runAs32Bit            = $false
                fileName              = $scriptFileName
            } | ConvertTo-Json -Depth 5

            $intuneUri = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts"
            $createdScript = Invoke-MgGraphRequest -Method POST -Uri $intuneUri -Body $intunePayload -ContentType "application/json" -ErrorAction Stop
            Write-ScriptLog -Level SUCCESS -Message "[Cloud Entra ID] Deployed Cloud User Logon Script '$GpoName' (ScriptId: $($createdScript.id))."

            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step3-CloudIntuneDeploy"
                Environment = "CloudEntraID"
                Target      = "$GpoName ($($createdScript.id))"
                Status      = "Completed"
                Details     = "Uploaded user-context PowerShell logon script to Microsoft Intune / Entra ID."
            })
        }
        Write-Progress -Id 3 -Activity "Deploying Logon Script to Cloud (Microsoft Entra ID / Intune)" -Completed
    }

    return $results
}

# ==============================================================================
# WORKFLOW 4: VERIFY LOGON SCRIPT, MAPPED DRIVE, STATUS LOG & GPO (Step 4)
# ==============================================================================
function Invoke-VerifyLogonConfiguration {
    $results = New-Object System.Collections.Generic.List[object]
    Write-ScriptLog -Level STEP -Message "Step 4: Verifying User Logon Script execution and environment status..."

    # 1. Optional gpupdate /force
    if ($RunGpUpdate) {
        if ($DryRun) {
            Write-ScriptLog -Level INFO -Message "[DRY-RUN] Would run 'gpupdate /force' to refresh Group Policy."
        } else {
            Write-ScriptLog -Level STEP -Message "Running 'gpupdate /force' to refresh Group Policy..."
            $gpOut = & gpupdate.exe /force 2>&1
            Write-ScriptLog -Level SUCCESS -Message "Completed 'gpupdate /force'."
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step4-GpUpdateForce"
                Environment = $script:NormalizedMode
                Target      = "gpupdate /force"
                Status      = "Completed"
                Details     = ($gpOut | Out-String).Trim()
            })
        }
    }

    # 2. Verify mapped drive (e.g. Z:)
    $drivePresent = Test-Path -LiteralPath $normalizedDriveRoot
    if ($drivePresent) {
        Write-ScriptLog -Level SUCCESS -Message "Verification [Drive '$normalizedDriveRoot']: PRESENT and accessible."
        $results.Add([PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Step        = "Step4-VerifyMappedDrive"
            Environment = $script:NormalizedMode
            Target      = $normalizedDriveRoot
            Status      = "Verified"
            Details     = "Network drive '$normalizedDriveRoot' is mapped and reachable."
        })
    } else {
        Write-ScriptLog -Level WARN -Message "Verification [Drive '$normalizedDriveRoot']: NOT MAPPED in current session."
        $results.Add([PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Step        = "Step4-VerifyMappedDrive"
            Environment = $script:NormalizedMode
            Target      = $normalizedDriveRoot
            Status      = "NotMapped"
            Details     = "Drive '$normalizedDriveRoot' is not currently mapped."
        })
    }

    # 3. Verify local logon status log (C:\Temp\LogonStatus.txt)
    if (Test-Path -LiteralPath $StatusLogPath) {
        $lastEntry = Get-Content -LiteralPath $StatusLogPath -Tail 1 -Encoding UTF8 -ErrorAction SilentlyContinue
        Write-ScriptLog -Level SUCCESS -Message "Verification [Status Log '$StatusLogPath']: PRESENT. Last entry: '$lastEntry'"
        $results.Add([PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Step        = "Step4-VerifyStatusLog"
            Environment = $script:NormalizedMode
            Target      = $StatusLogPath
            Status      = "Verified"
            Details     = "Last log entry: $lastEntry"
        })
    } else {
        Write-ScriptLog -Level WARN -Message "Verification [Status Log '$StatusLogPath']: File does not exist yet."
        $results.Add([PSCustomObject]@{
            Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Step        = "Step4-VerifyStatusLog"
            Environment = $script:NormalizedMode
            Target      = $StatusLogPath
            Status      = "Missing"
            Details     = "Status log '$StatusLogPath' was not found."
        })
    }

    # 4. Verify SYSVOL UNC script availability if DomainName or SysvolScriptsPath is provided
    $checkDomain = if (-not [string]::IsNullOrWhiteSpace($DomainName)) { $DomainName } elseif (-not [string]::IsNullOrWhiteSpace($env:USERDNSDOMAIN)) { $env:USERDNSDOMAIN } else { $null }
    if (-not [string]::IsNullOrWhiteSpace($SysvolScriptsPath) -or -not [string]::IsNullOrWhiteSpace($checkDomain)) {
        $sysvolDir = if (-not [string]::IsNullOrWhiteSpace($SysvolScriptsPath)) { $SysvolScriptsPath.TrimEnd('\') } else { "\\$checkDomain\sysvol\$checkDomain\scripts" }
        $scriptName = [System.IO.Path]::GetFileName($ScriptOutputPath)
        $sysvolUnc  = Join-Path -Path $sysvolDir -ChildPath $scriptName

        if (Test-Path -LiteralPath $sysvolUnc) {
            Write-ScriptLog -Level SUCCESS -Message "Verification [SYSVOL UNC '$sysvolUnc']: ACCESSIBLE."
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step4-VerifySysvolUNC"
                Environment = "LocalAD"
                Target      = $sysvolUnc
                Status      = "Verified"
                Details     = "SYSVOL script UNC path is reachable."
            })
        } else {
            Write-ScriptLog -Level WARN -Message "Verification [SYSVOL UNC '$sysvolUnc']: Not found or unreachable."
            $results.Add([PSCustomObject]@{
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Step        = "Step4-VerifySysvolUNC"
                Environment = "LocalAD"
                Target      = $sysvolUnc
                Status      = "NotFound"
                Details     = "SYSVOL script path '$sysvolUnc' was not found."
            })
        }
    }

    return $results
}

# ==============================================================================
# MAIN EXECUTION ORCHESTRATOR
# ==============================================================================
$allResults = New-Object System.Collections.Generic.List[object]
$startTime  = Get-Date

try {
    switch ($Action) {
        'GenerateScript' {
            $res = Invoke-GenerateLogonScriptFile -OutputPath $ScriptOutputPath
            $allResults.Add($res)
        }
        'DeployGPO' {
            $deployRes = Invoke-DeployLogonScriptAndPolicy
            foreach ($r in $deployRes) { $allResults.Add($r) }
        }
        'Verify' {
            $verifyRes = Invoke-VerifyLogonConfiguration
            foreach ($r in $verifyRes) { $allResults.Add($r) }
        }
        default {
            # ExecuteLogon
            $execRes = Invoke-UserLogonExecution
            foreach ($r in $execRes) { $allResults.Add($r) }
        }
    }
} catch {
    Write-ScriptLog -Level ERROR -Message "Fatal execution error: $($_.Exception.Message)"
    exit 1
}

$duration = (Get-Date) - $startTime

Write-Host ""
Write-ScriptLog -Level STEP -Message "================================================================================"
Write-ScriptLog -Level INFO -Message "EXECUTION SUMMARY ($script:ScriptName v$script:ScriptVersion)"
Write-ScriptLog -Level STEP -Message "================================================================================"
Write-ScriptLog -Level INFO -Message "  Action Performed    : $Action"
Write-ScriptLog -Level INFO -Message "  Directory Mode      : $script:NormalizedMode"
Write-ScriptLog -Level INFO -Message "  Drive Mapping       : $normalizedDriveRoot -> $NetworkPath"
Write-ScriptLog -Level INFO -Message "  Status File         : $StatusLogPath"
Write-ScriptLog -Level INFO -Message "  Steps Processed     : $($allResults.Count)"
Write-ScriptLog -Level INFO -Message "  Elapsed Time        : $($duration.ToString('hh\:mm\:ss\.fff'))"
if ($script:ActiveLogFile) {
    Write-ScriptLog -Level INFO -Message "  Audit Log Saved To  : $script:ActiveLogFile"
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
