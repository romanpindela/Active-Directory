<#
================================================================================
  Script Name : Reset-UserPassword.ps1
  Author      : Roman Pindela
  Contact     : roman.pindela@gmail.com
  Version     : 1.2.0
  Release Date: 2026-10-17
  License     : MIT
  Repository  : https://github.com/romanpindela

  DESCRIPTION:
    Enterprise-grade PowerShell emergency password reset script for IT
    Administrators and Helpdesk teams when a user forgets their password and
    requests an immediate temporary password reset.

    Supports both:
    - Local Mode (Local / AD / LocalAD / OnPremises):
      Windows Server Active Directory Domain Services (via ActiveDirectory module:
      Set-ADAccountPassword -Identity $Login -NewPassword $NoweHaslo -Reset $true
      and Set-ADUser -Identity $Login -ChangePasswordAtLogon $true)
    - Cloud Mode (Cloud / EntraID / CloudAD / AzureAD):
      Microsoft Entra ID cloud directory (via Microsoft Graph PowerShell SDK:
      Update-MgUser -PasswordProfile @{ Password = ...; ForceChangePasswordNextSignIn = $true },
      supporting both interactive administrator sign-in and unattended App-Only
      authentication using Client Secret or X.509 Certificate)
    - Hybrid Mode (Both):
      Resets the user's password across both Local Active Directory and Cloud
      Microsoft Entra ID in a single execution.

    Key Capabilities:
    1. Zero-Parameter Interactive Help (-Help / -h):
       Displays complete usage instructions, examples, Entra ID non-interactive
       setup guide, script version, and author details when launched without
       parameters.
    2. Interactive & Parameterized Execution:
       Can prompt interactively via Read-Host for the user login (SamAccountName)
       and SecureString temporary password (-Interactive), or accept parameters
       (-Login, -NewPassword, -PlainTextPassword, -GenerateRandomPassword).
    3. Mandatory Password Change at Next Logon:
       Enforces ChangePasswordAtLogon ($true by default) in Local AD and
       ForceChangePasswordNextSignIn ($true by default) in Cloud Entra ID, with
       optional account unlocking (-UnlockAccount).
    4. Input Sanitization & Defensive Validation:
       Protects against malicious input, command injection, LDAP filter injection
       (RFC 4515), and OData filter injection without ever logging plaintext
       passwords to disk.
    5. Language-Independent UAC Auto-Elevation:
       Verifies Administrator privileges via well-known Windows SID
       (S-1-5-32-544 / BuiltInAdministratorsSid) for full compatibility across
       Polish ("Administratorzy") and English ("Administrators") Windows systems.
    6. Real-Time Granular Progress Bar (Write-Progress) & Audit Logging:
       Displays live progress steps and writes UTF-8 timestamped execution logs to:
       C:\Logs\<yyyyMMdd_HHmmss>-Reset-UserPassword-<ComputerName>-<UserName>.logs
================================================================================
.SYNOPSIS
    Resets the password of a selected user account and forces a password change
    at next logon in Local Active Directory (AD DS) and/or Cloud Microsoft Entra ID.

.DESCRIPTION
    Primary emergency / rescue script used when a domain or cloud user forgets
    their password and requests an immediate reset from an administrator.

    In Local Active Directory mode, executes:
      Set-ADAccountPassword -Identity $Login -NewPassword $NoweHaslo -Reset $true
      Set-ADUser -Identity $Login -ChangePasswordAtLogon $true
      Write-Host "Hasło dla użytkownika $Login zostało zresetowane." -ForegroundColor Cyan

    In Cloud Microsoft Entra ID mode, executes Microsoft Graph SDK password profile
    updates (Update-MgUser -PasswordProfile) with ForceChangePasswordNextSignIn = $true.

.PARAMETER Login
    User login (SamAccountName, UserPrincipalName, DistinguishedName, Mail, or
    ObjectId) of the account whose password will be reset.
    If omitted when -Interactive is used, the script prompts via:
      Read-Host "Podaj login użytkownika (SamAccountName)"
    Aliases: -Identity, -SamAccountName, -UserPrincipalName, -User, -Username, -u

.PARAMETER NewPassword
    The new temporary password as a SecureString.
    If neither -NewPassword, -PlainTextPassword, nor -GenerateRandomPassword is
    provided, the script securely prompts interactively via:
      Read-Host -AsSecureString "Podaj nowe tymczasowe hasło"
    Aliases: -Password, -NoweHaslo, -SecurePassword

.PARAMETER PlainTextPassword
    Optional plain-text string for the new temporary password (useful in automated
    CLI pipelines; automatically converted to SecureString in memory and never
    written to log files).
    Aliases: -PasswordPlain, -TempPassword

.PARAMETER Interactive
    Switch parameter. Launches the classic interactive rescue flow that prompts
    the administrator for the user login (if not already provided) and the new
    temporary password via Read-Host / Read-Host -AsSecureString.
    Aliases: -Prompt, -RunInteractive

.PARAMETER GenerateRandomPassword
    Switch parameter. Automatically generates a cryptographically strong temporary
    password meeting Active Directory and Microsoft Entra ID complexity requirements
    and displays it once on the console.
    Aliases: -RandomPassword, -AutoPassword

.PARAMETER PasswordLength
    Length of the auto-generated temporary password when -GenerateRandomPassword
    is used. Valid range: 12 to 64. Default: 16.

.PARAMETER Mode
    Target directory environment mode:
      - 'Local'   (or 'AD', 'LocalAD', 'OnPremises')   : Local Active Directory Domain Services (Default).
      - 'Cloud'   (or 'EntraID', 'CloudAD', 'AzureAD') : Microsoft Entra ID cloud directory via Graph SDK.
      - 'Both'                                         : Resets password in both Local AD and Cloud Entra ID.
    Aliases: -Provider, -Environment, -Target, -Directory

.PARAMETER ChangePasswordAtLogon
    Enforces password change at the user's next sign-in. Enabled ($true) by default.

.PARAMETER NoChangePasswordAtLogon
    Switch parameter. If specified, does NOT require the user to change their
    password at next logon.

.PARAMETER UnlockAccount
    Switch parameter. Also unlocks the user account in Local Active Directory
    (Unlock-ADAccount) if it was locked out due to failed logon attempts.
    Aliases: -Unlock

.PARAMETER UpnSuffix
    Optional UPN domain suffix (e.g., "firma.pl" or "contoso.com"). In Cloud
    (Entra ID) mode, if a short SamAccountName without '@domain' is supplied
    (e.g., "jkowalski"), this suffix is appended ("jkowalski@firma.pl") to resolve
    the cloud account.
    Aliases: -Domain, -DomainSuffix

.PARAMETER DomainController
    Optional specific Active Directory Domain Controller FQDN or IP address to
    target in Local AD mode.
    Aliases: -Server, -DC

.PARAMETER Credential
    Optional PSCredential object for authenticating against Local Active Directory.

.PARAMETER ExportReportPath
    Optional file path to export a UTF-8 CSV audit report of the password reset
    operation (never includes the password itself).
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
    Optional administrator UPN hint for interactive Microsoft Graph sign-in.
    Aliases: -AdminUPN

.PARAMETER DryRun
    Switch parameter. Simulates resolving the user account and resetting the
    password without modifying Active Directory or Microsoft Entra ID.
    Aliases: -Simulate, -Preview

.PARAMETER SkipAdminCheck
    Switch parameter. Skips automatic UAC Administrator privilege elevation check.

.PARAMETER PassThru
    Switch parameter. Outputs structured password reset audit result objects to
    the PowerShell pipeline.

.PARAMETER LogPath
    Custom path for the execution log file.
    Default: C:\Logs\<yyyyMMdd_HHmmss>-Reset-UserPassword-<ComputerName>-<UserName>.logs
    Aliases: -l, -Log

.PARAMETER NoLog
    Switch parameter. Disables writing execution logs to disk.

.PARAMETER Force
    Switch parameter. Bypasses interactive confirmation prompts (Y/N / T/N) for
    rapid emergency or automated execution.

.PARAMETER Help
    Displays detailed script help, examples, Entra ID non-interactive configuration
    guide, version, and author information.
    Aliases: -h

.EXAMPLE
    .\Reset-UserPassword.ps1
    Displays the built-in help screen, usage examples, version, and author info.

.EXAMPLE
    .\Reset-UserPassword.ps1 -Interactive
    Prompts interactively for the user login ("Podaj login użytkownika (SamAccountName)")
    and the new temporary password ("Podaj nowe tymczasowe hasło"), resets the password
    in Local Active Directory, forces password change at next logon, and displays:
    "Hasło dla użytkownika <Login> zostało zresetowane."

.EXAMPLE
    .\Reset-UserPassword.ps1 -Login "jkowalski"
    Prompts securely for the new temporary password for user "jkowalski", resets the
    password in Local Active Directory, and forces change at first logon.

.EXAMPLE
    .\Reset-UserPassword.ps1 -Login "jkowalski" -GenerateRandomPassword -UnlockAccount -Force
    Generates a strong temporary password, resets the password for "jkowalski" in Local AD,
    forces password change at next logon, and unlocks the account without confirmation prompts.

.EXAMPLE
    .\Reset-UserPassword.ps1 -Login "jkowalski@firma.pl" -Mode Cloud
    Prompts for the new temporary password and resets the user's password in Cloud
    Microsoft Entra ID using interactive Microsoft Graph administrator sign-in.

.EXAMPLE
    .\Reset-UserPassword.ps1 -Login "jkowalski" -Mode Cloud -UpnSuffix "firma.pl" `
        -GenerateRandomPassword `
        -TenantId "11111111-2222-3333-4444-555555555555" `
        -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
        -ClientSecret "YourClientSecretValue" -Force
    Resets the user's password in Cloud Microsoft Entra ID non-interactively (unattended
    App-Only mode) using an Entra ID App Registration and Client Secret.

.EXAMPLE
    .\Reset-UserPassword.ps1 -Login "jkowalski" -Mode Both -UpnSuffix "firma.pl" -Interactive
    Prompts for the temporary password and resets it simultaneously in both Local
    Active Directory and Cloud Microsoft Entra ID.

.NOTES
    Author  : Roman Pindela
    Email   : roman.pindela@gmail.com
    GitHub  : https://github.com/romanpindela
    Version : 1.2.0
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'ResetPassword')]
param(
    [Parameter(ParameterSetName = 'ResetPassword', Mandatory = $false, Position = 0)]
    [Alias('Identity', 'SamAccountName', 'UserPrincipalName', 'User', 'Username', 'u')]
    [string]$Login,

    [Parameter(ParameterSetName = 'ResetPassword', Mandatory = $false, Position = 1)]
    [Alias('Password', 'NoweHaslo', 'SecurePassword')]
    [System.Security.SecureString]$NewPassword,

    [Parameter(ParameterSetName = 'ResetPassword', Mandatory = $false)]
    [Alias('PasswordPlain', 'TempPassword')]
    [string]$PlainTextPassword,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Prompt', 'RunInteractive')]
    [switch]$Interactive,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('RandomPassword', 'AutoPassword')]
    [switch]$GenerateRandomPassword,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [ValidateRange(12, 64)]
    [int]$PasswordLength = 16,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Provider', 'Environment', 'Target', 'Directory')]
    [ValidateSet('Local', 'AD', 'LocalAD', 'OnPremises', 'Cloud', 'EntraID', 'CloudAD', 'AzureAD', 'Both')]
    [string]$Mode = 'Local',

    [Parameter(ParameterSetName = 'ResetPassword')]
    [bool]$ChangePasswordAtLogon = $true,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [switch]$NoChangePasswordAtLogon,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Unlock')]
    [switch]$UnlockAccount,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Domain', 'DomainSuffix')]
    [string]$UpnSuffix,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Server', 'DC')]
    [string]$DomainController,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('ExportCsv', 'ReportPath')]
    [string]$ExportReportPath,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Tenant', 'DirectoryId')]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('AppId', 'ApplicationId')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Secret')]
    [string]$ClientSecret,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [System.Security.SecureString]$ClientSecretSecure,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Thumbprint')]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('AdminUPN')]
    [string]$AdminUserPrincipalName,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('Simulate', 'Preview')]
    [switch]$DryRun,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [switch]$SkipAdminCheck,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [switch]$PassThru,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [Alias('l', 'Log')]
    [string]$LogPath,

    [Parameter(ParameterSetName = 'ResetPassword')]
    [switch]$NoLog,

    [Parameter(ParameterSetName = 'ResetPassword')]
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
$script:ScriptName    = "Reset-UserPassword"
$script:ScriptVersion = "1.2.0"
$script:ScriptDate    = "2026-10-17"
$script:ScriptAuthor  = "Roman Pindela"
$script:ScriptEmail   = "roman.pindela@gmail.com"
$script:ScriptGitHub  = "https://github.com/romanpindela"
$script:ActiveLogFile = $null
$script:AuthMode      = "Interactive"

# Normalize Mode ('Local'/'AD'/'LocalAD'/'OnPremises' -> 'Local', 'Cloud'/'EntraID'/'CloudAD'/'AzureAD' -> 'Cloud', 'Both' -> 'Both')
$script:NormalizedMode = switch ($Mode.ToUpperInvariant()) {
    'LOCAL'      { 'Local' }
    'AD'         { 'Local' }
    'LOCALAD'    { 'Local' }
    'ONPREMISES' { 'Local' }
    'CLOUD'      { 'Cloud' }
    'ENTRAID'    { 'Cloud' }
    'CLOUDAD'    { 'Cloud' }
    'AZUREAD'    { 'Cloud' }
    'BOTH'       { 'Both' }
    default      { 'Local' }
}

if ($NoChangePasswordAtLogon) {
    $ChangePasswordAtLogon = $false
}

# ==============================================================================
# HELP & DOCUMENTATION DISPLAY (-Help / -h / Zero-Parameters)
# ==============================================================================
function Show-ScriptHelp {
    $helpText = @"
================================================================================
  SCRIPT  : Reset-UserPassword.ps1
  VERSION : $script:ScriptVersion ($script:ScriptDate)
  AUTHOR  : $script:ScriptAuthor
  CONTACT : $script:ScriptEmail | $script:ScriptGitHub
================================================================================

DESCRIPTION:
    Primary emergency / rescue PowerShell utility for IT Administrators when a
    user forgets their password and requests an immediate password reset.
    Resets the selected user's password to a temporary password and enforces
    a mandatory password change at first logon.

    Core Local Active Directory Workflow:
      `$Login = Read-Host "Podaj login użytkownika (SamAccountName)"
      `$NoweHaslo = Read-Host -AsSecureString "Podaj nowe tymczasowe hasło"
      Set-ADAccountPassword -Identity `$Login -NewPassword `$NoweHaslo -Reset `$true
      Set-ADUser -Identity `$Login -ChangePasswordAtLogon `$true
      Write-Host "Hasło dla użytkownika `$Login zostało zresetowane." -ForegroundColor Cyan

    Supports three operational directory modes (-Mode / -Provider):
      1. Local (AD / LocalAD / OnPremises) : Local Active Directory Domain Services
                                             (via ActiveDirectory module:
                                             Set-ADAccountPassword & Set-ADUser).
      2. Cloud (EntraID / CloudAD / Cloud) : Microsoft Entra ID / Azure AD cloud
                                             directory (via Microsoft Graph SDK:
                                             Update-MgUser -PasswordProfile).
      3. Both                              : Resets the user's password across
                                             both Local AD and Cloud Entra ID.

--------------------------------------------------------------------------------
HOW TO CONFIGURE ENTRA ID FOR NON-INTERACTIVE / UNATTENDED AUTHENTICATION:
(Only via API Keys / Credentials and Entra ID Microsoft Graph SDK Permissions)
--------------------------------------------------------------------------------
To run this script in unattended / non-interactive Cloud mode against Microsoft
Entra ID (e.g., Helpdesk portals, self-service workflows, or automation pipelines)
without any interactive browser prompts:

Step 1: Register an Application in Microsoft Entra ID
    1. Sign in to the Microsoft Entra admin center (https://entra.microsoft.com).
    2. Navigate to: Identity > Applications > App registrations > New registration.
    3. Name: 'AD-Password-Reset-Automation'.
    4. Supported account types: 'Accounts in this organizational directory only'.
    5. Click 'Register' and copy:
       - Application (client) ID  -> pass to -ClientId
       - Directory (tenant) ID    -> pass to -TenantId

Step 2: Grant Microsoft Graph API Application Permissions & Directory Role
    1. In the App Registration, go to: Manage > API permissions > Add a permission.
    2. Select 'Microsoft Graph' > 'Application permissions' (NOT Delegated).
    3. Search for and check the following permissions:
       * UserAuthenticationMethod.ReadWrite.All  (Recommended for password reset)
       * User.ReadWrite.All                      (Required to update PasswordProfile)
       * Directory.Read.All                      (Required to resolve user attributes)
    4. Click 'Add permissions' and click 'Grant admin consent for <Your Tenant>'.
    5. IMPORTANT (Entra ID Role Requirement for App-Only Password Reset):
       In Microsoft Entra admin center, navigate to:
       Identity > Roles & admins > Roles & admins > select 'User Administrator'
       (or 'Helpdesk Administrator' / 'Authentication Administrator' / 'Privileged
       Authentication Administrator') > Add assignments > search for and select your
       App Registration ('AD-Password-Reset-Automation') > Add.

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
         `$cert = New-SelfSignedCertificate -Subject 'CN=EntraPasswordResetAutomation' ``
             -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable ``
             -KeySpec Signature -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
         Export-Certificate -Cert `$cert -FilePath 'C:\Logs\EntraPasswordResetAutomation.cer'
      2. In Entra Admin Center: Manage > Certificates & secrets > Certificates > Upload certificate.
         Upload 'EntraPasswordResetAutomation.cer'.
      3. Pass directly to this script:
         -Mode Cloud -TenantId '<TenantId>' -ClientId '<ClientId>' -CertificateThumbprint `$cert.Thumbprint

--------------------------------------------------------------------------------
USAGE EXAMPLES:
--------------------------------------------------------------------------------
  # 1. Interactive rescue mode in Local AD (prompts for Login and SecureString Password):
  .\Reset-UserPassword.ps1 -Interactive

  # 2. Reset password for a specific Local AD user (prompts securely for password):
  .\Reset-UserPassword.ps1 -Login "jkowalski"

  # 3. Reset Local AD user password with auto-generated strong password & account unlock:
  .\Reset-UserPassword.ps1 -Login "jkowalski" -GenerateRandomPassword -UnlockAccount -Force

  # 4. Preview / Dry-Run simulation without changing the user's password:
  .\Reset-UserPassword.ps1 -Login "jkowalski" -GenerateRandomPassword -DryRun

  # 5. Reset password in Cloud (Microsoft Entra ID) with interactive Admin sign-in:
  .\Reset-UserPassword.ps1 -Login "jkowalski@firma.pl" -Mode Cloud

  # 6. Reset password in Cloud (Entra ID) Non-Interactively via Client Secret:
  .\Reset-UserPassword.ps1 -Login "jkowalski" ``
      -Mode Cloud ``
      -UpnSuffix "contoso.com" ``
      -GenerateRandomPassword ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -ClientSecret "YourClientSecretValueHere" ``
      -Force

  # 7. Reset password in Cloud (Entra ID) Non-Interactively via X.509 Certificate:
  .\Reset-UserPassword.ps1 -Login "jkowalski@contoso.com" ``
      -Mode Cloud ``
      -GenerateRandomPassword ``
      -TenantId "11111111-2222-3333-4444-555555555555" ``
      -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" ``
      -CertificateThumbprint "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678" ``
      -Force

  # 8. Hybrid Mode (Both Local AD and Cloud Entra ID) with CSV audit report export:
  .\Reset-UserPassword.ps1 -Login "jkowalski" ``
      -Mode Both -UpnSuffix "contoso.com" ``
      -Interactive ``
      -ExportReportPath "C:\Logs\PasswordReset_Audit.csv"

--------------------------------------------------------------------------------
PARAMETERS:
--------------------------------------------------------------------------------
  -Login, -Identity, -u         User login (SamAccountName, UPN, DN, Mail, or ObjectId).
  -NewPassword, -Password       New temporary password as a SecureString.
  -PlainTextPassword            New temporary password as plain text (converted in memory).
  -Interactive, -Prompt         Prompt interactively for Login and SecureString password.
  -GenerateRandomPassword       Auto-generate a strong complexity-compliant temporary password.
  -PasswordLength               Length of generated password (12-64, default: 16).
  -Mode, -Provider              Directory mode: 'Local' ('AD'), 'Cloud' ('EntraID'), or 'Both'.
  -ChangePasswordAtLogon        Force password change at first logon (default: `$true).
  -NoChangePasswordAtLogon      Do not force password change at next logon.
  -UnlockAccount, -Unlock       Also unlock the user account in Local AD if locked out.
  -UpnSuffix, -Domain           Domain suffix appended to short logins in Cloud mode.
  -DomainController, -Server    Specific AD Domain Controller to target in Local mode.
  -Credential                   PSCredential for Local Active Directory operations.
  -ExportReportPath, -ExportCsv Export password reset audit record to a UTF-8 CSV file.
  -TenantId                     Entra ID Tenant ID (for non-interactive Cloud auth).
  -ClientId                     Entra ID App Client ID (for non-interactive Cloud auth).
  -ClientSecret                 Entra ID Client Secret (for non-interactive Cloud auth).
  -CertificateThumbprint        X.509 Certificate thumbprint (for non-interactive Cloud auth).
  -AdminUserPrincipalName       Admin UPN hint for interactive Cloud sign-in.
  -DryRun, -Simulate            Validate user and simulate password reset without applying.
  -SkipAdminCheck               Skip automatic UAC administrator elevation check.
  -PassThru                     Output result object(s) to the PowerShell pipeline.
  -LogPath, -Log                Custom log path (Default: C:\Logs\<timestamp>-Reset-UserPassword-<PC>-<User>.logs).
  -NoLog                        Disable file logging.
  -Force                        Bypass interactive confirmation prompts (Y/N / T/N).
  -Help, -h                     Display this help manual.

LOGGING:
  Detailed execution logs are automatically written by default to:
  C:\Logs\<yyyyMMdd_HHmmss>-Reset-UserPassword-<ComputerName>-<UserName>.logs

SECURITY & UNBLOCKING:
  After downloading this script from GitHub, unblock the file before execution:
  Unblock-File -Path .\Reset-UserPassword.ps1
================================================================================
"@
    Write-Host $helpText -ForegroundColor Cyan
}

# ==============================================================================
# LOGGING ENGINE (Default: C:\Logs\<DateTime>-Reset-UserPassword-<PC>-<User>.logs)
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

if (-not $SkipAdminCheck -and -not $DryRun -and ($script:NormalizedMode -eq 'Local' -or $script:NormalizedMode -eq 'Both')) {
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
        [string]$ParameterName = "ExportReportPath"
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

function New-StrongTemporaryPassword {
    param([int]$Length = 16)
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower   = "abcdefghijkmnopqrstuvwxyz"
    $digits  = "23456789"
    $special = "!@#$%^&*()-_=+?"
    $allChars = $upper + $lower + $digits + $special

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] ($Length + 8)
    $rng.GetBytes($bytes)

    # Guarantee at least one character from each complexity class
    $chars = New-Object System.Collections.Generic.List[char]
    $chars.Add($upper[$bytes[0] % $upper.Length])
    $chars.Add($lower[$bytes[1] % $lower.Length])
    $chars.Add($digits[$bytes[2] % $digits.Length])
    $chars.Add($special[$bytes[3] % $special.Length])

    for ($i = 4; $i -lt $Length; $i++) {
        $chars.Add($allChars[$bytes[$i] % $allChars.Length])
    }

    # Shuffle characters
    $shuffled = $chars | Sort-Object {
        $b = New-Object byte[] 4
        $rng.GetBytes($b)
        [BitConverter]::ToUInt32($b, 0)
    }
    return (-join $shuffled)
}

# ==============================================================================
# INTERACTIVE OR PARAMETERIZED USER LOGIN & TEMPORARY PASSWORD ACQUISITION
# ==============================================================================
if ([string]::IsNullOrWhiteSpace($Login)) {
    # Prompt interactively using the exact prompt required by specification
    $Login = Read-Host "Podaj login użytkownika (SamAccountName)"
}

if ([string]::IsNullOrWhiteSpace($Login)) {
    Write-ScriptLog -Level ERROR -Message "No user login (SamAccountName / UPN) was provided. Aborting password reset."
    exit 1
}

$Login = $Login.Trim()
Assert-SafeInput -InputValue $Login -ParameterName "Login" -MaxLength 256
Assert-SafeInput -InputValue $UpnSuffix -ParameterName "UpnSuffix" -MaxLength 255
Assert-SafeInput -InputValue $DomainController -ParameterName "DomainController" -MaxLength 255
Assert-SafeInput -InputValue $TenantId -ParameterName "TenantId" -MaxLength 128
Assert-SafeInput -InputValue $ClientId -ParameterName "ClientId" -MaxLength 128
Assert-SafeInput -InputValue $CertificateThumbprint -ParameterName "CertificateThumbprint" -MaxLength 128
Assert-SafeInput -InputValue $AdminUserPrincipalName -ParameterName "AdminUserPrincipalName" -MaxLength 256

$NoweHaslo = $null
$generatedPlainPassword = $null

if ($null -ne $NewPassword) {
    $NoweHaslo = $NewPassword
    Write-ScriptLog -Level INFO -Message "Using temporary password supplied via -NewPassword (SecureString)."
} elseif (-not [string]::IsNullOrWhiteSpace($PlainTextPassword)) {
    $NoweHaslo = ConvertTo-SecureString -String $PlainTextPassword -AsPlainText -Force
    Write-ScriptLog -Level INFO -Message "Using temporary password supplied via -PlainTextPassword (converted to SecureString)."
} elseif ($GenerateRandomPassword) {
    $generatedPlainPassword = New-StrongTemporaryPassword -Length $PasswordLength
    $NoweHaslo = ConvertTo-SecureString -String $generatedPlainPassword -AsPlainText -Force
    Write-ScriptLog -Level INFO -Message "Generated cryptographically strong temporary password ($PasswordLength characters)."
} else {
    # Prompt interactively using the exact SecureString prompt required by specification
    $NoweHaslo = Read-Host -AsSecureString "Podaj nowe tymczasowe hasło"
}

$plainCheck = Convert-SecureStringToPlain -SecureValue $NoweHaslo
if ([string]::IsNullOrWhiteSpace($plainCheck)) {
    Write-ScriptLog -Level ERROR -Message "The provided temporary password cannot be empty. Aborting password reset."
    exit 1
}
$plainCheck = $null

Write-ScriptLog -Level INFO -Message "Target User Login        : $Login"
Write-ScriptLog -Level INFO -Message "Target Directory Mode    : $script:NormalizedMode"
Write-ScriptLog -Level INFO -Message "Change Password At Logon : $ChangePasswordAtLogon"
if ($UnlockAccount) {
    Write-ScriptLog -Level INFO -Message "Unlock Account Option    : Enabled"
}

# ==============================================================================
# INTERACTIVE CONFIRMATION PROMPT (Bilingual English Y/N & Polish T/N)
# ==============================================================================
if (-not $Force -and -not $DryRun -and -not $Interactive) {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Yellow
    Write-Host "  CONFIRMATION REQUIRED / WYMAGANE POTWIERDZENIE" -ForegroundColor Yellow
    Write-Host "  Target User (Login)      : $Login" -ForegroundColor White
    Write-Host "  Directory Mode           : $script:NormalizedMode" -ForegroundColor White
    Write-Host "  Force Change At Logon    : $ChangePasswordAtLogon" -ForegroundColor White
    Write-Host "  Unlock Account           : $UnlockAccount" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Yellow
    $confirmInput = Read-Host "Do you want to reset the password for user '$Login'? [Y/T = Yes/Tak, N = No/Nie]"
    if ($confirmInput -notmatch '^(Y|y|T|t|Yes|yes|Tak|tak)$') {
        Write-ScriptLog -Level WARN -Message "Password reset operation cancelled by administrator at confirmation prompt."
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

function Resolve-LocalADUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserLogin,
        [Parameter(Mandatory = $true)]
        [hashtable]$AdParams
    )

    $adUser = $null
    try {
        $adUser = Get-ADUser -Identity $UserLogin -Properties SamAccountName, UserPrincipalName, DisplayName, Enabled, LockedOut, PasswordExpired @AdParams -ErrorAction Stop
    } catch {
        $safeLogin  = ConvertTo-SafeLdapFilterValue -Value $UserLogin
        $shortLogin = if ($UserLogin -match '^([^@]+)@') { ConvertTo-SafeLdapFilterValue -Value $Matches[1] } else { $safeLogin }
        $ldapQuery  = "(|(sAMAccountName=$safeLogin)(userPrincipalName=$safeLogin)(mail=$safeLogin)(sAMAccountName=$shortLogin))"
        $foundUsers = @(Get-ADUser -LDAPFilter $ldapQuery -Properties SamAccountName, UserPrincipalName, DisplayName, Enabled, LockedOut, PasswordExpired @AdParams -ErrorAction SilentlyContinue)
        if ($foundUsers.Count -eq 1) {
            $adUser = $foundUsers[0]
        } elseif ($foundUsers.Count -gt 1) {
            throw "Ambiguous login '$UserLogin': matched $($foundUsers.Count) Local AD user accounts."
        }
    }

    return $adUser
}

function Invoke-LocalADPasswordReset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserLogin,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecurePassword
    )

    Write-Progress -Id 1 -Activity "Local Active Directory: Resetting User Password" -Status "Connecting to Local Active Directory..." -PercentComplete 15
    $adParams = Initialize-LocalADEnvironment

    Write-Progress -Id 1 -Activity "Local Active Directory: Resetting User Password" -Status "Resolving user account '$UserLogin'..." -PercentComplete 40
    $adUser = Resolve-LocalADUser -UserLogin $UserLogin -AdParams $adParams

    if ($null -eq $adUser) {
        Write-Progress -Id 1 -Activity "Local Active Directory: Resetting User Password" -Completed
        $msg = "User '$UserLogin' was not found in Local Active Directory."
        Write-ScriptLog -Level ERROR -Message "[Local AD] $msg"
        return [PSCustomObject]@{
            Timestamp             = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Environment           = "LocalAD"
            InputLogin            = $UserLogin
            ResolvedSamAccount    = ""
            UserPrincipalName     = ""
            ChangePasswordAtLogon = $ChangePasswordAtLogon
            AccountUnlocked       = $false
            Status                = "UserNotFound"
            Details               = $msg
        }
    }

    $resolvedSam = $adUser.SamAccountName
    $resolvedUpn = [string]$adUser.UserPrincipalName
    Write-ScriptLog -Level INFO -Message "[Local AD] Resolved user: $($adUser.DisplayName) (SamAccountName: $resolvedSam, UPN: $resolvedUpn, Enabled: $($adUser.Enabled), LockedOut: $($adUser.LockedOut))"

    if (-not $adUser.Enabled) {
        Write-ScriptLog -Level WARN -Message "[Local AD] Note: User account '$resolvedSam' is currently disabled in Active Directory."
    }

    $unlocked = $false
    $status   = "Pending"
    $details  = ""

    try {
        if ($DryRun -or -not $PSCmdlet.ShouldProcess("User '$resolvedSam' ($($adUser.DistinguishedName))", "Set-ADAccountPassword & Set-ADUser -ChangePasswordAtLogon:`$$ChangePasswordAtLogon")) {
            $status  = "Simulated"
            $details = "[DRY-RUN] Would reset password for Local AD user '$resolvedSam' and set ChangePasswordAtLogon = $ChangePasswordAtLogon."
            Write-ScriptLog -Level INFO -Message "[Local AD] $details"
        } else {
            Write-Progress -Id 1 -Activity "Local Active Directory: Resetting User Password" -Status "Executing Set-ADAccountPassword for '$resolvedSam'..." -PercentComplete 70

            # Core Local AD password reset command
            Set-ADAccountPassword -Identity $resolvedSam -NewPassword $SecurePassword -Reset $true @adParams -ErrorAction Stop

            Write-Progress -Id 1 -Activity "Local Active Directory: Resetting User Password" -Status "Configuring ChangePasswordAtLogon ($ChangePasswordAtLogon) for '$resolvedSam'..." -PercentComplete 85

            # Force password change at first logon
            Set-ADUser -Identity $resolvedSam -ChangePasswordAtLogon $ChangePasswordAtLogon @adParams -ErrorAction Stop

            if ($UnlockAccount -or $adUser.LockedOut) {
                if ($UnlockAccount) {
                    Unlock-ADAccount -Identity $resolvedSam @adParams -ErrorAction Stop
                    $unlocked = $true
                    Write-ScriptLog -Level SUCCESS -Message "[Local AD] Unlocked user account '$resolvedSam'."
                } else {
                    Write-ScriptLog -Level WARN -Message "[Local AD] Account '$resolvedSam' is currently locked out (LockedOut = True). Pass -UnlockAccount to unlock it automatically."
                }
            }

            # Core confirmation output required by specification
            Write-Host "Hasło dla użytkownika $UserLogin zostało zresetowane." -ForegroundColor Cyan
            Write-ScriptLog -Level SUCCESS -Message "[Local AD] Password for user '$UserLogin' (SamAccountName: $resolvedSam) was reset successfully (ChangePasswordAtLogon: $ChangePasswordAtLogon)." -NoConsole

            $status  = "PasswordReset"
            $details = "Successfully reset password for '$resolvedSam' in Local AD (ChangePasswordAtLogon=$ChangePasswordAtLogon)."
        }
    } catch {
        $status  = "Failed"
        $details = $_.Exception.Message
        Write-ScriptLog -Level ERROR -Message "[Local AD] Failed to reset password for '$UserLogin': $details"
    } finally {
        Write-Progress -Id 1 -Activity "Local Active Directory: Resetting User Password" -Completed
    }

    return [PSCustomObject]@{
        Timestamp             = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Environment           = "LocalAD"
        InputLogin            = $UserLogin
        ResolvedSamAccount    = $resolvedSam
        UserPrincipalName     = $resolvedUpn
        ChangePasswordAtLogon = $ChangePasswordAtLogon
        AccountUnlocked       = $unlocked
        Status                = $status
        Details               = $details
    }
}

# ==============================================================================
# CLOUD MICROSOFT ENTRA ID ENGINE (Mode: Cloud / Both)
# ==============================================================================
function Connect-EntraIDDirectory {
    Write-ScriptLog -Level STEP -Message "Initializing Cloud Microsoft Entra ID connection (Microsoft Graph SDK)..."

    $requiredModules = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Users')
    foreach ($mod in $requiredModules) {
        if (-not (Get-Module -Name $mod -ErrorAction SilentlyContinue)) {
            if (-not (Get-Module -ListAvailable -Name $mod)) {
                throw "Required Microsoft Graph SDK module '$mod' is not installed. Install it via: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser"
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
        $secString  = ConvertTo-SecureString -String $plainSecret -AsPlainText -Force
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
        $ctx    = Get-MgContext -ErrorAction SilentlyContinue
        $scopes = @("UserAuthenticationMethod.ReadWrite.All", "User.ReadWrite.All", "Directory.AccessAsUser.All")

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

function Resolve-CloudEntraUser {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserLogin
    )

    $mgUser = $null
    $candidateIdentity = $UserLogin
    if ($UserLogin -notmatch '@' -and -not [Guid]::TryParse($UserLogin, [ref]([Guid]::Empty)) -and -not [string]::IsNullOrWhiteSpace($UpnSuffix)) {
        $candidateIdentity = "$UserLogin@$($UpnSuffix.TrimStart('@'))"
    }

    try {
        $mgUser = Get-MgUser -UserId $candidateIdentity -Property Id, UserPrincipalName, DisplayName, Mail, MailNickname, AccountEnabled, OnPremisesSamAccountName -ErrorAction Stop
        if ($null -ne $mgUser) { return $mgUser }
    } catch {}

    $safeLogin = ConvertTo-SafeODataValue -Value $UserLogin
    $safeCand  = ConvertTo-SafeODataValue -Value $candidateIdentity
    $filterQuery = "userPrincipalName eq '$safeCand' or mail eq '$safeCand' or mailNickname eq '$safeLogin' or onPremisesSamAccountName eq '$safeLogin'"

    try {
        $matched = @(Get-MgUser -Filter $filterQuery -Property Id, UserPrincipalName, DisplayName, Mail, MailNickname, AccountEnabled, OnPremisesSamAccountName -ErrorAction Stop)
        if ($matched.Count -eq 1) {
            return $matched[0]
        } elseif ($matched.Count -gt 1) {
            throw "Ambiguous login '$UserLogin': matched $($matched.Count) accounts in Microsoft Entra ID."
        }
    } catch {
        $fallbackFilter = "userPrincipalName eq '$safeCand' or mail eq '$safeCand' or mailNickname eq '$safeLogin'"
        $matched = @(Get-MgUser -Filter $fallbackFilter -Property Id, UserPrincipalName, DisplayName, Mail, MailNickname, AccountEnabled -ErrorAction SilentlyContinue)
        if ($matched.Count -eq 1) {
            return $matched[0]
        }
    }

    return $null
}

function Invoke-CloudEntraPasswordReset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserLogin,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecurePassword
    )

    Write-Progress -Id 2 -Activity "Cloud Entra ID: Resetting User Password" -Status "Connecting to Microsoft Graph..." -PercentComplete 15
    Connect-EntraIDDirectory

    Write-Progress -Id 2 -Activity "Cloud Entra ID: Resetting User Password" -Status "Resolving cloud user '$UserLogin'..." -PercentComplete 45
    $cloudUser = Resolve-CloudEntraUser -UserLogin $UserLogin

    if ($null -eq $cloudUser) {
        Write-Progress -Id 2 -Activity "Cloud Entra ID: Resetting User Password" -Completed
        $hint = if ($UserLogin -notmatch '@' -and [string]::IsNullOrWhiteSpace($UpnSuffix)) { " (Tip: provide -UpnSuffix 'yourdomain.com' when using short logins in Cloud mode)" } else { "" }
        $msg  = "User '$UserLogin' was not found in Microsoft Entra ID.$hint"
        Write-ScriptLog -Level ERROR -Message "[Cloud Entra ID] $msg"
        return [PSCustomObject]@{
            Timestamp             = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Environment           = "CloudEntraID"
            InputLogin            = $UserLogin
            ResolvedSamAccount    = ""
            UserPrincipalName     = ""
            ChangePasswordAtLogon = $ChangePasswordAtLogon
            AccountUnlocked       = $false
            Status                = "UserNotFound"
            Details               = $msg
        }
    }

    $resolvedId  = $cloudUser.Id
    $resolvedUpn = [string]$cloudUser.UserPrincipalName
    Write-ScriptLog -Level INFO -Message "[Cloud Entra ID] Resolved user: $($cloudUser.DisplayName) (UPN: $resolvedUpn, ObjectId: $resolvedId, AccountEnabled: $($cloudUser.AccountEnabled))"

    $status  = "Pending"
    $details = ""

    try {
        if ($DryRun -or -not $PSCmdlet.ShouldProcess("Cloud User '$resolvedUpn' (ObjectId: $resolvedId)", "Update-MgUser -PasswordProfile (ForceChangePasswordNextSignIn: $ChangePasswordAtLogon)")) {
            $status  = "Simulated"
            $details = "[DRY-RUN] Would reset password for Cloud Entra ID user '$resolvedUpn' and set ForceChangePasswordNextSignIn = $ChangePasswordAtLogon."
            Write-ScriptLog -Level INFO -Message "[Cloud Entra ID] $details"
        } else {
            Write-Progress -Id 2 -Activity "Cloud Entra ID: Resetting User Password" -Status "Updating PasswordProfile for '$resolvedUpn'..." -PercentComplete 80

            $plainPass = Convert-SecureStringToPlain -SecureValue $SecurePassword
            try {
                $passwordProfile = @{
                    Password                      = $plainPass
                    ForceChangePasswordNextSignIn = [bool]$ChangePasswordAtLogon
                }
                Update-MgUser -UserId $resolvedId -PasswordProfile $passwordProfile -ErrorAction Stop
            } finally {
                $plainPass = $null
            }

            # Core confirmation output required by specification
            Write-Host "Hasło dla użytkownika $UserLogin zostało zresetowane." -ForegroundColor Cyan
            Write-ScriptLog -Level SUCCESS -Message "[Cloud Entra ID] Password for user '$UserLogin' (UPN: $resolvedUpn, ObjectId: $resolvedId) was reset successfully (ForceChangePasswordNextSignIn: $ChangePasswordAtLogon)." -NoConsole

            $status  = "PasswordReset"
            $details = "Successfully reset password for '$resolvedUpn' in Cloud Entra ID (ForceChangePasswordNextSignIn=$ChangePasswordAtLogon)."
        }
    } catch {
        $status  = "Failed"
        $details = $_.Exception.Message
        Write-ScriptLog -Level ERROR -Message "[Cloud Entra ID] Failed to reset password for '$UserLogin': $details"
    } finally {
        Write-Progress -Id 2 -Activity "Cloud Entra ID: Resetting User Password" -Completed
    }

    return [PSCustomObject]@{
        Timestamp             = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Environment           = "CloudEntraID"
        InputLogin            = $UserLogin
        ResolvedSamAccount    = $resolvedId
        UserPrincipalName     = $resolvedUpn
        ChangePasswordAtLogon = $ChangePasswordAtLogon
        AccountUnlocked       = $false
        Status                = $status
        Details               = $details
    }
}

# ==============================================================================
# MAIN EXECUTION ORCHESTRATOR
# ==============================================================================
$allResults = New-Object System.Collections.Generic.List[object]
$startTime  = Get-Date

try {
    if ($script:NormalizedMode -eq 'Local' -or $script:NormalizedMode -eq 'Both') {
        $localResult = Invoke-LocalADPasswordReset -UserLogin $Login -SecurePassword $NoweHaslo
        $allResults.Add($localResult)
    }

    if ($script:NormalizedMode -eq 'Cloud' -or $script:NormalizedMode -eq 'Both') {
        $cloudResult = Invoke-CloudEntraPasswordReset -UserLogin $Login -SecurePassword $NoweHaslo
        $allResults.Add($cloudResult)
    }
} catch {
    Write-ScriptLog -Level ERROR -Message "Fatal execution error: $($_.Exception.Message)"
    exit 1
}

if (-not [string]::IsNullOrWhiteSpace($generatedPlainPassword)) {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "  GENERATED TEMPORARY PASSWORD (DISPLAYED ONCE - DO NOT STORE IN PLAINTEXT)" -ForegroundColor Green
    Write-Host "  User Login         : $Login" -ForegroundColor White
    Write-Host "  Temporary Password : $generatedPlainPassword" -ForegroundColor Yellow
    Write-Host "================================================================================" -ForegroundColor Green
    $generatedPlainPassword = $null
}

$duration       = (Get-Date) - $startTime
$resetCount     = @($allResults | Where-Object { $_.Status -eq 'PasswordReset' }).Count
$simulatedCount = @($allResults | Where-Object { $_.Status -eq 'Simulated' }).Count
$notFoundCount  = @($allResults | Where-Object { $_.Status -eq 'UserNotFound' }).Count
$failedCount    = @($allResults | Where-Object { $_.Status -eq 'Failed' }).Count

Write-Host ""
Write-ScriptLog -Level STEP -Message "================================================================================"
Write-ScriptLog -Level INFO -Message "EXECUTION SUMMARY ($script:ScriptName v$script:ScriptVersion)"
Write-ScriptLog -Level STEP -Message "================================================================================"
Write-ScriptLog -Level INFO -Message "  Target User Login     : $Login"
Write-ScriptLog -Level INFO -Message "  Execution Mode        : $script:NormalizedMode"
Write-ScriptLog -Level INFO -Message "  Force Change At Logon : $ChangePasswordAtLogon"
Write-ScriptLog -Level SUCCESS -Message "  Passwords Reset       : $resetCount"
if ($simulatedCount -gt 0) {
    Write-ScriptLog -Level INFO -Message "  Simulated (Dry-Run)   : $simulatedCount"
}
if ($notFoundCount -gt 0) {
    Write-ScriptLog -Level ERROR -Message "  Users Not Found       : $notFoundCount"
}
if ($failedCount -gt 0) {
    Write-ScriptLog -Level ERROR -Message "  Failed Operations     : $failedCount"
}
Write-ScriptLog -Level INFO -Message "  Elapsed Time          : $($duration.ToString('hh\:mm\:ss\.fff'))"
if ($script:ActiveLogFile) {
    Write-ScriptLog -Level INFO -Message "  Log File Saved To     : $script:ActiveLogFile"
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
        Write-ScriptLog -Level SUCCESS -Message "Exported password reset audit report to CSV: $ExportReportPath"
    } catch {
        Write-ScriptLog -Level ERROR -Message "Failed to export CSV report to '$ExportReportPath': $($_.Exception.Message)"
    }
}

if ($PassThru) {
    Write-Output $allResults
}
