# Reset-UserPassword

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS-0078D4.svg)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Graph%20SDK-008272.svg)](https://learn.microsoft.com/graph/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade PowerShell emergency / rescue script designed to **immediately reset the password of a selected user account** when a user forgets their password and contacts an administrator or Helpdesk team, while automatically enforcing a password change at first logon (`ChangePasswordAtLogon`).

Supports **Local Active Directory Domain Services (`-Mode Local` / `AD`)**, **Cloud Microsoft Entra ID (`-Mode Cloud` / `EntraID`)**, and **Hybrid (`-Mode Both`)** environments with interactive `Read-Host` prompts or CLI parameters, cryptographic temporary password generation, optional account unlocking (`-UnlockAccount`), language-independent UAC auto-elevation, and centralized audit logging.

---

## ✨ Key Features

1. **Zero-Parameter Interactive Help (`-Help` / `-h`)**
   Running `.\Reset-UserPassword.ps1` without parameters or with `-h` / `-Help` displays comprehensive console documentation, step-by-step non-interactive Entra ID setup instructions, usage examples, script version (`1.2.0`), and author details without making any directory changes.
2. **Emergency Interactive & Parameterized Password Reset**
   - **Classic Interactive Rescue Flow (`-Interactive`):** Prompts the administrator directly on the console:
     ```powershell
     $Login = Read-Host "Podaj login użytkownika (SamAccountName)"
     $NoweHaslo = Read-Host -AsSecureString "Podaj nowe tymczasowe hasło"
     Set-ADAccountPassword -Identity $Login -NewPassword $NoweHaslo -Reset $true
     Set-ADUser -Identity $Login -ChangePasswordAtLogon $true
     Write-Host "Hasło dla użytkownika $Login zostało zresetowane." -ForegroundColor Cyan
     ```
   - **Parameterized / Automated Execution:** Accepts `-Login`, `-NewPassword` (`SecureString`), `-PlainTextPassword`, or `-GenerateRandomPassword` (auto-generates a cryptographically strong complexity-compliant temporary password).
3. **Dual Directory Environment Support (`-Mode Local | Cloud | Both`)**
   - **`Local` (`AD` / `LocalAD` / `OnPremises` — Default):** Uses the Windows Server `ActiveDirectory` module (`Set-ADAccountPassword`, `Set-ADUser -ChangePasswordAtLogon $true`, `Get-ADUser`, `Unlock-ADAccount`) to reset domain user passwords, supporting `-DomainController` and `-Credential`.
   - **`Cloud` (`EntraID` / `CloudAD` / `AzureAD`):** Uses the **Microsoft Graph PowerShell SDK** (`Update-MgUser -PasswordProfile @{ Password = ...; ForceChangePasswordNextSignIn = $true }`, `Get-MgUser`) to reset cloud user passwords in Microsoft Entra ID, supporting both interactive administrator sign-in and unattended App-Only authentication (Client Secret or X.509 Certificate).
   - **`Both`:** Resets the user's password across both On-Premises Active Directory and Cloud Microsoft Entra ID in a single run.
4. **Mandatory Password Change at First Logon & Account Unlocking**
   - Enforces `ChangePasswordAtLogon = $true` (Local AD) and `ForceChangePasswordNextSignIn = $true` (Cloud Entra ID) by default (can be overridden with `-NoChangePasswordAtLogon`).
   - Optionally unlocks locked-out domain accounts via `-UnlockAccount` (`Unlock-ADAccount`).
   - Outputs clear visual confirmation in cyan upon completion:
     `Hasło dla użytkownika <Login> zostało zresetowane.`
5. **Language-Independent UAC Auto-Elevation (PL / EN Windows)**
   Verifies Administrator privileges using the well-known Windows SID `S-1-5-32-544` (`BuiltInAdministratorsSid`), ensuring seamless compatibility across both Polish (`Administratorzy`) and English (`Administrators`) editions of Windows Desktop and Windows Server.
6. **Centralized Audit Logging (`C:\Logs`)**
   Automatically records detailed, timestamped UTF-8 execution logs (without ever writing plaintext passwords to disk) by default at:
   `C:\Logs\<yyyyMMdd_HHmmss>-Reset-UserPassword-<ComputerName>-<UserName>.logs`

---

## 📋 Prerequisites

* **Operating System:** Windows Server 2016/2019/2022/2025 or Windows 10/11 (Polish or English locale).
* **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+.
* **For Local Active Directory Mode (`-Mode Local` / `AD`):**
  * Active Directory module for Windows PowerShell (`RSAT-AD-PowerShell`).
  * Domain account with permissions to reset user passwords (`Reset Password` and write `pwdLastSet`).
  ```powershell
  # Install on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

  # Install on Windows Server:
  Install-WindowsFeature -Name RSAT-AD-PowerShell
  ```
* **For Cloud Microsoft Entra ID Mode (`-Mode Cloud` / `EntraID`):**
  * `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users` modules.
  ```powershell
  Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser -Repository PSGallery -Force
  ```

---

## 🔓 Unblocking the Script After Download

After downloading or cloning this script from GitHub, Windows marks the `.ps1` file with a `Zone.Identifier` alternate data stream. Unblock the file before running it:

```powershell
Unblock-File -Path .\Reset-UserPassword.ps1
```

---

## 🔐 Non-Interactive Authentication in Microsoft Entra ID (Microsoft Graph SDK)

To run `Reset-UserPassword.ps1` in `-Mode Cloud` unattended (e.g., from an internal Helpdesk portal, ITSM workflow, or background automation pipeline) using **only API credentials and Microsoft Graph SDK Application Permissions**:

### Step 1: Register an Application in Microsoft Entra ID
1. Sign in to the [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Navigate to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Set **Name** to `AD-Password-Reset-Automation`.
4. Under **Supported account types**, select *Accounts in this organizational directory only (Single tenant)*.
5. Click **Register** and copy:
   * **Application (client) ID** (`-ClientId`)
   * **Directory (tenant) ID** (`-TenantId`)

### Step 2: Assign Microsoft Graph Application Permissions & Directory Role
1. Inside the registered application, go to **Manage** > **API permissions** > **Add a permission**.
2. Select **Microsoft Graph** > **Application permissions** *(do not choose Delegated permissions for unattended execution)*.
3. Search for and select:
   * `UserAuthenticationMethod.ReadWrite.All` *(Recommended for resetting user authentication credentials)*
   * `User.ReadWrite.All` *(Required to update user `PasswordProfile`)*
   * `Directory.Read.All` *(Required to resolve user logins/UPNs to directory `ObjectId`s)*
4. Click **Add permissions**.
5. Click **Grant admin consent for \<Your Organization\>** and verify that all permissions display a green checkmark.
6. **Assign Entra ID Directory Role for Password Reset:**
   In the Microsoft Entra Admin Center, navigate to **Identity** > **Roles & admins** > **Roles & admins**, select **User Administrator** (or **Helpdesk Administrator** / **Authentication Administrator** / **Privileged Authentication Administrator**), click **Add assignments**, and add your `AD-Password-Reset-Automation` enterprise application / service principal.

### Step 3: Create API Credentials (Option A: Client Secret or Option B: X.509 Certificate)

#### Option A: Client Secret (API Key)
1. Go to **Manage** > **Certificates & secrets** > **Client secrets** > **New client secret**.
2. Enter a description (e.g., `PasswordResetSecret`), choose an expiration period, and click **Add**.
3. Copy the **Value** immediately and pass it to the script:
   ```powershell
   .\Reset-UserPassword.ps1 -Login "jkowalski" `
       -Mode Cloud `
       -UpnSuffix "contoso.com" `
       -GenerateRandomPassword `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -ClientSecret "YourClientSecretValueHere" `
       -Force
   ```

#### Option B: X.509 Certificate (Recommended for Production)
1. Generate a self-signed certificate in PowerShell and export the `.cer` public key:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=EntraPasswordResetAutomation" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable -KeySpec Signature `
       -KeyLength 2048 -HashAlgorithm SHA256 `
       -NotAfter (Get-Date).AddYears(2)
   Export-Certificate -Cert $cert -FilePath "C:\Logs\EntraPasswordResetAutomation.cer"
   ```
2. Upload `C:\Logs\EntraPasswordResetAutomation.cer` in **Microsoft Entra Admin Center** > **App registrations** > **Certificates & secrets** > **Certificates** > **Upload certificate**.
3. Execute the script using the certificate thumbprint:
   ```powershell
   .\Reset-UserPassword.ps1 -Login "jkowalski@contoso.com" `
       -Mode Cloud `
       -GenerateRandomPassword `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -CertificateThumbprint $cert.Thumbprint `
       -Force
   ```

---

## 🚀 Usage Examples

### Example 1: Display Built-In Help & Configuration Guide
Running the script without parameters or with `-h` / `-Help` displays the help manual:
```powershell
.\Reset-UserPassword.ps1
# or
.\Reset-UserPassword.ps1 -Help
```

### Example 2: Classic Interactive Rescue Mode in Local Active Directory (`-Interactive`)
Prompts interactively for the user login (`Podaj login użytkownika (SamAccountName)`) and the new temporary password (`Podaj nowe tymczasowe hasło`), resets the password, and forces a password change at first logon:
```powershell
.\Reset-UserPassword.ps1 -Interactive
```

### Example 3: Reset Password for a Specified Local AD User (Prompts Securely for Password)
Specifies the user login via parameter and prompts via `Read-Host -AsSecureString` for the temporary password:
```powershell
.\Reset-UserPassword.ps1 -Login "jkowalski"
```

### Example 4: Auto-Generate Strong Temporary Password & Unlock Account in Local AD
Generates a 16-character complexity-compliant temporary password, resets the user's password, forces password change at next logon, and unlocks the account if locked out:
```powershell
.\Reset-UserPassword.ps1 -Login "jkowalski" -GenerateRandomPassword -UnlockAccount -Force
```

### Example 5: Preview / Dry-Run Simulation (`-DryRun`)
Validates user account existence and lockout status in Active Directory without modifying the password:
```powershell
.\Reset-UserPassword.ps1 -Login "jkowalski" -GenerateRandomPassword -DryRun
```

### Example 6: Reset User Password in Cloud Microsoft Entra ID (Interactive Sign-In)
Connects interactively to Microsoft Graph and resets the user's cloud password with `ForceChangePasswordNextSignIn = $true`:
```powershell
.\Reset-UserPassword.ps1 -Login "jkowalski@firma.pl" -Mode Cloud
```

### Example 7: Hybrid Mode (`-Mode Both`) — Local AD + Cloud Entra ID with CSV Audit Export
Resets the user's password in both On-Premises Active Directory and Cloud Microsoft Entra ID and exports an audit record to CSV:
```powershell
.\Reset-UserPassword.ps1 -Login "jkowalski" `
    -Mode Both `
    -UpnSuffix "firma.pl" `
    -Interactive `
    -ExportReportPath "C:\Logs\PasswordReset_Audit.csv"
```

---

## ⚙️ Parameter Reference

| Parameter | Alias(es) | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-Login` | `-Identity`, `-SamAccountName`, `-UserPrincipalName`, `-User`, `-u` | `string` | Interactive prompt | Target user login (`SamAccountName`, `UPN`, `DN`, `Mail`, or `ObjectId`). |
| `-NewPassword` | `-Password`, `-NoweHaslo`, `-SecurePassword` | `SecureString` | Interactive prompt | New temporary password provided as a `SecureString`. |
| `-PlainTextPassword` | `-PasswordPlain`, `-TempPassword` | `string` | — | New temporary password provided as plain text (converted in memory to `SecureString`). |
| `-Interactive` | `-Prompt`, `-RunInteractive` | `switch` | `$false` | Prompts interactively for user login and `SecureString` temporary password. |
| `-GenerateRandomPassword` | `-RandomPassword`, `-AutoPassword` | `switch` | `$false` | Auto-generates a cryptographically strong complexity-compliant temporary password. |
| `-PasswordLength` | — | `int` | `16` | Character length (`12`–`64`) when `-GenerateRandomPassword` is used. |
| `-Mode` | `-Provider`, `-Environment`, `-Target`, `-Directory` | `string` | `'Local'` | Target environment: `'Local'` (`'AD'`, `'LocalAD'`, `'OnPremises'`), `'Cloud'` (`'EntraID'`, `'CloudAD'`, `'AzureAD'`), or `'Both'`. |
| `-ChangePasswordAtLogon` | — | `bool` | `$true` | Forces the user to change their password at first logon. |
| `-NoChangePasswordAtLogon` | — | `switch` | `$false` | Disables forcing password change at next logon. |
| `-UnlockAccount` | `-Unlock` | `switch` | `$false` | Unlocks the user account in Local Active Directory (`Unlock-ADAccount`). |
| `-UpnSuffix` | `-Domain`, `-DomainSuffix` | `string` | — | Domain suffix appended to short logins in Cloud mode (e.g., `firma.pl`). |
| `-DomainController` | `-Server`, `-DC` | `string` | Auto | Specific Active Directory Domain Controller FQDN/IP for Local mode. |
| `-Credential` | — | `PSCredential` | Current User | Credentials for Local Active Directory authentication. |
| `-ExportReportPath` | `-ExportCsv`, `-ReportPath` | `string` | — | File path to export password reset audit results as a UTF-8 CSV. |
| `-TenantId` | `-Tenant`, `-DirectoryId` | `string` | — | Microsoft Entra ID Tenant ID for Cloud authentication. |
| `-ClientId` | `-AppId`, `-ApplicationId` | `string` | — | Microsoft Entra ID Application (Client) ID for non-interactive Cloud auth. |
| `-ClientSecret` | `-Secret` | `string` | — | Microsoft Entra ID Client Secret for non-interactive Cloud auth. |
| `-ClientSecretSecure` | — | `SecureString` | — | `SecureString` containing the Entra ID Client Secret. |
| `-CertificateThumbprint` | `-Thumbprint` | `string` | — | Certificate thumbprint for non-interactive Cloud authentication. |
| `-AdminUserPrincipalName` | `-AdminUPN` | `string` | — | Admin UPN hint for interactive Cloud sign-in. |
| `-DryRun` | `-Simulate`, `-Preview` | `switch` | `$false` | Simulates the password reset without making changes in AD or Entra ID. |
| `-SkipAdminCheck` | — | `switch` | `$false` | Skips automatic UAC Administrator privilege check. |
| `-PassThru` | — | `switch` | `$false` | Outputs structured result objects to the PowerShell pipeline. |
| `-LogPath` | `-l`, `-Log` | `string` | `C:\Logs\...` | Custom file path for the execution log. |
| `-NoLog` | — | `switch` | `$false` | Disables writing execution logs to disk. |
| `-Force` | — | `switch` | `$false` | Bypasses interactive confirmation prompts (`Y/N` / `T/N`). |
| `-Help` | `-h` | `switch` | `$false` | Displays the console help screen and exits. |

---

## 📝 Logging

Detailed execution logs are enabled by default and automatically saved to:

```text
C:\Logs\<yyyyMMdd_HHmmss>-Reset-UserPassword-<ComputerName>-<UserName>.logs
```

Each log entry includes a millisecond-precision timestamp, severity level (`INFO`, `STEP`, `SUCCESS`, `WARN`, `ERROR`), and detailed operational context for security auditing (temporary passwords are never written to log files).

---

## 📌 Version History

* **v1.2.0 (2026-10-17)**
  * Implemented automatic UAC elevation prompt with language-independent SID verification (`S-1-5-32-544` / `BuiltInAdministratorsSid`) supporting Polish (`Administratorzy`) and English (`Administrators`) Windows environments.
  * Added dual-mode support for Local Active Directory (`-Mode Local` / `AD`) and Cloud Microsoft Entra ID (`-Mode Cloud` / `EntraID` / `Both`) via Microsoft Graph SDK.
  * Added non-interactive App-Only Entra ID authentication (Client Secret & X.509 Certificate) and comprehensive setup guide.
  * Added centralized audit logging to `C:\Logs\<DateTime>-Reset-UserPassword-<ComputerName>-<UserName>.logs`.
  * Added zero-parameter interactive help (`-Help` / `-h`), interactive `Read-Host` rescue mode (`-Interactive`), cryptographic temporary password generator (`-GenerateRandomPassword`), and optional account unlocking (`-UnlockAccount`).

---

## 👨‍💻 Author & Contact

* **Author:** Roman Pindela
* **Email:** [roman.pindela@gmail.com](mailto:roman.pindela@gmail.com)
* **GitHub:** [https://github.com/romanpindela](https://github.com/romanpindela)
* **License:** MIT
