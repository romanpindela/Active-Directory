# Add-UsersToGroup

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS-0078D4.svg)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Graph%20SDK-008272.svg)](https://learn.microsoft.com/graph/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade PowerShell automation script designed to **bulk assign multiple users to a target security or distribution group** (for example, granting access to shared network drives or departmental resources such as `Dzial_Ksiegowosci`) based on a plain text file containing user logins (`nowi_ksiegowi.txt`), a CSV file, or a command-line list of accounts.

Supports **Local Active Directory Domain Services (`-Mode Local` / `AD`)**, **Cloud Microsoft Entra ID (`-Mode Cloud` / `EntraID`)**, and **Hybrid (`-Mode Both`)** environments with full pre-flight validation, duplicate membership checks, real-time progress bars, language-independent UAC auto-elevation, and centralized audit logging.

---

## ✨ Key Features

1. **Zero-Parameter Interactive Help (`-Help` / `-h`)**
   Running `.\Add-UsersToGroup.ps1` without parameters or with `-h` / `-Help` displays comprehensive console documentation, input file specifications, step-by-step non-interactive Entra ID setup instructions, usage examples, script version (`1.2.0`), and author details without making any directory changes.
2. **Flexible User Input Sources (`-UsersFile` & `-Users`)**
   - **Plain Text Files (`.txt`):** Reads one user login (`SamAccountName` or `UserPrincipalName`) per line (e.g., `C:\skrypty\nowi_ksiegowi.txt`), automatically ignoring blank lines and `#` / `//` comments.
   - **CSV Files (`.csv`):** Automatically detects comma (`,`) and Polish Excel semicolon (`;`) delimiters and extracts logins from columns such as `SamAccountName`, `Login`, `UserPrincipalName`, `UPN`, `User`, or `Mail` (or a custom `-CsvColumn`).
   - **Direct CLI Array (`-Users` / `-Loginy`):** Accepts one or more usernames directly on the command line.
3. **Dual Directory Environment Support (`-Mode Local | Cloud | Both`)**
   - **`Local` (`AD` / `OnPremises` — Default):** Uses the Windows Server `ActiveDirectory` module (`Add-ADGroupMember`, `Get-ADGroup`, `Get-ADUser`) to assign users to local domain groups, supporting `-DomainController` and `-Credential`.
   - **`Cloud` (`EntraID` / `AzureAD`):** Uses the **Microsoft Graph PowerShell SDK** (`New-MgGroupMemberByRef`, `Get-MgGroup`, `Get-MgUser`) to assign users to cloud groups in Microsoft Entra ID, supporting both interactive administrator sign-in and unattended App-Only authentication (Client Secret or X.509 Certificate).
   - **`Both`:** Assigns users to the target group across both On-Premises Active Directory and Cloud Microsoft Entra ID in a single run.
4. **Idempotent Pre-Flight Checks & Group Auto-Creation**
   - Verifies that the target group exists before processing users (or creates it automatically when `-CreateGroupIfMissing` is specified).
   - Pre-fetches existing group members to skip users who already belong to the group (`AlreadyMember`), preventing unnecessary errors.
   - Outputs clear visual confirmation in green for every assigned user:
     `Dodano użytkownika: <Login> do grupy <Grupa>`
5. **Language-Independent UAC Auto-Elevation (PL / EN Windows)**
   Verifies Administrator privileges using the well-known Windows SID `S-1-5-32-544` (`BuiltInAdministratorsSid`), ensuring seamless compatibility across both Polish (`Administratorzy`) and English (`Administrators`) editions of Windows Desktop and Windows Server.
6. **Centralized Audit Logging (`C:\Logs`)**
   Automatically records detailed, timestamped UTF-8 execution logs by default at:
   `C:\Logs\<yyyyMMdd_HHmmss>-Add-UsersToGroup-<ComputerName>-<UserName>.logs`

---

## 📋 Prerequisites

* **Operating System:** Windows Server 2016/2019/2022/2025 or Windows 10/11 (Polish or English locale).
* **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+.
* **For Local Active Directory Mode (`-Mode Local` / `AD`):**
  * Active Directory module for Windows PowerShell (`RSAT-AD-PowerShell`).
  * Domain account with permissions to modify membership of the target group.
  ```powershell
  # Install on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

  # Install on Windows Server:
  Install-WindowsFeature -Name RSAT-AD-PowerShell
  ```
* **For Cloud Microsoft Entra ID Mode (`-Mode Cloud` / `EntraID`):**
  * `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, and `Microsoft.Graph.Groups` modules.
  ```powershell
  Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force
  ```

---

## 🔓 Unblocking the Script After Download

After downloading or cloning this script from GitHub, Windows marks the `.ps1` file with a `Zone.Identifier` alternate data stream. Unblock the file before running it:

```powershell
Unblock-File -Path .\Add-UsersToGroup.ps1
```

---

## 📄 Input File Format (`nowi_ksiegowi.txt`)

Create a plain text file containing one login (`SamAccountName` or `UserPrincipalName`) per line. Blank lines and lines beginning with `#` are ignored automatically:

```text
# Sample user logins list for Add-UsersToGroup.ps1
# Group example: Dzial_Ksiegowosci
jkowalski
anowak
pwisniewski
mkaminska
tzelazny
```

> **Tip:** You can generate this sample file automatically at any time by running:
> ```powershell
> .\Add-UsersToGroup.ps1 -GenerateSampleFile -UsersFile ".\nowi_ksiegowi.txt"
> ```

---

## 🔐 Non-Interactive Authentication in Microsoft Entra ID (Microsoft Graph SDK)

To run `Add-UsersToGroup.ps1` in `-Mode Cloud` unattended (e.g., in Windows Task Scheduler, HR onboarding workflows, or background automation pipelines) using **only API credentials and Microsoft Graph SDK Application Permissions**:

### Step 1: Register an Application in Microsoft Entra ID
1. Sign in to the [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Navigate to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Set **Name** to `AD-Group-Membership-Automation`.
4. Under **Supported account types**, select *Accounts in this organizational directory only (Single tenant)*.
5. Click **Register** and copy:
   * **Application (client) ID** (`-ClientId`)
   * **Directory (tenant) ID** (`-TenantId`)

### Step 2: Assign Microsoft Graph Application Permissions
1. Inside the registered application, go to **Manage** > **API permissions** > **Add a permission**.
2. Select **Microsoft Graph** > **Application permissions** *(do not choose Delegated permissions for unattended execution)*.
3. Search for and select:
   * `GroupMember.ReadWrite.All` *(Required to read and add group members)*
   * `Group.ReadWrite.All` *(Required if using `-CreateGroupIfMissing`)*
   * `User.Read.All` *(Required to resolve user logins/UPNs to directory ObjectIds)*
4. Click **Add permissions**.
5. Click **Grant admin consent for \<Your Organization\>** and verify that all permissions display a green checkmark.

### Step 3: Create API Credentials (Option A: Client Secret or Option B: X.509 Certificate)

#### Option A: Client Secret (API Key)
1. Go to **Manage** > **Certificates & secrets** > **Client secrets** > **New client secret**.
2. Enter a description (e.g., `GroupAutomationSecret`), choose an expiration period, and click **Add**.
3. Copy the **Value** immediately and pass it to the script:
   ```powershell
   .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" `
       -UsersFile ".\nowi_ksiegowi.txt" `
       -Mode Cloud `
       -UpnSuffix "contoso.com" `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -ClientSecret "YourClientSecretValueHere" `
       -Force
   ```

#### Option B: X.509 Certificate (Recommended for Production)
1. Generate a self-signed certificate in PowerShell and export the `.cer` public key:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=EntraGroupAutomation" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable -KeySpec Signature `
       -KeyLength 2048 -HashAlgorithm SHA256 `
       -NotAfter (Get-Date).AddYears(2)
   Export-Certificate -Cert $cert -FilePath "C:\Logs\EntraGroupAutomation.cer"
   ```
2. Upload `C:\Logs\EntraGroupAutomation.cer` in **Microsoft Entra Admin Center** > **App registrations** > **Certificates & secrets** > **Certificates** > **Upload certificate**.
3. Execute the script using the certificate thumbprint:
   ```powershell
   .\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" `
       -UsersFile ".\nowi_ksiegowi.txt" `
       -Mode Cloud `
       -UpnSuffix "contoso.com" `
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
.\Add-UsersToGroup.ps1
# or
.\Add-UsersToGroup.ps1 -Help
```

### Example 2: Add Users from a Text File to a Local Active Directory Group
Reads logins from `C:\skrypty\nowi_ksiegowi.txt` and assigns each user to the `Dzial_Ksiegowosci` security group in Local AD:
```powershell
.\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile "C:\skrypty\nowi_ksiegowi.txt"
```

### Example 3: Add Users Directly via Command-Line Array (Unattended Local AD)
Assigns specified logins directly without requiring an external file and skips confirmation prompts via `-Force`:
```powershell
.\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" `
    -Users "jkowalski", "anowak", "pwisniewski" `
    -Mode Local `
    -Force
```

### Example 4: Preview / Dry-Run Simulation (`-DryRun`)
Validates group existence, user accounts, and current membership without modifying Active Directory:
```powershell
.\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" `
    -UsersFile ".\nowi_ksiegowi.txt" `
    -DryRun
```

### Example 5: Auto-Create Target Group If Missing & Export CSV Audit Report
Creates the `Dzial_Ksiegowosci` security group if it does not yet exist, adds all users, and exports a CSV report:
```powershell
.\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" `
    -UsersFile ".\nowi_ksiegowi.txt" `
    -CreateGroupIfMissing `
    -GroupOU "OU=Groups,DC=firma,DC=local" `
    -ExportReportPath "C:\Logs\Dzial_Ksiegowosci_Audit.csv" `
    -Force
```

### Example 6: Add Users to a Cloud (Microsoft Entra ID) Group (Interactive Sign-In)
Connects interactively to Microsoft Graph and adds users from `nowi_ksiegowi.txt` (appending `@firma.pl` to short logins):
```powershell
.\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" `
    -UsersFile ".\nowi_ksiegowi.txt" `
    -Mode Cloud `
    -UpnSuffix "firma.pl"
```

### Example 7: Hybrid Mode (`-Mode Both`) — Local AD + Cloud Entra ID
Adds users to the `Dzial_Ksiegowosci` group in both On-Premises Active Directory and Cloud Microsoft Entra ID:
```powershell
.\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" `
    -UsersFile ".\nowi_ksiegowi.txt" `
    -Mode Both `
    -UpnSuffix "firma.pl" `
    -ExportReportPath "C:\Logs\Hybrid_Group_Assignment.csv" `
    -Force
```

---

## ⚙️ Parameter Reference

| Parameter | Alias(es) | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-Group` | `-Identity`, `-GroupName`, `-Grupa`, `-g` | `string` | — | Target group name, `SamAccountName`, `DistinguishedName`, `GUID`, or `ObjectId`. |
| `-UsersFile` | `-FilePath`, `-Path`, `-InputFile`, `-f` | `string` | — | Path to a `.txt` or `.csv` file containing user logins. |
| `-Users` | `-Members`, `-Loginy`, `-u` | `string[]` | — | Direct list of user logins (`SamAccountName` or `UPN`) to add. |
| `-Mode` | `-Provider`, `-Environment`, `-Target` | `string` | `'Local'` | Target environment: `'Local'` (`'AD'`, `'OnPremises'`), `'Cloud'` (`'EntraID'`, `'AzureAD'`), or `'Both'`. |
| `-CsvColumn` | — | `string` | Auto | Column name when `-UsersFile` is a `.csv` file. |
| `-UpnSuffix` | `-Domain`, `-DomainSuffix` | `string` | — | Domain suffix appended to short logins in Cloud mode (e.g., `contoso.com`). |
| `-DomainController` | `-Server`, `-DC` | `string` | Auto | Specific Active Directory Domain Controller FQDN/IP for Local mode. |
| `-Credential` | — | `PSCredential` | Current User | Credentials for Local Active Directory authentication. |
| `-CreateGroupIfMissing` | — | `switch` | `$false` | Creates the target security group automatically if it does not exist. |
| `-GroupOU` | — | `string` | Default Users/OU | Target Organizational Unit DN when creating a missing group in Local AD. |
| `-GroupScope` | — | `string` | `'Global'` | Group scope when creating a group in Local AD (`Global`, `Universal`, `DomainLocal`). |
| `-GenerateSampleFile` | `-CreateTemplate`, `-Sample` | `switch` | `$false` | Generates a sample `nowi_ksiegowi.txt` file and exits. |
| `-ExportReportPath` | `-ExportCsv`, `-ReportPath` | `string` | — | File path to export per-user membership assignment results as a UTF-8 CSV. |
| `-TenantId` | `-Tenant`, `-DirectoryId` | `string` | — | Microsoft Entra ID Tenant ID for Cloud authentication. |
| `-ClientId` | `-AppId`, `-ApplicationId` | `string` | — | Microsoft Entra ID Application (Client) ID for non-interactive Cloud auth. |
| `-ClientSecret` | `-Secret` | `string` | — | Microsoft Entra ID Client Secret for non-interactive Cloud auth. |
| `-ClientSecretSecure` | — | `SecureString` | — | SecureString containing the Entra ID Client Secret. |
| `-CertificateThumbprint` | `-Thumbprint` | `string` | — | Certificate thumbprint for non-interactive Cloud authentication. |
| `-AdminUserPrincipalName` | `-AdminUPN` | `string` | — | Admin UPN hint for interactive Cloud sign-in. |
| `-DryRun` | `-Simulate`, `-Preview` | `switch` | `$false` | Simulates the operation without making changes in AD or Entra ID. |
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
C:\Logs\<yyyyMMdd_HHmmss>-Add-UsersToGroup-<ComputerName>-<UserName>.logs
```

Each log entry includes a millisecond-precision timestamp, severity level (`INFO`, `STEP`, `SUCCESS`, `WARN`, `ERROR`), and detailed context for auditing and troubleshooting.

---

## 📌 Version History

* **v1.2.0 (2026-10-17)**
  * Implemented automatic UAC elevation prompt with language-independent SID verification (`S-1-5-32-544` / `BuiltInAdministratorsSid`) supporting Polish (`Administratorzy`) and English (`Administrators`) Windows environments.
  * Added dual-mode support for Local Active Directory (`-Mode Local` / `AD`) and Cloud Microsoft Entra ID (`-Mode Cloud` / `EntraID` / `Both`) via Microsoft Graph SDK.
  * Added non-interactive App-Only Entra ID authentication (Client Secret & X.509 Certificate) and comprehensive setup guide.
  * Added centralized audit logging to `C:\Logs\<DateTime>-Add-UsersToGroup-<ComputerName>-<UserName>.logs`.
  * Added zero-parameter interactive help (`-Help` / `-h`), input sanitization, duplicate membership checks, `.txt` and `.csv` input support, and CSV report export.

---

## 👨‍💻 Author & Contact

* **Author:** Roman Pindela
* **Email:** [roman.pindela@gmail.com](mailto:roman.pindela@gmail.com)
* **GitHub:** [https://github.com/romanpindela](https://github.com/romanpindela)
* **License:** MIT
