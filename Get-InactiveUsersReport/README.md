# Get-InactiveUsersReport

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS-0078D4.svg)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Graph%20SDK-008272.svg)](https://learn.microsoft.com/graph/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade PowerShell security auditing script that identifies **inactive user accounts** (e.g., enabled accounts that have not logged into the domain or cloud tenant for more than **90 days**) across **On-Premises Active Directory (AD DS)** and **Microsoft Entra ID (Cloud AD)**, and exports a structured UTF-8 CSV report to `C:\Logs\`.

---

## ✨ Key Features

1. **Zero-Parameter Interactive Help (`-Help` / `-h`)**
   Running `.\Get-InactiveUsersReport.ps1` without parameters or with `-h` / `-Help` displays complete console help, usage examples, Microsoft Entra ID non-interactive configuration instructions, version history, and author contact details without modifying the system.
2. **Inactive Account Auditing (`> 90 Days` Default, Configurable via `-InactiveDays`)**
   Calculates the cutoff date (`$DataGraniczna = (Get-Date).AddDays(-$InactiveDays)`) and discovers enabled accounts whose last authentication occurred before the cutoff date:
   ```powershell
   $DataGraniczna = (Get-Date).AddDays(-90)

   Get-ADUser -Filter {LastLogonDate -lt $DataGraniczna -and Enabled -eq $true} -Properties LastLogonDate, DisplayName |
   Select-Object Name, SamAccountName, LastLogonDate |
   Export-Csv -Path "C:\Logs\<datagodzina>Get-InactiveUsersReport<nazwaserweraad>nieaktywni_uzytkownicy.csv" -NoTypeInformation -Encoding UTF8
   ```
3. **Dual Directory Mode (`-Provider AD | EntraID | Both`)**
   * **Local Active Directory (`AD` / `Local` / `LocalAD` / `OnPrem`):** Queries On-Premises Windows Server Active Directory via `Get-ADUser` (`ActiveDirectory` RSAT module), supporting custom Organizational Units (`-SearchBase`) and specific Domain Controllers (`-DomainController`).
   * **Cloud Active Directory (`EntraID` / `Cloud` / `CloudAD` / `AzureAD`):** Queries Microsoft Entra ID via Microsoft Graph PowerShell SDK (`Get-MgUser -Property SignInActivity`), evaluating both `LastSignInDateTime` and `LastNonInteractiveSignInDateTime`. Supports both interactive admin sign-in and unattended App-Only authentication (Client Secret or X.509 Certificate).
   * **Hybrid Mode (`Both`):** Audits both Local On-Premises AD DS and Cloud Microsoft Entra ID in a single run and consolidates the findings into a unified CSV report.
4. **Automated CSV Naming in `C:\Logs\`**
   By default, exports the UTF-8 CSV report to:
   ```text
   C:\Logs\<yyyyMMdd_HHmmss>Get-InactiveUsersReport<ADServerName>nieaktywni_uzytkownicy.csv
   ```
   You can also override the destination path at any time with `-OutputPath` (`-CsvPath`) or switch between extended audit columns and the classic 3-column output (`Name, SamAccountName, LastLogonDate`) using `-SimpleCsv`.
5. **Language-Independent UAC Auto-Elevation (PL / EN Windows)**
   Verifies Administrator privileges using the well-known Windows SID `S-1-5-32-544` (`BuiltInAdministratorsSid`), ensuring full compatibility across Polish (`Administratorzy`) and English (`Administrators`) editions of Windows Desktop and Windows Server.
6. **Detailed Execution Logging (`C:\Logs`)**
   Automatically records timestamped UTF-8 execution logs at:
   ```text
   C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs
   ```

---

## 📋 Prerequisites

* **Operating System:** Windows Server 2016/2019/2022/2025 or Windows 10/11 (Polish or English locale).
* **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+.
* **For Local Active Directory Mode (`-Provider AD` / `LocalAD`):**
  * Active Directory module for Windows PowerShell (`RSAT-AD-PowerShell`).
  ```powershell
  # Install on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

  # Install on Windows Server:
  Install-WindowsFeature -Name RSAT-AD-PowerShell
  ```
* **For Cloud Microsoft Entra ID Mode (`-Provider EntraID` / `CloudAD`):**
  * `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users` modules.
  * Microsoft Entra ID P1/P2 license in the tenant (required by Microsoft Graph API to expose the `signInActivity` resource).
  ```powershell
  Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users -Scope CurrentUser -Repository PSGallery -Force
  ```

---

## 🔓 Unblocking the Script After Download

After downloading or cloning this script from GitHub, Windows attaches a `Zone.Identifier` alternate data stream to the `.ps1` file. Unblock the file before running it:

```powershell
Unblock-File -Path .\Get-InactiveUsersReport.ps1
```

---

## 🔐 Non-Interactive Authentication in Microsoft Entra ID (Microsoft Graph SDK)

To run `Get-InactiveUsersReport.ps1` unattended (e.g., in Windows Task Scheduler, SIEM compliance pipelines, or automated monthly security audits) using **only API credentials and Microsoft Graph SDK Application Permissions**:

### Step 1: Register an Application in Microsoft Entra ID
1. Sign in to the [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Navigate to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Set **Name** to `EntraID-InactiveUsers-Auditor`.
4. Under **Supported account types**, select *Accounts in this organizational directory only (Single tenant)*.
5. Click **Register** and copy:
   * **Application (client) ID** (`-ClientId`)
   * **Directory (tenant) ID** (`-TenantId`)

### Step 2: Assign Microsoft Graph Application Permissions
1. Inside the registered application, go to **Manage** > **API permissions** > **Add a permission**.
2. Select **Microsoft Graph** > **Application permissions** *(do not select Delegated permissions for unattended execution)*.
3. Search for and add the following permissions required to query user profiles and `SignInActivity`:
   * `AuditLog.Read.All` *(Required to read `SignInActivity` / `LastSignInDateTime`)*
   * `User.Read.All` *(Required to read user profiles and account status)*
   * `Directory.Read.All` *(Required to read directory metadata)*
4. Click **Add permissions**.
5. Click **Grant admin consent for \<Your Organization\>** and confirm that all permissions display a green checkmark.

### Step 3: Create API Credentials (Option A: Client Secret or Option B: X.509 Certificate)

#### Option A: Client Secret (API Key)
1. Go to **Manage** > **Certificates & secrets** > **Client secrets** > **New client secret**.
2. Enter a description (e.g., `InactiveUsersAuditSecret`), select an expiration period, and click **Add**.
3. Copy the **Value** immediately and pass it to the script:
   ```powershell
   .\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90 `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -ClientSecret "YourClientSecretValueHere"
   ```

#### Option B: X.509 Certificate (Recommended for Production Scheduled Tasks)
1. Generate a self-signed certificate in PowerShell and export the `.cer` public key:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=EntraInactiveUsersAuditor" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable -KeySpec Signature `
       -KeyLength 2048 -HashAlgorithm SHA256 `
       -NotAfter (Get-Date).AddYears(2)
   Export-Certificate -Cert $cert -FilePath "C:\Logs\EntraInactiveUsersAuditor.cer"
   ```
2. In Entra Admin Center, navigate to **Manage** > **Certificates & secrets** > **Certificates** > **Upload certificate**, and upload `C:\Logs\EntraInactiveUsersAuditor.cer`.
3. Run the script non-interactively with `-CertificateThumbprint`:
   ```powershell
   .\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90 `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -CertificateThumbprint $cert.Thumbprint
   ```

---

## 🚀 Usage Examples

### 1. Display Help & Usage Instructions (Zero Parameters or `-h`)
```powershell
.\Get-InactiveUsersReport.ps1
# or explicitly:
.\Get-InactiveUsersReport.ps1 -h
.\Get-InactiveUsersReport.ps1 -Help
```

### 2. Standard Local Active Directory Audit (> 90 Days Inactive)
Finds all enabled users in Local AD who have not logged in for over 90 days and exports the CSV report to `C:\Logs\<datagodzina>Get-InactiveUsersReport<nazwaserweraad>nieaktywni_uzytkownicy.csv`:
```powershell
.\Get-InactiveUsersReport.ps1 -Run
```

### 3. Export Classic 3-Column CSV (`Name`, `SamAccountName`, `LastLogonDate`)
```powershell
.\Get-InactiveUsersReport.ps1 -InactiveDays 90 -SimpleCsv
```

### 4. Scope Local AD Audit to a Specific OU & Include Accounts That Never Logged On
```powershell
.\Get-InactiveUsersReport.ps1 -Provider LocalAD `
    -InactiveDays 60 `
    -DomainController "DC01.firma.local" `
    -SearchBase "OU=Pracownicy,DC=firma,DC=local" `
    -IncludeNeverLoggedOn
```

### 5. Audit Cloud Microsoft Entra ID Interactively
Prompts for Microsoft Entra administrator sign-in and exports cloud users inactive for over 90 days:
```powershell
.\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90
```

### 6. Audit Both Local Active Directory and Cloud Microsoft Entra ID (`-Provider Both`)
```powershell
.\Get-InactiveUsersReport.ps1 -Provider Both -InactiveDays 90
```

### 7. Custom CSV Output Path & Semicolon Delimiter (Polish Excel Compatible)
```powershell
.\Get-InactiveUsersReport.ps1 -InactiveDays 90 `
    -OutputPath "C:\Logs\Raport_Nieaktywni_90dni.csv" `
    -Delimiter ";"
```

### 8. Dry-Run Simulation Mode (Test Without Live AD / Domain Connectivity)
```powershell
.\Get-InactiveUsersReport.ps1 -Run -DryRun
```

---

## 📊 CSV Output Columns

### Default Extended Audit View
| Column Name | Description |
| :--- | :--- |
| `Name` | Full account name |
| `SamAccountName` | User logon name (`sAMAccountName` in AD / `OnPremisesSamAccountName` or `MailNickname` in Entra ID) |
| `DisplayName` | Display name of the user |
| `UserPrincipalName` | UPN / Email login (`user@domain.com`) |
| `LastLogonDate` | Timestamp of last recorded domain or cloud sign-in |
| `DaysInactive` | Total days elapsed since `LastLogonDate` (or `NeverLoggedOn`) |
| `Enabled` | Account enabled status (`True` / `False`) |
| `Department` | Organizational department |
| `Title` | Job title |
| `WhenCreated` | Account creation timestamp |
| `DirectorySource` | `'LocalAD'` or `'EntraID'` |
| `ServerOrTenant` | Queried Domain Controller FQDN or Entra ID Tenant ID |

### Classic Simple View (`-SimpleCsv`)
| Column Name | Description |
| :--- | :--- |
| `Name` | Full account name |
| `SamAccountName` | User logon name |
| `LastLogonDate` | Timestamp of last recorded domain or cloud sign-in |

---

## ⚙️ Parameters Reference

| Parameter | Alias | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-Run` | `-Audit`, `-All` | `Switch` | `$false` | Executes the audit using default settings (90 days, Local AD). |
| `-InactiveDays` | `-Days`, `-ThresholdDays` | `Int32` | `90` | Number of days of inactivity (`$DataGraniczna = (Get-Date).AddDays(-$InactiveDays)`). |
| `-Provider` | `-Mode`, `-Target`, `-Directory` | `String` | `'AD'` | Target directory: `'AD'`/`'LocalAD'`, `'EntraID'`/`'CloudAD'`, or `'Both'`. |
| `-OutputPath` | `-CsvPath`, `-ExportCsv`, `-Path` | `String` | `C:\Logs\...` | Custom CSV report file path. Defaults to `C:\Logs\<datagodzina>Get-InactiveUsersReport<ADServer>nieaktywni_uzytkownicy.csv`. |
| `-Delimiter` | — | `String` | `','` | CSV delimiter (`','`, `';'`, or Tab). |
| `-SimpleCsv` | — | `Switch` | `$false` | Exports strictly `Name, SamAccountName, LastLogonDate`. |
| `-SearchBase` | `-OU`, `-OrganizationalUnit` | `String` | Domain Root | Organizational Unit Distinguished Name (DN) to scope Local AD queries. |
| `-DomainController` | `-Server`, `-DC` | `String` | Auto-Discovered | Specific Active Directory Domain Controller FQDN or IP. |
| `-Department` | — | `String` | — | Filter results by partial or exact Department name. |
| `-IncludeDisabled` | — | `Switch` | `$false` | Includes disabled accounts (`Enabled -eq $false`) in the report. |
| `-IncludeNeverLoggedOn` | — | `Switch` | `$false` | Includes enabled accounts that have never logged on and were created before `$DataGraniczna`. |
| `-PassThru` | — | `Switch` | `$false` | Outputs discovered inactive user objects to the PowerShell pipeline. |
| `-TenantId` | `-Tenant`, `-DirectoryId` | `String` | — | Microsoft Entra ID Tenant ID for Cloud AD authentication. |
| `-ClientId` | `-AppId`, `-ApplicationId` | `String` | — | Microsoft Entra ID Application (Client) ID for non-interactive auth. |
| `-ClientSecret` | `-Secret` | `String` | — | Microsoft Entra ID Client Secret string for non-interactive auth. |
| `-ClientSecretSecure` | — | `SecureString` | — | Microsoft Entra ID Client Secret as a `SecureString`. |
| `-CertificateThumbprint` | `-Thumbprint` | `String` | — | X.509 Certificate Thumbprint for non-interactive auth. |
| `-DryRun` | `-Simulate`, `-Preview` | `Switch` | `$false` | Simulates the audit with sample data without requiring live AD/Entra connectivity. |
| `-SkipAdminCheck` | — | `Switch` | `$false` | Skips automatic UAC Administrator privilege elevation check. |
| `-LogPath` | `-l`, `-Log` | `String` | `C:\Logs\...` | Custom log file path. Defaults to `C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<PC>-<User>.logs`. |
| `-NoLog` | — | `Switch` | `$false` | Disables writing execution log files to disk. |
| `-Help` | `-h` | `Switch` | `$false` | Displays the console help screen and exits. |

---

## 📝 Logging & Output Files

By default, every execution writes two files into `C:\Logs\`:
1. **CSV Audit Report:**
   ```text
   C:\Logs\<yyyyMMdd_HHmmss>Get-InactiveUsersReport<ADServerName>nieaktywni_uzytkownicy.csv
   ```
2. **Detailed Execution Log:**
   ```text
   C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs
   ```

---

## 📜 Version History

* **1.2.0 (2026-10-17)**
  * Implemented automatic UAC elevation prompt that relaunches the script with Administrator privileges if missing.
  * Replaced manual administrator group name checks with language-independent SID verification (`S-1-5-32-544` / `BuiltInAdministratorsSid`) supporting both Polish (`Administratorzy`) and English (`Administrators`) Windows systems.
  * Added dual directory support for Local Active Directory (`AD` / `LocalAD`) and Cloud Microsoft Entra ID (`EntraID` / `CloudAD`), plus `Both`.
  * Added automated UTF-8 CSV export to `C:\Logs\<datagodzina>Get-InactiveUsersReport<nazwaserweraad>nieaktywni_uzytkownicy.csv` and detailed execution logging to `C:\Logs\<dataigodzina>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs`.

---

## 👨‍💻 Author & Contact

* **Author:** Roman Pindela
* **Email:** [roman.pindela@gmail.com](mailto:roman.pindela@gmail.com)
* **GitHub:** [https://github.com/romanpindela](https://github.com/romanpindela)
* **Version:** 1.2.0
* **License:** MIT
