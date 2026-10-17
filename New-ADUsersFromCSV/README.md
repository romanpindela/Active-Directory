# New-ADUsersFromCSV

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS-0078D4.svg)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Graph%20SDK-008272.svg)](https://learn.microsoft.com/graph/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade PowerShell automation script for **bulk user provisioning from a CSV file** (`uzytkownicy.csv`) into **On-Premises Active Directory (AD DS)** and/or **Microsoft Entra ID (Azure AD)**. Instead of manually clicking through each employee in graphical consoles (`dsa.msc` / Active Directory Users and Computers or Microsoft Entra Admin Center), administrators can prepare a standard CSV file with columns such as `SamAccountName`, `Name`, `GivenName`, `Surname`, `Password`, and `Department`, and provision accounts in bulk with full audit logging, progress tracking, and input validation.

---

## ✨ Key Features

1. **Zero-Parameter Interactive Help (`-Help` / `-h`)**
   Running `.\New-ADUsersFromCSV.ps1` without parameters or with `-h` / `-Help` displays comprehensive console documentation, CSV column specifications, non-interactive Entra ID setup instructions, usage examples, script version, and author details without making any changes.
2. **Bulk User Creation from CSV (`uzytkownicy.csv`)**
   Reads user records from CSV files with core columns:
   - `SamAccountName` — Unique user logon name (up to 20 characters)
   - `Name` — Full object/display name
   - `GivenName` — First name
   - `Surname` — Last name
   - `Password` — Initial password (securely converted to `[System.Security.SecureString]`)
   - `Department` — Department name
   Plus optional extended columns if present in the CSV: `UserPrincipalName`, `DisplayName`, `EmailAddress` / `Mail`, `Title` / `JobTitle`, `Company`, `Office`, `MobilePhone` / `TelephoneNumber`, `OU` / `OrganizationalUnit` / `Path`, `Groups`, `Enabled`, `ChangePasswordAtLogon`.
3. **Dual Directory Support (`-Provider AD | EntraID | Both`)**
   - **`AD` (Default):** Provisions accounts in local Windows Server Active Directory using `New-ADUser` (`ActiveDirectory` RSAT module).
   - **`EntraID`:** Provisions cloud accounts in Microsoft Entra ID / M365 using `New-MgUser` (`Microsoft.Graph.Users` SDK), supporting both interactive sign-in and unattended App-Only authentication (Client Secret or X.509 Certificate).
   - **`Both`:** Provisions accounts across both local Active Directory and Microsoft Entra ID.
4. **Automatic CSV Delimiter Detection (`-Delimiter Auto`)**
   Automatically detects whether the CSV file is comma-delimited (`,`), semicolon-delimited (`;`, standard in Polish Excel exports), or tab-delimited.
5. **Language-Independent UAC Auto-Elevation (PL / EN Windows)**
   Verifies Administrator privileges using the well-known Windows SID `S-1-5-32-544` (`BuiltInAdministratorsSid`), ensuring compatibility on both Polish (`Administratorzy`) and English (`Administrators`) editions of Windows Desktop and Windows Server.
6. **Real-Time Granular Progress Bar (`Write-Progress`)**
   Displays a live progress indicator showing `[Row/Total]`, percentage completed, active `SamAccountName`, full name, and department.
7. **Centralized Audit Logging (`C:\Logs`)**
   Automatically records timestamped UTF-8 execution logs (with plaintext passwords never written to disk) at:
   `C:\Logs\<yyyyMMdd_HHmmss>-New-ADUsersFromCSV-<ComputerName>-<UserName>.logs`

---

## 📋 Prerequisites

* **Operating System:** Windows Server 2016/2019/2022/2025 or Windows 10/11 (Polish or English locale).
* **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+.
* **For On-Premises Active Directory (`-Provider AD`):**
  * Active Directory module for Windows PowerShell (`RSAT-AD-PowerShell`).
  * Domain Account with permissions to create/modify users in the target Organizational Unit (OU).
  ```powershell
  # Install on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

  # Install on Windows Server:
  Install-WindowsFeature -Name RSAT-AD-PowerShell
  ```
* **For Microsoft Entra ID (`-Provider EntraID`):**
  * `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users` (and `Microsoft.Graph.Groups` when assigning groups).
  ```powershell
  Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force
  ```

---

## 🔓 Unblocking the Script After Download

After downloading or cloning this script from GitHub, Windows marks the `.ps1` file with a `Zone.Identifier` alternate data stream. Unblock it before execution:

```powershell
Unblock-File -Path .\New-ADUsersFromCSV.ps1
```

---

## 📄 CSV File Structure (`uzytkownicy.csv`)

### Required Columns

| Column Name | Description | Example |
| :--- | :--- | :--- |
| `SamAccountName` | Unique login name (1–20 chars, alphanumeric / `.` / `_` / `-`) | `jkowalski` |
| `Name` | Full name / Active Directory object name | `Jan Kowalski` |
| `GivenName` | First name | `Jan` |
| `Surname` | Last name | `Kowalski` |
| `Password` | Initial password (meets domain/Entra complexity rules) | `Start123!@#2026` |
| `Department` | Employee department | `IT` |

### Sample `uzytkownicy.csv`

```csv
SamAccountName,Name,GivenName,Surname,Password,Department
jkowalski,Jan Kowalski,Jan,Kowalski,Start123!@#2026,IT
anowak,Anna Nowak,Anna,Nowak,BezpieczneHaslo9!,HR
pwisniewski,Piotr Wisniewski,Piotr,Wisniewski,KontoStart#2026,Finanse
mkaminska,Magdalena Kaminska,Magdalena,Kaminska,HasloStartowe$26,Sprzedaz
tzelazny,Tomasz Zelazny,Tomasz,Zelazny,AdminPass!9876,Logistyka
```

> **Tip:** You can generate this template automatically at any time by running:
> ```powershell
> .\New-ADUsersFromCSV.ps1 -GenerateSampleCsv -CsvPath ".\uzytkownicy.csv"
> ```

---

## 🔐 Non-Interactive Authentication in Microsoft Entra ID (Microsoft Graph SDK)

To run `New-ADUsersFromCSV.ps1` unattended (e.g., in Windows Task Scheduler, HR onboarding pipelines, or background automation) using **only API credentials and Microsoft Graph SDK Application Permissions**:

### Step 1: Register an Application in Microsoft Entra ID
1. Sign in to the [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Navigate to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Set **Name** to `AD-CSV-User-Provisioning-Automation`.
4. Under **Supported account types**, select *Accounts in this organizational directory only (Single tenant)*.
5. Click **Register** and copy:
   * **Application (client) ID** (`-ClientId`)
   * **Directory (tenant) ID** (`-TenantId`)

### Step 2: Assign Microsoft Graph Application Permissions
1. Inside the registered application, go to **Manage** > **API permissions** > **Add a permission**.
2. Select **Microsoft Graph** > **Application permissions** *(do not choose Delegated permissions for unattended execution)*.
3. Search for and select:
   * `User.ReadWrite.All` *(Required to create and update user accounts)*
   * `Directory.ReadWrite.All` *(Required for directory properties and group memberships)*
   * `GroupMember.ReadWrite.All` *(Optional: required when using `-DefaultGroups` or the CSV `Groups` column)*
4. Click **Add permissions**.
5. Click **Grant admin consent for \<Your Organization\>** and confirm that all permissions show a green checkmark.

### Step 3: Create API Credentials (Option A: Client Secret or Option B: X.509 Certificate)

#### Option A: Client Secret (API Key)
1. Go to **Manage** > **Certificates & secrets** > **Client secrets** > **New client secret**.
2. Provide a description (e.g., `CSVProvisioningKey`), choose an expiration period, and click **Add**.
3. Copy the **Value** immediately and pass it to the script:
   ```powershell
   .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" `
       -Provider EntraID `
       -UpnSuffix "contoso.com" `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -ClientSecret "YourClientSecretValueHere" `
       -Force
   ```

#### Option B: X.509 Certificate (Recommended for Production)
1. Generate a self-signed certificate in PowerShell and export the `.cer` public key:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=EntraUserProvisioning" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable -KeySpec Signature `
       -KeyLength 2048 -HashAlgorithm SHA256 `
       -NotAfter (Get-Date).AddYears(2)
   Export-Certificate -Cert $cert -FilePath "C:\Logs\EntraUserProvisioning.cer"
   ```
2. In Entra Admin Center, go to **Manage** > **Certificates & secrets** > **Certificates** > **Upload certificate**, and upload `C:\Logs\EntraUserProvisioning.cer`.
3. Run the script non-interactively with `-CertificateThumbprint`:
   ```powershell
   .\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" `
       -Provider EntraID `
       -UpnSuffix "contoso.com" `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -CertificateThumbprint $cert.Thumbprint `
       -Force
   ```

---

## 🚀 Usage Examples

### 1. Display Help & Entra ID Setup Guide
```powershell
.\New-ADUsersFromCSV.ps1
# or
.\New-ADUsersFromCSV.ps1 -Help
.\New-ADUsersFromCSV.ps1 -h
```

### 2. Generate a Sample CSV File (`uzytkownicy.csv`)
```powershell
.\New-ADUsersFromCSV.ps1 -GenerateSampleCsv -CsvPath ".\uzytkownicy.csv"
```

### 3. Dry-Run / Simulation Mode (Validate CSV Without Creating Accounts)
```powershell
.\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" -DryRun
```

### 4. Bulk Create Users in Local Active Directory (AD DS)
```powershell
.\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" `
    -TargetOU "OU=Pracownicy,DC=firma,DC=local" `
    -UpnSuffix "firma.local"
```

### 5. Bulk Create Users in AD DS, Add to Default Groups, and Export Report
```powershell
.\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" `
    -TargetOU "OU=Users,OU=HQ,DC=corp,DC=com" `
    -DefaultGroups "VPN-Users", "Intranet-Readers" `
    -ExportReportPath "C:\Logs\CreatedUsersReport.csv" `
    -Force
```

### 6. Update Existing Users If They Already Exist (`-UpdateExisting`)
```powershell
.\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" `
    -TargetOU "OU=Pracownicy,DC=firma,DC=local" `
    -UpdateExisting -Force
```

### 7. Bulk Create Users in Microsoft Entra ID (Interactive Admin Sign-In)
```powershell
.\New-ADUsersFromCSV.ps1 -CsvPath ".\uzytkownicy.csv" `
    -Provider EntraID `
    -UpnSuffix "yourtenant.onmicrosoft.com"
```

---

## ⚙️ Parameters Reference

| Parameter | Alias | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-CsvPath` | `-Path`, `-File` | `String` | — | Path to the CSV file containing user definitions (e.g., `.\uzytkownicy.csv`). |
| `-Provider` | `-Target`, `-Mode` | `String` | `'AD'` | Target directory: `'AD'` (local Active Directory), `'EntraID'` (Microsoft Graph), or `'Both'`. |
| `-Delimiter` | — | `String` | `'Auto'` | CSV field delimiter (`'Auto'`, `','`, `';'`, or Tab). |
| `-TargetOU` | `-OU` | `String` | Domain Users Container | Target Organizational Unit Distinguished Name in local Active Directory. |
| `-UpnSuffix` | `-Domain` | `String` | Auto-resolved | Domain suffix for `UserPrincipalName` (e.g., `firma.local` or `contoso.com`). |
| `-DomainController` | `-Server`, `-DC` | `String` | Default DC | Specific Active Directory Domain Controller FQDN or IP. |
| `-DefaultGroups` | `-Groups` | `String[]` | — | Security or distribution groups to assign to all created accounts. |
| `-AccountEnabled` | — | `Boolean` | `$true` | Enables newly provisioned user accounts immediately. |
| `-ChangePasswordAtLogon` | — | `Boolean` | `$true` | Forces the user to change their password upon next login. |
| `-UpdateExisting` | — | `Switch` | `$false` | Updates existing accounts (`Department`, `GivenName`, `Surname`, `DisplayName`) instead of skipping. |
| `-AutoGenerateMissingPasswords` | — | `Switch` | `$false` | Generates a 16-character random password if the CSV `Password` field is blank. |
| `-UsageLocation` | — | `String` | `'PL'` | Two-letter ISO 3166 country code for Entra ID users. |
| `-GenerateSampleCsv` | `-Sample` | `Switch` | `$false` | Generates a ready-to-use sample `uzytkownicy.csv` file and exits. |
| `-ExportReportPath` | — | `String` | — | Optional file path to save the CSV execution report. |
| `-TenantId` | `-Tenant` | `String` | — | Microsoft Entra ID Tenant ID for non-interactive Graph authentication. |
| `-ClientId` | `-AppId` | `String` | — | Microsoft Entra ID Application Client ID for non-interactive Graph authentication. |
| `-ClientSecret` | `-Secret` | `String` | — | Microsoft Entra ID Client Secret for non-interactive Graph authentication. |
| `-ClientSecretSecure` | — | `SecureString` | — | Microsoft Entra ID Client Secret as a `SecureString`. |
| `-CertificateThumbprint` | `-Thumbprint` | `String` | — | X.509 Certificate Thumbprint for non-interactive Graph authentication. |
| `-DryRun` | `-Simulate` | `Switch` | `$false` | Validates the CSV and simulates user provisioning without making directory changes. |
| `-SkipAdminCheck` | — | `Switch` | `$false` | Skips automatic UAC elevation check. |
| `-LogPath` | `-l`, `-Log` | `String` | `C:\Logs\...` | Custom log file path. Defaults to `C:\Logs\<yyyyMMdd_HHmmss>-New-ADUsersFromCSV-<PC>-<User>.logs`. |
| `-NoLog` | — | `Switch` | `$false` | Disables writing log files to disk. |
| `-Force` | — | `Switch` | `$false` | Bypasses interactive confirmation prompts (`Y/N` / `T/N`). |
| `-Help` | `-h` | `Switch` | `$false` | Displays full console help and exits. |

---

## 📝 Logging

By default, every execution creates a detailed UTF-8 log file in `C:\Logs`:

```text
C:\Logs\<yyyyMMdd_HHmmss>-New-ADUsersFromCSV-<ComputerName>-<UserName>.logs
```

Passwords are never written to the log file.

---

## 📜 Version History

* **1.0.0 (2026-10-17)**
  * Initial release of `New-ADUsersFromCSV.ps1`.
  * Bulk user creation from CSV (`SamAccountName`, `Name`, `GivenName`, `Surname`, `Password`, `Department`, plus extended attributes).
  * Dual provider support: On-Premises Active Directory (`New-ADUser`) and Microsoft Entra ID (`New-MgUser`).
  * Non-interactive Entra ID authentication support (Client Secret & X.509 Certificate) with setup guide in `-Help` and `README.md`.
  * Language-independent SID UAC auto-elevation (`S-1-5-32-544`), auto-delimiter detection, `Write-Progress` bar, and centralized logging to `C:\Logs`.

---

## 👨‍💻 Author & Contact

* **Author:** Roman Pindela
* **Email:** [roman.pindela@gmail.com](mailto:roman.pindela@gmail.com)
* **GitHub:** [https://github.com/romanpindela](https://github.com/romanpindela)
* **Version:** 1.0.0
* **License:** MIT
