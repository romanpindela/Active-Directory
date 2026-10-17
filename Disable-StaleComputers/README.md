# Disable-StaleComputers

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS-0078D4.svg)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Graph%20SDK-008272.svg)](https://learn.microsoft.com/graph/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade PowerShell directory hygiene and security automation script designed to **bulk disable or remove stale computer accounts** (workstations and cloud endpoints) that have not reported their presence in the domain or cloud tenant for an extended period (default: **180 days**).

When organizations replace workstations on a local network or decommission laptops, obsolete computer objects often remain active in Active Directory and Microsoft Entra ID. `Disable-StaleComputers.ps1` automates the discovery, safe disabling (`Disable-ADAccount` / `Set-ADComputer` / `Update-MgDevice`), quarantine OU relocation (`Move-ADObject`), or permanent deletion (`Remove-ADComputer` / `Remove-MgDevice`) of inactive computer accounts across **Local Active Directory (`-Mode Local` / `AD`)**, **Cloud Microsoft Entra ID (`-Mode Cloud` / `EntraID`)**, and **Hybrid (`-Mode Both`)** environments.

---

## ✨ Key Features

1. **Zero-Parameter Interactive Help (`-Help` / `-h`)**
   Running `.\Disable-StaleComputers.ps1` without parameters or with `-h` / `-Help` displays full console documentation, examples, step-by-step non-interactive Entra ID setup instructions, script version (`1.2.0`), and author details without modifying any directory objects.
2. **Core Active Directory Stale Computer Cleanup (`> 180 Days`)**
   Implements and expands upon the core Active Directory workstation cleanup pattern:
   ```powershell
   # Find computers that have not rotated their machine password / logged on for 180 days
   $StareDni = (Get-Date).AddDays(-180)

   Get-ADComputer -Filter {PasswordLastSet -lt $StareDni} -Properties PasswordLastSet |
   ForEach-Object {
       # Safely disable the computer account (or use Set-ADComputer / Remove-ADComputer)
       Disable-ADAccount -Identity $_.DistinguishedName
       Write-Host "Wyłączono nieaktywny komputer: $($_.Name)" -ForegroundColor Yellow
   }
   ```
3. **Dual Directory Environment Support (`-Mode Local | Cloud | Both`)**
   - **`Local` (`AD` / `LocalAD` / `OnPremises` — Default):** Uses the Windows Server `ActiveDirectory` module (`Get-ADComputer`, `Disable-ADAccount`, `Set-ADComputer`, `Remove-ADComputer`, `Move-ADObject`) to clean up domain computer accounts.
   - **`Cloud` (`EntraID` / `CloudAD` / `AzureAD`):** Uses the **Microsoft Graph PowerShell SDK** (`Get-MgDevice`, `Update-MgDevice`, `Remove-MgDevice`) to identify and disable/delete stale cloud devices based on `ApproximateLastSignInDateTime`, supporting both interactive sign-in and unattended App-Only authentication (Client Secret or X.509 Certificate).
   - **`Both`:** Cleans up stale computers across both On-Premises Active Directory and Cloud Microsoft Entra ID in a single run.
4. **Built-In Safety Guardrails & Exclusion Filters**
   - **Domain Controller Protection:** Automatically detects and skips Domain Controllers (`PrimaryGroupID -eq 516` or `OU=Domain Controllers`) so critical infrastructure is never disabled or deleted.
   - **Workstation-First Safety Default:** Excludes Windows Server OS computer accounts by default unless `-IncludeServers` is explicitly specified.
   - **Custom Exclusions (`-ExcludeComputers`):** Supports exact computer names or wildcard patterns (e.g., `"SRV-*"`, `"KIOSK-*"`).
   - **Quarantine OU Move & Description Stamping:** Optionally stamps the computer `Description` with the disable date (`-StampDescription`) and moves disabled accounts to a dedicated Quarantine OU (`-TargetOU`).
5. **Language-Independent UAC Auto-Elevation (PL / EN Windows)**
   Verifies Administrator privileges using the well-known Windows SID `S-1-5-32-544` (`BuiltInAdministratorsSid`), ensuring full compatibility across both Polish (`Administratorzy`) and English (`Administrators`) editions of Windows Desktop and Windows Server.
6. **Centralized Audit Logging & CSV Reporting (`C:\Logs`)**
   - Automatically writes detailed, timestamped UTF-8 execution logs by default to:
     `C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-<ComputerName>-<UserName>.logs`
   - Exports a structured UTF-8 CSV report of all processed computers to:
     `C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-Report.csv`

---

## 📋 Prerequisites

* **Operating System:** Windows Server 2016/2019/2022/2025 or Windows 10/11 (Polish or English locale).
* **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+.
* **For Local Active Directory Mode (`-Mode Local` / `AD`):**
  * Active Directory module for Windows PowerShell (`RSAT-AD-PowerShell`).
  * Domain account with permissions to disable, move, or delete computer objects in the target OU.
  ```powershell
  # Install on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

  # Install on Windows Server:
  Install-WindowsFeature -Name RSAT-AD-PowerShell
  ```
* **For Cloud Microsoft Entra ID Mode (`-Mode Cloud` / `EntraID`):**
  * `Microsoft.Graph.Authentication` and `Microsoft.Graph.Identity.DirectoryManagement` modules.
  ```powershell
  Install-Module -Name Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser -Repository PSGallery -Force
  ```

---

## 🔓 Unblocking the Script After Download

After downloading or cloning this script from GitHub, Windows may attach a `Zone.Identifier` alternate data stream blocking execution. Unblock the file before running it:

```powershell
Unblock-File -Path .\Disable-StaleComputers.ps1
```

---

## 🔐 Non-Interactive Authentication in Microsoft Entra ID (Microsoft Graph SDK)

To run `Disable-StaleComputers.ps1` in `-Mode Cloud` unattended (e.g., in Windows Task Scheduler, endpoint lifecycle jobs, or CI/CD pipelines) using **only API credentials and Microsoft Graph SDK Application Permissions**:

### Step 1: Register an Application in Microsoft Entra ID
1. Sign in to the [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Navigate to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Set **Name** to `EntraID-StaleDevices-Cleanup`.
4. Under **Supported account types**, select *Accounts in this organizational directory only (Single tenant)*.
5. Click **Register** and copy:
   * **Application (client) ID** (`-ClientId`)
   * **Directory (tenant) ID** (`-TenantId`)

### Step 2: Assign Microsoft Graph Application Permissions
1. Inside the registered application, go to **Manage** > **API permissions** > **Add a permission**.
2. Select **Microsoft Graph** > **Application permissions** *(do not choose Delegated permissions for unattended execution)*.
3. Search for and select:
   * `Device.ReadWrite.All` *(Required to read, disable, or delete devices in Entra ID)*
   * `Directory.ReadWrite.All` *(Required for full directory device lifecycle operations)*
4. Click **Add permissions**.
5. Click **Grant admin consent for \<Your Organization\>** and verify that all permissions display a green checkmark.
   > **Note:** If you plan to permanently delete devices (`-Action Remove`) via App-Only authentication, also assign the App Registration's Service Principal to the **Cloud Device Administrator** role under **Identity** > **Roles & admins** > **Cloud Device Administrator**.

### Step 3: Create API Credentials (Option A: Client Secret or Option B: X.509 Certificate)

#### Option A: Client Secret (API Key)
1. Go to **Manage** > **Certificates & secrets** > **Client secrets** > **New client secret**.
2. Enter a description (e.g., `StaleDevicesCleanupSecret`), choose an expiration period, and click **Add**.
3. Copy the **Value** immediately and pass it to the script:
   ```powershell
   .\Disable-StaleComputers.ps1 -Mode Cloud `
       -StaleDays 180 `
       -Action Disable `
       -TenantId "11111111-2222-3333-4444-555555555555" `
       -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
       -ClientSecret "YourClientSecretValueHere" `
       -Force
   ```

#### Option B: X.509 Certificate (Recommended for Production Scheduled Tasks)
1. Generate a self-signed certificate in PowerShell and export the `.cer` public key:
   ```powershell
   $cert = New-SelfSignedCertificate -Subject "CN=EntraStaleDevicesCleanup" `
       -CertStoreLocation "Cert:\CurrentUser\My" `
       -KeyExportPolicy Exportable -KeySpec Signature `
       -KeyLength 2048 -HashAlgorithm SHA256 `
       -NotAfter (Get-Date).AddYears(2)
   Export-Certificate -Cert $cert -FilePath "C:\Logs\EntraStaleDevicesCleanup.cer"
   ```
2. Upload `C:\Logs\EntraStaleDevicesCleanup.cer` in **Microsoft Entra Admin Center** > **App registrations** > **Certificates & secrets** > **Certificates** > **Upload certificate**.
3. Execute the script using the certificate thumbprint:
   ```powershell
   .\Disable-StaleComputers.ps1 -Mode Cloud `
       -StaleDays 180 `
       -Action Disable `
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
.\Disable-StaleComputers.ps1
# or
.\Disable-StaleComputers.ps1 -Help
```

### Example 2: Disable Stale Local AD Computers Inactive for > 180 Days (Default Settings)
Finds all Local Active Directory workstations with `PasswordLastSet` older than 180 days, disables them via `Disable-ADAccount`, and outputs `Wyłączono nieaktywny komputer: <Name>` in yellow:
```powershell
.\Disable-StaleComputers.ps1 -Run
```

### Example 3: Disable Stale Workstations in a Specific OU, Stamp Description, and Move to Quarantine OU
Scopes the search to `OU=Workstations`, stamps the AD `Description` with the disable date, and moves disabled computer accounts to `OU=Disabled_Computers`:
```powershell
.\Disable-StaleComputers.ps1 -StaleDays 180 `
    -SearchBase "OU=Workstations,DC=firma,DC=local" `
    -TargetOU "OU=Disabled_Computers,DC=firma,DC=local" `
    -StampDescription `
    -ExcludeComputers "KIOSK-*", "PC-RECEPCJA*" `
    -Force
```

### Example 4: Audit-Only Mode (Generate CSV Report Without Disabling Accounts)
Discovers all computers inactive for more than 180 days and exports a full CSV audit report to `C:\Logs\` without modifying Active Directory:
```powershell
.\Disable-StaleComputers.ps1 -StaleDays 180 -Action AuditOnly
```

### Example 5: Permanently Remove Computers Inactive for > 365 Days
Deletes obsolete computer accounts (including previously disabled accounts) that have not updated their password in over 365 days:
```powershell
.\Disable-StaleComputers.ps1 -StaleDays 365 `
    -Action Remove `
    -IncludeAlreadyDisabled `
    -Force
```

### Example 6: Disable Stale Devices in Cloud Microsoft Entra ID (Interactive Sign-In)
Connects interactively to Microsoft Graph and disables cloud devices whose `ApproximateLastSignInDateTime` is older than 180 days:
```powershell
.\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable
```

### Example 7: Hybrid Mode (`-Mode Both`) & Dry-Run Simulation (`-DryRun`)
Simulates disabling stale computers across both Local Active Directory and Cloud Microsoft Entra ID without making live changes:
```powershell
.\Disable-StaleComputers.ps1 -Mode Both -StaleDays 180 -DryRun
```

---

## ⚙️ Parameter Reference

| Parameter | Alias(es) | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-Run` | `-Execute`, `-Cleanup` | `switch` | `$false` | Runs the cleanup with default settings (`180` days, `Disable`, `Local` mode). |
| `-StaleDays` | `-InactiveDays`, `-Days`, `-ThresholdDays` | `int` | `180` | Inactivity threshold in days (`$StareDni = (Get-Date).AddDays(-$StaleDays)`). |
| `-Mode` | `-Provider`, `-Environment`, `-Target`, `-Directory` | `string` | `'Local'` | Target directory: `'Local'` (`'AD'`, `'LocalAD'`), `'Cloud'` (`'EntraID'`, `'AzureAD'`), or `'Both'`. |
| `-Action` | — | `string` | `'Disable'` | Operation to perform: `'Disable'`, `'Remove'` (`'Delete'`), or `'AuditOnly'` (`'ReportOnly'`). |
| `-FilterProperty` | — | `string` | `'PasswordLastSet'` | Local AD timestamp property: `'PasswordLastSet'`, `'LastLogonDate'`, or `'Both'`. |
| `-UseSetADComputer` | — | `switch` | `$false` | Uses `Set-ADComputer -Enabled $false` instead of `Disable-ADAccount` when disabling in Local AD. |
| `-SearchBase` | `-OU`, `-OrganizationalUnit` | `string` | Entire Domain | Optional Organizational Unit Distinguished Name (DN) to scope Local AD search. |
| `-TargetOU` | `-MoveToOU`, `-QuarantineOU` | `string` | — | Optional Quarantine OU DN to move disabled Local AD computers into. |
| `-StampDescription` | — | `switch` | `$false` | Appends `[Disabled by Disable-StaleComputers on yyyy-MM-dd]` to the AD `Description`. |
| `-DomainController` | `-Server`, `-DC` | `string` | Auto | Specific Active Directory Domain Controller FQDN or IP address. |
| `-Credential` | — | `PSCredential` | Current User | Optional credentials for Local Active Directory operations. |
| `-IncludeServers` | — | `switch` | `$false` | Includes Windows Server OS computer accounts (excluded by default for safety). |
| `-IncludeAlreadyDisabled` | — | `switch` | `$false` | Includes computer accounts that are already disabled. |
| `-ExcludeComputers` | `-Exclude` | `string[]` | — | List of computer names or wildcard patterns (e.g., `"SRV-*"`) to exclude. |
| `-OutputPath` | `-CsvPath`, `-ExportCsv`, `-ExportReportPath` | `string` | `C:\Logs\...` | Custom file path for the exported UTF-8 CSV report. |
| `-Delimiter` | — | `string` | `','` | CSV delimiter character (`','`, `';'`, or Tab). |
| `-TenantId` | `-Tenant`, `-DirectoryId` | `string` | — | Microsoft Entra ID Tenant ID for Cloud authentication. |
| `-ClientId` | `-AppId`, `-ApplicationId` | `string` | — | Microsoft Entra ID Application (Client) ID for non-interactive Cloud auth. |
| `-ClientSecret` | `-Secret` | `string` | — | Microsoft Entra ID Client Secret for non-interactive Cloud auth. |
| `-ClientSecretSecure` | — | `SecureString` | — | SecureString containing the Entra ID Client Secret. |
| `-CertificateThumbprint` | `-Thumbprint` | `string` | — | X.509 Certificate thumbprint for non-interactive Cloud authentication. |
| `-DryRun` | `-Simulate`, `-Preview` | `switch` | `$false` | Simulates execution without modifying Active Directory or Entra ID. |
| `-Force` | — | `switch` | `$false` | Bypasses interactive confirmation prompts (`Y/N` / `T/N`). |
| `-SkipAdminCheck` | — | `switch` | `$false` | Skips automatic UAC Administrator privilege check. |
| `-PassThru` | — | `switch` | `$false` | Outputs processed computer result objects to the PowerShell pipeline. |
| `-LogPath` | `-l`, `-Log` | `string` | `C:\Logs\...` | Custom file path for the execution log. |
| `-NoLog` | — | `switch` | `$false` | Disables writing execution logs to disk. |
| `-Help` | `-h` | `switch` | `$false` | Displays the console help screen and exits. |

---

## 📝 Logging & CSV Reporting

Detailed execution logs are enabled by default and automatically saved to:

```text
C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-<ComputerName>-<UserName>.logs
```

Additionally, a structured UTF-8 CSV report of all discovered and processed computer accounts is automatically saved to:

```text
C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-Report.csv
```

---

## 📌 Version History

* **v1.2.0 (2026-10-17)**
  * Implemented automatic UAC elevation prompt with language-independent SID verification (`S-1-5-32-544` / `BuiltInAdministratorsSid`) supporting Polish (`Administratorzy`) and English (`Administrators`) Windows systems.
  * Added dual-mode support for Local Active Directory (`-Mode Local` / `AD`) and Cloud Microsoft Entra ID (`-Mode Cloud` / `EntraID` / `Both`) via Microsoft Graph SDK (`Get-MgDevice`, `Update-MgDevice`, `Remove-MgDevice`).
  * Added non-interactive App-Only Entra ID authentication (Client Secret & X.509 Certificate) and step-by-step setup documentation.
  * Added safety guardrails protecting Domain Controllers and Server OS accounts by default, plus quarantine OU relocation (`-TargetOU`) and description stamping (`-StampDescription`).
  * Added centralized audit logging to `C:\Logs\<DateTime>-Disable-StaleComputers-<ComputerName>-<UserName>.logs` and CSV report export.

---

## 👨‍💻 Author & Contact

* **Author:** Roman Pindela
* **Email:** [roman.pindela@gmail.com](mailto:roman.pindela@gmail.com)
* **GitHub:** [https://github.com/romanpindela](https://github.com/romanpindela)
* **License:** MIT
