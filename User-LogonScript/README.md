# User-LogonScript

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS%20%26%20GPO-0078D4.svg)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Graph%20SDK-008272.svg)](https://learn.microsoft.com/graph/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20Server%20%7C%20Windows%2010%2F11-0078D4.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade PowerShell **User Logon Script & Group Policy (GPO) / Cloud Deployment Toolkit** engineered to **map persistent network drives (`New-PSDrive -Persist`), record local and centralized user logon status logs (`C:\Temp\LogonStatus.txt` and `C:\Logs`), publish logon scripts to the Active Directory `SYSVOL` share, and automate GPO or Microsoft Entra ID / Intune assignment**.

Supports **Local Active Directory Domain Services (`-Mode Local` / `AD`)**, **Cloud Microsoft Entra ID (`-Mode Cloud` / `EntraID` / `Intune`)**, and **Hybrid (`-Mode Both`)** environments with language-independent UAC auto-elevation (`S-1-5-32-544`), optional security group filtering, GPO PowerShell `ExecutionPolicy` provisioning, and centralized audit logging.

---

## ✨ Key Features

1. **Zero-Parameter Interactive Help (`-Help` / `-h`)**
   Running `.\User-LogonScript.ps1` without parameters or with `-h` / `-Help` displays comprehensive console documentation, the complete 4-step Active Directory GPO Logon Script guide, GPO `ExecutionPolicy` instructions, non-interactive Microsoft Entra ID setup instructions, usage examples, script version (`1.2.0`), and author details without making any system changes.
2. **Complete End-to-End Logon Script Lifecycle (`-Action`)**
   - **`ExecuteLogon` (Default):** Checks if the target drive letter (e.g., `Z:`) is already mapped (`Test-Path $DriveLetter`), maps the UNC share (`\\serwer\zasob`) persistently via `New-PSDrive -Persist`, optionally verifies user membership in a target AD or Entra ID group (`-RequiredGroup`), and writes verification entries to `C:\Temp\LogonStatus.txt` (`"Zalogowano pomyślnie dnia $(Get-Date)"`) and `C:\Logs`.
   - **`GenerateScript` (`-GenerateLogonScript`):** Generates a standalone, production-ready `LogonScript.ps1` file ready to be placed in `SYSVOL`.
   - **`DeployGPO` (`-DeployGPO`):** Automates copying `LogonScript.ps1` to `\\<domain>\sysvol\<domain>\scripts`, creating/updating the Group Policy Object (e.g., `Skrypty_Logowania_GPO`), registering the PowerShell User Logon Script (`psscripts.ini`), linking the GPO to the target Organizational Unit (`-TargetOU`), and optionally configuring the GPO PowerShell `ExecutionPolicy` (`-ConfigureExecutionPolicy`).
   - **`Verify` (`-Verify`):** Optionally runs `gpupdate /force` (`-RunGpUpdate`) and verifies mapped network drives, `C:\Temp\LogonStatus.txt`, and `SYSVOL` UNC reachability.
3. **Dual Directory Environment Support (`-Mode Local | Cloud | Both`)**
   - **`Local` (`AD` / `OnPremises` — Default):** Uses Windows Server Active Directory (`ActiveDirectory` and `GroupPolicy` modules), Kerberos/NTLM token group inspection, and `SYSVOL` / GPO provisioning.
   - **`Cloud` (`EntraID` / `AzureAD` / `Intune`):** Uses the **Microsoft Graph PowerShell SDK** to verify cloud user identities and transitive group memberships in Microsoft Entra ID (`users/{id}/transitiveMemberOf`) before mapping cloud/SMB shares, or deploys the PowerShell logon script to **Microsoft Intune** (`deviceManagementScripts` in `user` context). Supports both interactive sign-in and unattended App-Only authentication (Client Secret or X.509 Certificate).
   - **`Both`:** Executes or deploys the logon script across both On-Premises Active Directory and Cloud Microsoft Entra ID.
4. **Language-Independent UAC Auto-Elevation (PL / EN Windows)**
   Verifies Administrator privileges using the well-known Windows SID `S-1-5-32-544` (`BuiltInAdministratorsSid`), ensuring full compatibility across both Polish (`Administratorzy`) and English (`Administrators`) editions of Windows Desktop and Windows Server when performing administrative GPO/SYSVOL deployment tasks.
5. **Centralized Audit Logging (`C:\Logs` & `C:\Temp\LogonStatus.txt`)**
   - Automatically writes detailed, timestamped UTF-8 execution logs by default to:
     `C:\Logs\<yyyyMMdd_HHmmss>-User-LogonScript-<ComputerName>-<UserName>.logs`
   - Appends user logon status verification lines to:
     `C:\Temp\LogonStatus.txt`

---

## 📋 Prerequisites

* **Operating System:** Windows Server 2016/2019/2022/2025 or Windows 10/11 (Polish or English locale).
* **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+.
* **For Local Active Directory GPO Deployment (`-Mode Local -DeployGPO`):**
  * Group Policy Management Console (`GPMC` / `GroupPolicy` module) and Active Directory module (`RSAT-AD-PowerShell`).
  ```powershell
  # Install on Windows 10/11:
  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
  Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

  # Install on Windows Server:
  Install-WindowsFeature -Name GPMC, RSAT-AD-PowerShell
  ```
* **For Cloud Microsoft Entra ID Mode (`-Mode Cloud` / `EntraID`):**
  * `Microsoft.Graph.Authentication` module.
  ```powershell
  Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
  ```

---

## 🔓 Unblocking the Script After Download

After downloading or cloning this script from GitHub, Windows marks the `.ps1` file with a `Zone.Identifier` alternate data stream. Unblock the file before running it:

```powershell
Unblock-File -Path .\User-LogonScript.ps1
Unblock-File -Path .\LogonScript.ps1
```

---

## 📘 Step-by-Step Guide: Configuring a PowerShell User Logon Script via Active Directory GPO

Configuring a PowerShell User Logon Script using Group Policy (GPO) in Active Directory consists of four key steps: preparing the script, placing it in the domain-replicated `SYSVOL` share, configuring the GPO, and verifying execution on a client workstation.

### Step 1: Prepare the PowerShell Logon Script (`LogonScript.ps1`)

You can generate `LogonScript.ps1` automatically using `.\User-LogonScript.ps1 -GenerateLogonScript` or use the included [`LogonScript.ps1`](LogonScript.ps1) file. It maps a persistent network drive (e.g., `Z:` to `\\serwer\zasob`) if not already mapped and writes a verification entry to `C:\Temp\LogonStatus.txt` and `C:\Logs`:

```powershell
# Example: Map a persistent network drive for the user
$DriveLetter = "Z:"
$DriveName   = $DriveLetter.TrimEnd(':')
$NetworkPath = "\\serwer\zasob"

# Check if the drive is not already mapped and map it persistently
if (!(Test-Path $DriveLetter)) {
    New-PSDrive -Name $DriveName -PSProvider FileSystem -Root $NetworkPath -Persist -Scope Global | Out-Null
}

# Verify success (append to local status log)
$LogPath = "C:\Temp\LogonStatus.txt"
if (!(Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" | Out-Null }
"Zalogowano pomyślnie dnia $(Get-Date)" | Out-File -Append -FilePath $LogPath -Encoding UTF8
```

### Step 2: Place the Script in the Domain `SYSVOL` Share

For domain workstations to retrieve and execute the script when a user logs on, the file must reside in the domain-replicated **`SYSVOL`** share:

1. On a Domain Controller (or administrative workstation), open **File Explorer** and navigate to:
   ```text
   \\twojadomena.local\sysvol\twojadomena.local\scripts
   ```
   *(Replace `twojadomena.local` with your actual Active Directory DNS domain name).*
2. Copy `LogonScript.ps1` (or `User-LogonScript.ps1`) into this folder.
3. **Verification:** Confirm that the UNC path is accessible from a domain client workstation (e.g., press `Win + R` and enter `\\twojadomena.local\sysvol\twojadomena.local\scripts`).

> **Tip:** Running `.\User-LogonScript.ps1 -DeployGPO -DomainName "twojadomena.local" ...` performs Step 1 and Step 2 automatically!

### Step 3: Configure the Group Policy Object (GPO)

Link the logon script to the appropriate Organizational Unit (OU) containing your domain users:

1. Open the **Group Policy Management Console**: press `Win + R`, type `gpmc.msc`, and press **Enter**.
2. Expand your forest and domain, right-click the Organizational Unit containing your target users (e.g., `Pracownicy`), and select:
   * **EN:** *Create a GPO in this domain, and Link it here...*
   * **PL:** *Utwórz obiekt GPO w tym lesie i połącz go tutaj...*
   * Name the policy e.g. `Skrypty_Logowania_GPO`.
3. Right-click the newly created `Skrypty_Logowania_GPO` policy and select **Edit** (*Edytuj*).
4. In the Group Policy Management Editor, navigate to:
   * **EN:** `User Configuration` $\rightarrow$ `Policies` $\rightarrow$ `Windows Settings` $\rightarrow$ `Scripts (Logon/Logoff)`
   * **PL:** `Konfiguracja użytkownika` $\rightarrow$ `Zasady` $\rightarrow$ `Ustawienia systemu Windows` $\rightarrow$ `Skrypty (Logowanie/Wylogowanie)`
5. In the right pane, double-click **Logon** (*Logowanie*).
6. Switch to the **PowerShell Scripts** tab (*Skrypty programu PowerShell*) — **this is critical**, because the standard *Scripts* tab executes `.bat`/`.cmd` files rather than `.ps1` scripts.
7. Click **Add** (*Dodaj*) $\rightarrow$ **Browse** (*Przeglądaj*), select `LogonScript.ps1` from the `SYSVOL` scripts folder, and click **OK**.
8. Click **Apply** and **OK** to save the GPO configuration.

### Step 4: Verify Execution on a Client Workstation

To apply and test the new Group Policy on a domain workstation:

1. Sign in to a domain-joined workstation using a user account located in the target OU (e.g., `OU=Pracownicy`).
2. To immediately force a Group Policy refresh without waiting for the background refresh interval, open PowerShell as Administrator and run:
   ```powershell
   gpupdate /force
   ```
   *(Or run `.\User-LogonScript.ps1 -Verify -RunGpUpdate`)*.
3. Log off and log back on to the user account.
4. **Verify Success:**
   * Check **File Explorer** (*This PC / Ten komputer*) to confirm that network drive `Z:` is mapped to `\\serwer\zasob`.
   * Check `C:\Temp\LogonStatus.txt` to confirm the timestamped entry:
     `Zalogowano pomyślnie dnia ...`
   * Check `C:\Logs\` for the detailed execution log file.

---

## 🛡️ Configuring PowerShell `ExecutionPolicy` via GPO

If client workstations block `.ps1` scripts due to the default Windows PowerShell `Restricted` execution policy, configure `ExecutionPolicy` directly in your GPO:

### Option A: Automated via `User-LogonScript.ps1`
Pass `-ConfigureExecutionPolicy` and `-ExecutionPolicyLevel RemoteSigned` when running `-DeployGPO`:
```powershell
.\User-LogonScript.ps1 -DeployGPO `
    -DomainName "twojadomena.local" `
    -GpoName "Skrypty_Logowania_GPO" `
    -TargetOU "OU=Pracownicy,DC=twojadomena,DC=local" `
    -ConfigureExecutionPolicy `
    -ExecutionPolicyLevel RemoteSigned `
    -Force
```

### Option B: Manual Configuration in `gpmc.msc`
1. Edit your GPO in `gpmc.msc`.
2. Navigate to:
   * **EN:** `Computer Configuration` (or `User Configuration`) $\rightarrow$ `Policies` $\rightarrow$ `Administrative Templates` $\rightarrow$ `Windows Components` $\rightarrow$ `Windows PowerShell`
   * **PL:** `Konfiguracja komputera` $\rightarrow$ `Zasady` $\rightarrow$ `Szablony administracyjne` $\rightarrow$ `Składniki systemu Windows` $\rightarrow$ `Windows PowerShell`
3. Double-click **Turn on Script Execution** (*Włącz wykonywanie skryptów*).
4. Select **Enabled** (*Włączone*) and under **Execution Policy** choose:
   * **Allow local scripts and remote signed scripts** (`RemoteSigned` — *Recommended*), or
   * **Allow all scripts** (`Unrestricted`).
5. Click **OK** and run `gpupdate /force` on client machines.

---

## 🔐 Non-Interactive Authentication in Microsoft Entra ID (Microsoft Graph SDK)

To run `User-LogonScript.ps1` in `-Mode Cloud` or `-Mode Both` unattended (without interactive browser prompts) using **only API credentials and Microsoft Graph SDK Application Permissions**:

### Step 1: Register an Application in Microsoft Entra ID
1. Sign in to the [Microsoft Entra Admin Center](https://entra.microsoft.com).
2. Navigate to **Identity** > **Applications** > **App registrations** > **New registration**.
3. Set **Name** to `AD-LogonScript-Automation`.
4. Select *Accounts in this organizational directory only (Single tenant)* and click **Register**.
5. Copy the **Application (client) ID** (`-ClientId`) and **Directory (tenant) ID** (`-TenantId`).

### Step 2: Assign Microsoft Graph Application Permissions
1. Go to **Manage** > **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**.
2. Select:
   * `User.Read.All` *(Required to verify cloud user profiles)*
   * `GroupMember.Read.All` *(Required to verify transitive cloud group memberships)*
   * `DeviceManagementConfiguration.ReadWrite.All` *(Required if deploying logon scripts to Microsoft Intune via `-DeployGPO -Mode Cloud`)*
3. Click **Add permissions** and click **Grant admin consent for \<Your Organization\>**.

### Step 3: Create API Credentials (Option A: Client Secret or Option B: X.509 Certificate)

#### Option A: Client Secret (API Key)
```powershell
.\User-LogonScript.ps1 -Mode Cloud `
    -DriveLetter "Z:" `
    -NetworkPath "\\storageaccount.file.core.windows.net\zasob" `
    -RequiredGroup "Dzial_Ksiegowosci" `
    -UserPrincipalName "jkowalski@contoso.com" `
    -TenantId "11111111-2222-3333-4444-555555555555" `
    -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
    -ClientSecret "YourClientSecretValueHere" `
    -Force
```

#### Option B: X.509 Certificate (Recommended for Production)
```powershell
$cert = New-SelfSignedCertificate -Subject "CN=EntraLogonAutomation" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable -KeySpec Signature `
    -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(2)
Export-Certificate -Cert $cert -FilePath "C:\Logs\EntraLogonAutomation.cer"

# Upload C:\Logs\EntraLogonAutomation.cer in Entra Admin Center > App registrations > Certificates & secrets > Certificates
.\User-LogonScript.ps1 -Mode Cloud `
    -DriveLetter "Z:" `
    -NetworkPath "\\storageaccount.file.core.windows.net\zasob" `
    -RequiredGroup "Dzial_Ksiegowosci" `
    -UserPrincipalName "jkowalski@contoso.com" `
    -TenantId "11111111-2222-3333-4444-555555555555" `
    -ClientId "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" `
    -CertificateThumbprint $cert.Thumbprint `
    -Force
```

---

## 🚀 Usage Examples

### Example 1: Display Built-In Help & Step-by-Step GPO Tutorial
```powershell
.\User-LogonScript.ps1
# or
.\User-LogonScript.ps1 -Help
```

### Example 2: Execute the User Logon Script Directly (Map Drive `Z:` & Log to `C:\Temp\LogonStatus.txt`)
Checks if `Z:` is already mapped, maps `Z:` to `\\serwer\zasob`, appends `"Zalogowano pomyślnie dnia ..."` to `C:\Temp\LogonStatus.txt`, and writes a full audit log to `C:\Logs`:
```powershell
.\User-LogonScript.ps1 -DriveLetter "Z:" -NetworkPath "\\serwer\zasob"
```

### Example 3: Generate a Standalone `LogonScript.ps1` File for `SYSVOL`
Generates a clean `LogonScript.ps1` script configured with your drive letter and UNC path:
```powershell
.\User-LogonScript.ps1 -GenerateLogonScript `
    -ScriptOutputPath ".\LogonScript.ps1" `
    -DriveLetter "Z:" `
    -NetworkPath "\\serwer\zasob" `
    -Force
```

### Example 4: Full Automated `SYSVOL` + GPO Deployment (Steps 1, 2 & 3 + `ExecutionPolicy`)
Generates `LogonScript.ps1`, copies it to `\\twojadomena.local\sysvol\twojadomena.local\scripts`, creates GPO `Skrypty_Logowania_GPO`, registers the PowerShell User Logon Script, enables GPO PowerShell `ExecutionPolicy` (`RemoteSigned`), and links the GPO to `OU=Pracownicy`:
```powershell
.\User-LogonScript.ps1 -DeployGPO `
    -DomainName "twojadomena.local" `
    -GpoName "Skrypty_Logowania_GPO" `
    -TargetOU "OU=Pracownicy,DC=twojadomena,DC=local" `
    -DriveLetter "Z:" `
    -NetworkPath "\\serwer\zasob" `
    -ConfigureExecutionPolicy `
    -ExecutionPolicyLevel RemoteSigned `
    -Force
```

### Example 5: Verify Logon Script Status & Force Group Policy Update (Step 4)
Runs `gpupdate /force`, checks whether drive `Z:` is mapped, reads the latest entry from `C:\Temp\LogonStatus.txt`, and verifies `SYSVOL` script availability:
```powershell
.\User-LogonScript.ps1 -Verify `
    -DriveLetter "Z:" `
    -DomainName "twojadomena.local" `
    -GpoName "Skrypty_Logowania_GPO" `
    -RunGpUpdate
```

### Example 6: Conditional Group-Based Drive Mapping in Local AD or Cloud Entra ID
Maps drive `Z:` only if the logging-in user is a member of the `Dzial_Ksiegowosci` group:
```powershell
# Local Active Directory:
.\User-LogonScript.ps1 -DriveLetter "Z:" -NetworkPath "\\serwer\ksiegowosc" -RequiredGroup "Dzial_Ksiegowosci" -Mode Local

# Cloud Microsoft Entra ID:
.\User-LogonScript.ps1 -DriveLetter "Z:" -NetworkPath "\\storage.file.core.windows.net\ksiegowosc" -RequiredGroup "Dzial_Ksiegowosci" -Mode Cloud
```

---

## ⚙️ Parameter Reference

| Parameter | Alias(es) | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `-Action` | `-Operation`, `-Task` | `string` | `'ExecuteLogon'` | Workflow: `'ExecuteLogon'`, `'GenerateScript'`, `'DeployGPO'`, or `'Verify'`. |
| `-Mode` | `-Provider`, `-Environment`, `-Target` | `string` | `'Local'` | Directory mode: `'Local'` (`'AD'`, `'OnPremises'`), `'Cloud'` (`'EntraID'`, `'AzureAD'`, `'Intune'`), or `'Both'`. |
| `-DriveLetter` | `-Drive`, `-d` | `string` | `'Z:'` | Drive letter to map (e.g., `'Z:'` or `'Z'`). |
| `-NetworkPath` | `-SharePath`, `-UncPath`, `-s` | `string` | `'\\serwer\zasob'` | UNC network share path to map to the drive letter. |
| `-StatusLogPath` | `-LogonStatusFile`, `-StatusFile` | `string` | `'C:\Temp\LogonStatus.txt'` | Local status file where logon confirmation is appended. |
| `-ScriptOutputPath` | `-ScriptPath`, `-LogonScriptPath` | `string` | `'.\LogonScript.ps1'` | File path for generating or reading the standalone `LogonScript.ps1`. |
| `-DomainName` | `-Domain`, `-DnsRoot` | `string` | Auto-detected | DNS name of the Active Directory domain (e.g., `twojadomena.local`). |
| `-SysvolScriptsPath` | — | `string` | Auto-built | Explicit UNC path to `\\<domain>\sysvol\<domain>\scripts`. |
| `-GpoName` | `-GPO`, `-PolicyName` | `string` | `'Skrypty_Logowania_GPO'` | Name of the Group Policy Object (or Intune policy) to create/update. |
| `-TargetOU` | `-OU`, `-SearchBase` | `string` | — | Distinguished Name (DN) of the Organizational Unit to link the GPO. |
| `-ConfigureExecutionPolicy` | — | `switch` | `$false` | Configures PowerShell `ExecutionPolicy` inside the target GPO. |
| `-ExecutionPolicyLevel` | — | `string` | `'RemoteSigned'` | GPO ExecutionPolicy level (`RemoteSigned`, `AllSigned`, `Unrestricted`). |
| `-RequiredGroup` | `-Group`, `-GroupName` | `string` | — | Optional AD or Entra ID group required before mapping the network drive. |
| `-UserPrincipalName` | `-UPN`, `-User` | `string` | Current User | User UPN to evaluate in Cloud Entra ID mode. |
| `-RunGpUpdate` | — | `switch` | `$false` | Executes `gpupdate /force` during `-Verify`. |
| `-GenerateLogonScript` | — | `switch` | `$false` | Shortcut switch for `-Action GenerateScript`. |
| `-DeployGPO` | — | `switch` | `$false` | Shortcut switch for `-Action DeployGPO`. |
| `-Verify` | — | `switch` | `$false` | Shortcut switch for `-Action Verify`. |
| `-ExecuteLogon` | — | `switch` | `$false` | Shortcut switch for `-Action ExecuteLogon`. |
| `-DomainController` | `-Server`, `-DC` | `string` | Auto | Specific AD Domain Controller FQDN/IP. |
| `-Credential` | — | `PSCredential` | Current User | Optional credentials for AD or SMB drive mapping. |
| `-TenantId` | `-Tenant`, `-DirectoryId` | `string` | — | Microsoft Entra ID Tenant ID for Cloud authentication. |
| `-ClientId` | `-AppId`, `-ApplicationId` | `string` | — | Microsoft Entra ID Application (Client) ID for non-interactive Cloud auth. |
| `-ClientSecret` | `-Secret` | `string` | — | Microsoft Entra ID Client Secret for non-interactive Cloud auth. |
| `-CertificateThumbprint` | `-Thumbprint` | `string` | — | Certificate thumbprint for non-interactive Cloud authentication. |
| `-ExportReportPath` | `-ExportCsv`, `-ReportPath` | `string` | — | File path to export execution results as a UTF-8 CSV. |
| `-DryRun` | `-Simulate`, `-Preview` | `switch` | `$false` | Simulates all operations without making changes. |
| `-RequireAdmin` | — | `switch` | `$false` | Forces UAC Administrator elevation. |
| `-SkipAdminCheck` | — | `switch` | `$false` | Skips automatic UAC Administrator privilege check. |
| `-PassThru` | — | `switch` | `$false` | Outputs structured result objects to the pipeline. |
| `-LogPath` | `-l`, `-Log` | `string` | `C:\Logs\...` | Custom file path for the centralized execution log. |
| `-NoLog` | — | `switch` | `$false` | Disables writing execution logs to `C:\Logs`. |
| `-Force` | — | `switch` | `$false` | Bypasses confirmation prompts and remaps existing drives. |
| `-Help` | `-h` | `switch` | `$false` | Displays the console help screen and exits. |

---

## 📝 Logging

1. **Centralized Execution Audit Logs (`C:\Logs`):**
   Detailed execution logs are enabled by default and automatically saved to:
   ```text
   C:\Logs\<yyyyMMdd_HHmmss>-User-LogonScript-<ComputerName>-<UserName>.logs
   ```
2. **Local User Logon Verification File (`C:\Temp\LogonStatus.txt`):**
   Every successful logon execution appends a verification line to `C:\Temp\LogonStatus.txt`:
   ```text
   Zalogowano pomyślnie dnia 10/17/2026 16:15:00
   ```

---

## 📌 Version History

* **v1.2.0 (2026-10-17)**
  * Implemented automatic UAC elevation prompt with language-independent SID verification (`S-1-5-32-544` / `BuiltInAdministratorsSid`) supporting Polish (`Administratorzy`) and English (`Administrators`) Windows environments.
  * Added full lifecycle support for Active Directory PowerShell User Logon Scripts: runtime drive mapping (`New-PSDrive -Persist`), standalone `LogonScript.ps1` generation, automated `SYSVOL` publishing, GPO creation & linking (`psscripts.ini`), GPO PowerShell `ExecutionPolicy` configuration, and `gpupdate /force` verification.
  * Added dual-mode support for Local Active Directory (`-Mode Local` / `AD`) and Cloud Microsoft Entra ID / Intune (`-Mode Cloud` / `EntraID` / `Both`) via Microsoft Graph SDK, including non-interactive App-Only authentication (Client Secret & X.509 Certificate).
  * Added centralized audit logging to `C:\Logs\<DateTime>-User-LogonScript-<ComputerName>-<UserName>.logs` and local verification logging to `C:\Temp\LogonStatus.txt`.

---

## 👨‍💻 Author & Contact

* **Author:** Roman Pindela
* **Email:** [roman.pindela@gmail.com](mailto:roman.pindela@gmail.com)
* **GitHub:** [https://github.com/romanpindela](https://github.com/romanpindela)
* **License:** MIT
