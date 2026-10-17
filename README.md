# Active Directory & Entra ID PowerShell Automation Toolkit

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS-0078D4.svg)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Microsoft Entra ID](https://img.shields.io/badge/Microsoft%20Entra%20ID-Graph%20SDK-008272.svg)](https://learn.microsoft.com/graph/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A collection of enterprise-grade PowerShell provisioning and directory administration tools for **Windows Server Active Directory (AD DS)** and **Microsoft Entra ID (Azure AD)**, engineered and maintained by **Roman Pindela**.

---

## 🏛️ Repository Structure

```text
Active-Directory/
├── Add-UsersToGroup/                    # Bulk group membership assignment for Local AD & Cloud Entra ID
│   ├── Add-UsersToGroup.ps1             # Main PowerShell group membership automation script
│   ├── nowi_ksiegowi.txt                # Ready-to-use sample user logins file
│   └── README.md                        # Full technical documentation and Entra ID setup guide
├── Disable-StaleComputers/              # Bulk disabling or removal of stale AD & Entra ID computer accounts (>180 days)
│   ├── Disable-StaleComputers.ps1       # Main PowerShell stale computers cleanup script
│   └── README.md                        # Full technical documentation and Entra ID setup guide
├── Get-InactiveUsersReport/             # Security audit report of inactive AD & Entra ID user accounts (>90 days)
│   ├── Get-InactiveUsersReport.ps1      # Main PowerShell security auditing script
│   └── README.md                        # Full technical documentation and Entra ID setup guide
├── New-ADUsersFromCSV/                  # Bulk Active Directory & Entra ID user provisioning from CSV
│   ├── New-ADUsersFromCSV.ps1           # Main PowerShell automation script
│   ├── uzytkownicy.csv                  # Ready-to-use sample CSV user import template
│   └── README.md                        # Full technical documentation and Entra ID setup guide
├── Reset-UserPassword/                  # Emergency user password reset for Local AD & Cloud Entra ID
│   ├── Reset-UserPassword.ps1           # Main PowerShell emergency password reset script
│   └── README.md                        # Full technical documentation and Entra ID setup guide
├── User-LogonScript/                    # PowerShell User Logon Script & AD GPO / Cloud Intune deployment toolkit
│   ├── User-LogonScript.ps1             # Main PowerShell logon script execution & GPO/Cloud deployment script
│   ├── LogonScript.ps1                  # Ready-to-use standalone SYSVOL PowerShell logon script payload
│   └── README.md                        # Step-by-step GPO Logon Script guide & Entra ID documentation
└── README.md                            # Root repository index and script catalog
```

---

## 🚀 Featured Scripts & Modules

### 1. [**New-ADUsersFromCSV**](New-ADUsersFromCSV/README.md)
* **Script:** [`New-ADUsersFromCSV/New-ADUsersFromCSV.ps1`](New-ADUsersFromCSV/New-ADUsersFromCSV.ps1)
* **Author:** Roman Pindela (`roman.pindela@gmail.com`)
* **Version:** 1.0.0
* **Description:** Automates bulk creation of user accounts from a CSV file (e.g., `uzytkownicy.csv`) with columns such as `SamAccountName`, `Name`, `GivenName`, `Surname`, `Password`, and `Department` (plus optional attributes like `UserPrincipalName`, `EmailAddress`, `Title`, `Company`, `Office`, `MobilePhone`, `OU`, and `Groups`).
  * **Dual Directory Support (`-Provider AD | EntraID | Both`):** Provisions accounts in local Windows Server Active Directory (`New-ADUser`) and/or Microsoft Entra ID (`New-MgUser` via Microsoft Graph SDK).
  * **Unattended / Non-Interactive Entra ID Authentication:** Supports App-Only authentication via Client Secret (`-TenantId`, `-ClientId`, `-ClientSecret`) or X.509 Certificate (`-CertificateThumbprint`) with complete setup instructions included in `-Help` (`-h`) and `README.md`.
  * **Auto-Detecting CSV Delimiter:** Seamlessly imports both standard comma-delimited (`,`) and Polish Excel semicolon-delimited (`;`) UTF-8 CSV files.
  * **Standards Compliant:** Displays help when launched without parameters (`-h` / `-Help`), performs language-independent SID UAC auto-elevation (`S-1-5-32-544` for Polish `Administratorzy` and English `Administrators`), displays a real-time `Write-Progress` bar, and writes detailed audit logs to `C:\Logs\<yyyyMMdd_HHmmss>-New-ADUsersFromCSV-<ComputerName>-<UserName>.logs`.
* **Quick Start:**
  ```powershell
  # 1. Unblock the script after downloading from GitHub
  Unblock-File -Path .\New-ADUsersFromCSV\New-ADUsersFromCSV.ps1

  # 2. Display help & Entra ID non-interactive setup instructions
  .\New-ADUsersFromCSV\New-ADUsersFromCSV.ps1 -h

  # 3. Generate a sample CSV template (uzytkownicy.csv)
  .\New-ADUsersFromCSV\New-ADUsersFromCSV.ps1 -GenerateSampleCsv -CsvPath .\New-ADUsersFromCSV\uzytkownicy.csv

  # 4. Bulk provision users in local Active Directory
  .\New-ADUsersFromCSV\New-ADUsersFromCSV.ps1 -CsvPath .\New-ADUsersFromCSV\uzytkownicy.csv -TargetOU "OU=Pracownicy,DC=firma,DC=local"
  ```

---

### 2. [**Get-InactiveUsersReport**](Get-InactiveUsersReport/README.md)
* **Script:** [`Get-InactiveUsersReport/Get-InactiveUsersReport.ps1`](Get-InactiveUsersReport/Get-InactiveUsersReport.ps1)
* **Author:** Roman Pindela (`roman.pindela@gmail.com`)
* **Version:** 1.2.0
* **Description:** Enterprise security auditing script that identifies enabled user accounts that have not logged into the domain or cloud tenant for more than N days (default: `90` days) and exports the findings to a UTF-8 CSV report in `C:\Logs\<datagodzina>Get-InactiveUsersReport<nazwaserweraad>nieaktywni_uzytkownicy.csv`.
  * **Dual Directory Support (`-Provider AD | EntraID | Both`):** Audits On-Premises Active Directory (`Get-ADUser` with `LastLogonDate -lt $DataGraniczna -and Enabled -eq $true`) and/or Cloud Microsoft Entra ID (`Get-MgUser -Property SignInActivity`).
  * **Unattended / Non-Interactive Entra ID Authentication:** Supports App-Only authentication via Client Secret (`-TenantId`, `-ClientId`, `-ClientSecret`) or X.509 Certificate (`-CertificateThumbprint`) with `AuditLog.Read.All`, `User.Read.All`, and `Directory.Read.All` permissions.
  * **Flexible Scoping & Output:** Supports Organizational Unit scoping (`-SearchBase`), Domain Controller targeting (`-DomainController`), department filtering (`-Department`), never-logged-on accounts (`-IncludeNeverLoggedOn`), and classic 3-column CSV output (`-SimpleCsv`).
  * **Standards Compliant:** Displays help when launched without parameters (`-h` / `-Help`), performs language-independent SID UAC auto-elevation (`S-1-5-32-544` for Polish `Administratorzy` and English `Administrators`), and writes detailed execution logs to `C:\Logs\<yyyyMMdd_HHmmss>-Get-InactiveUsersReport-<ComputerName>-<UserName>.logs`.
* **Quick Start:**
  ```powershell
  # 1. Unblock the script after downloading from GitHub
  Unblock-File -Path .\Get-InactiveUsersReport\Get-InactiveUsersReport.ps1

  # 2. Display help & Entra ID non-interactive setup instructions
  .\Get-InactiveUsersReport\Get-InactiveUsersReport.ps1 -h

  # 3. Audit Local Active Directory for enabled accounts inactive > 90 days
  .\Get-InactiveUsersReport\Get-InactiveUsersReport.ps1 -Run

  # 4. Audit Cloud Microsoft Entra ID for accounts inactive > 90 days
  .\Get-InactiveUsersReport\Get-InactiveUsersReport.ps1 -Provider EntraID -InactiveDays 90
  ```

---

### 3. [**Add-UsersToGroup**](Add-UsersToGroup/README.md)
* **Script:** [`Add-UsersToGroup/Add-UsersToGroup.ps1`](Add-UsersToGroup/Add-UsersToGroup.ps1)
* **Author:** Roman Pindela (`roman.pindela@gmail.com`)
* **Version:** 1.2.0
* **Description:** Automates bulk assignment of multiple users (e.g., from a plain text file containing logins such as `nowi_ksiegowi.txt`, a CSV file, or a command-line list) to a target security or distribution group (such as `Dzial_Ksiegowosci` for shared network drive access).
  * **Dual Directory Support (`-Mode Local | Cloud | Both`):** Assigns users to groups in Local Active Directory (`Add-ADGroupMember`) and/or Cloud Microsoft Entra ID (`New-MgGroupMemberByRef` via Microsoft Graph SDK).
  * **Unattended / Non-Interactive Entra ID Authentication:** Supports App-Only authentication via Client Secret (`-TenantId`, `-ClientId`, `-ClientSecret`) or X.509 Certificate (`-CertificateThumbprint`) with `GroupMember.ReadWrite.All`, `Group.ReadWrite.All`, and `User.Read.All` permissions.
  * **Idempotent Pre-Flight Checks:** Validates group and user existence, optionally creates missing groups (`-CreateGroupIfMissing`), skips already-assigned members (`AlreadyMember`), and supports dry-run simulation (`-DryRun`) and CSV reporting (`-ExportReportPath`).
  * **Standards Compliant:** Displays help when launched without parameters (`-h` / `-Help`), performs language-independent SID UAC auto-elevation (`S-1-5-32-544` for Polish `Administratorzy` and English `Administrators`), displays a real-time `Write-Progress` bar, and writes detailed audit logs to `C:\Logs\<yyyyMMdd_HHmmss>-Add-UsersToGroup-<ComputerName>-<UserName>.logs`.
* **Quick Start:**
  ```powershell
  # 1. Unblock the script after downloading from GitHub
  Unblock-File -Path .\Add-UsersToGroup\Add-UsersToGroup.ps1

  # 2. Display help & Entra ID non-interactive setup instructions
  .\Add-UsersToGroup\Add-UsersToGroup.ps1 -h

  # 3. Bulk add users from a text file to a Local Active Directory group
  .\Add-UsersToGroup\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile .\Add-UsersToGroup\nowi_ksiegowi.txt

  # 4. Bulk add users to a Cloud Microsoft Entra ID group
  .\Add-UsersToGroup\Add-UsersToGroup.ps1 -Group "Dzial_Ksiegowosci" -UsersFile .\Add-UsersToGroup\nowi_ksiegowi.txt -Mode Cloud -UpnSuffix "firma.pl"
  ```

---

### 4. [**Disable-StaleComputers**](Disable-StaleComputers/README.md)
* **Script:** [`Disable-StaleComputers/Disable-StaleComputers.ps1`](Disable-StaleComputers/Disable-StaleComputers.ps1)
* **Author:** Roman Pindela (`roman.pindela@gmail.com`)
* **Version:** 1.2.0
* **Description:** Automates bulk disabling or permanent removal of stale computer accounts (workstations and cloud endpoints) that have not reported their presence in the domain or cloud tenant for an extended period (default: `180` days).
  * **Dual Directory Support (`-Mode Local | Cloud | Both`):** Cleans up stale computers in Local Active Directory (`Get-ADComputer -Filter {PasswordLastSet -lt $StareDni}` with `Disable-ADAccount` / `Set-ADComputer` / `Remove-ADComputer`) and/or Cloud Microsoft Entra ID (`Get-MgDevice`, `Update-MgDevice`, `Remove-MgDevice` via Microsoft Graph SDK).
  * **Unattended / Non-Interactive Entra ID Authentication:** Supports App-Only authentication via Client Secret (`-TenantId`, `-ClientId`, `-ClientSecret`) or X.509 Certificate (`-CertificateThumbprint`) with `Device.ReadWrite.All` and `Directory.ReadWrite.All` permissions.
  * **Built-In Safety Guardrails:** Automatically protects Domain Controllers (`PrimaryGroupID 516`), excludes Windows Server OS accounts by default (unless `-IncludeServers` is specified), supports exclusion lists (`-ExcludeComputers`), and optionally moves disabled computers to a Quarantine OU (`-TargetOU`) while stamping their AD `Description` (`-StampDescription`).
  * **Standards Compliant:** Displays help when launched without parameters (`-h` / `-Help`), performs language-independent SID UAC auto-elevation (`S-1-5-32-544` for Polish `Administratorzy` and English `Administrators`), exports a UTF-8 CSV report, and writes detailed audit logs to `C:\Logs\<yyyyMMdd_HHmmss>-Disable-StaleComputers-<ComputerName>-<UserName>.logs`.
* **Quick Start:**
  ```powershell
  # 1. Unblock the script after downloading from GitHub
  Unblock-File -Path .\Disable-StaleComputers\Disable-StaleComputers.ps1

  # 2. Display help & Entra ID non-interactive setup instructions
  .\Disable-StaleComputers\Disable-StaleComputers.ps1 -h

  # 3. Disable Local Active Directory computers inactive for > 180 days
  .\Disable-StaleComputers\Disable-StaleComputers.ps1 -Run

  # 4. Disable Cloud Microsoft Entra ID devices inactive for > 180 days
  .\Disable-StaleComputers\Disable-StaleComputers.ps1 -Mode Cloud -StaleDays 180 -Action Disable
  ```

---

### 5. [**Reset-UserPassword**](Reset-UserPassword/README.md)
* **Script:** [`Reset-UserPassword/Reset-UserPassword.ps1`](Reset-UserPassword/Reset-UserPassword.ps1)
* **Author:** Roman Pindela (`roman.pindela@gmail.com`)
* **Version:** 1.2.0
* **Description:** Primary emergency / rescue PowerShell script for immediately resetting a forgotten user password to a temporary password and enforcing a mandatory password change at first logon (`ChangePasswordAtLogon = $true`).
  * **Dual Directory Support (`-Mode Local | Cloud | Both`):** Resets user passwords in Local Active Directory (`Set-ADAccountPassword -Reset $true` & `Set-ADUser -ChangePasswordAtLogon $true`) and/or Cloud Microsoft Entra ID (`Update-MgUser -PasswordProfile` via Microsoft Graph SDK).
  * **Interactive & Automated Modes:** Supports interactive `Read-Host` / `Read-Host -AsSecureString` rescue prompts (`-Interactive`), parameterized execution (`-Login`, `-NewPassword`), cryptographic random temporary password generation (`-GenerateRandomPassword`), and automatic account unlocking (`-UnlockAccount`).
  * **Unattended / Non-Interactive Entra ID Authentication:** Supports App-Only authentication via Client Secret (`-TenantId`, `-ClientId`, `-ClientSecret`) or X.509 Certificate (`-CertificateThumbprint`) with `UserAuthenticationMethod.ReadWrite.All`, `User.ReadWrite.All`, and `Directory.Read.All` permissions.
  * **Standards Compliant:** Displays help when launched without parameters (`-h` / `-Help`), performs language-independent SID UAC auto-elevation (`S-1-5-32-544` for Polish `Administratorzy` and English `Administrators`), displays a real-time `Write-Progress` bar, and writes detailed audit logs to `C:\Logs\<yyyyMMdd_HHmmss>-Reset-UserPassword-<ComputerName>-<UserName>.logs`.
* **Quick Start:**
  ```powershell
  # 1. Unblock the script after downloading from GitHub
  Unblock-File -Path .\Reset-UserPassword\Reset-UserPassword.ps1

  # 2. Display help & Entra ID non-interactive setup instructions
  .\Reset-UserPassword\Reset-UserPassword.ps1 -h

  # 3. Interactive emergency password reset in Local Active Directory
  .\Reset-UserPassword\Reset-UserPassword.ps1 -Interactive

  # 4. Reset user password in Cloud Microsoft Entra ID
  .\Reset-UserPassword\Reset-UserPassword.ps1 -Login "jkowalski@firma.pl" -Mode Cloud
  ```

---

### 6. [**User-LogonScript**](User-LogonScript/README.md)
* **Script:** [`User-LogonScript/User-LogonScript.ps1`](User-LogonScript/User-LogonScript.ps1) & [`User-LogonScript/LogonScript.ps1`](User-LogonScript/LogonScript.ps1)
* **Author:** Roman Pindela (`roman.pindela@gmail.com`)
* **Version:** 1.2.0
* **Description:** End-to-end PowerShell User Logon Script and Group Policy (GPO) / Cloud Intune deployment toolkit that maps persistent network drives (`New-PSDrive -Persist`, e.g., `Z:` $\rightarrow$ `\\serwer\zasob`), logs logon verification to `C:\Temp\LogonStatus.txt` (`"Zalogowano pomyślnie dnia $(Get-Date)"`) and `C:\Logs`, copies `LogonScript.ps1` to the domain `SYSVOL` share (`\\twojadomena.local\sysvol\twojadomena.local\scripts`), configures GPO PowerShell User Logon Scripts and GPO `ExecutionPolicy`, and verifies execution with `gpupdate /force`.
  * **Dual Directory Support (`-Mode Local | Cloud | Both`):** Supports On-Premises Active Directory (`SYSVOL` + `GroupPolicy` + group-filtered drive mapping) and Cloud Microsoft Entra ID / Intune (`Invoke-MgGraphRequest` for Entra ID group checks and Intune `deviceManagementScripts` deployment).
  * **Unattended / Non-Interactive Entra ID Authentication:** Supports App-Only authentication via Client Secret (`-TenantId`, `-ClientId`, `-ClientSecret`) or X.509 Certificate (`-CertificateThumbprint`) with `User.Read.All`, `GroupMember.Read.All`, and `DeviceManagementConfiguration.ReadWrite.All` permissions.
  * **Standards Compliant:** Displays help and the complete 4-step GPO Logon Script guide when launched without parameters (`-h` / `-Help`), performs language-independent SID UAC auto-elevation (`S-1-5-32-544` for Polish `Administratorzy` and English `Administrators`), and writes detailed audit logs to `C:\Logs\<yyyyMMdd_HHmmss>-User-LogonScript-<ComputerName>-<UserName>.logs`.
* **Quick Start:**
  ```powershell
  # 1. Unblock the scripts after downloading from GitHub
  Unblock-File -Path .\User-LogonScript\User-LogonScript.ps1

  # 2. Display help, 4-step GPO tutorial & Entra ID setup instructions
  .\User-LogonScript\User-LogonScript.ps1 -h

  # 3. Execute User Logon Script (map Z: -> \\serwer\zasob & log to C:\Temp\LogonStatus.txt)
  .\User-LogonScript\User-LogonScript.ps1 -DriveLetter "Z:" -NetworkPath "\\serwer\zasob"

  # 4. Deploy LogonScript.ps1 to SYSVOL, create/link GPO & configure GPO ExecutionPolicy
  .\User-LogonScript\User-LogonScript.ps1 -DeployGPO -DomainName "twojadomena.local" -GpoName "Skrypty_Logowania_GPO" -TargetOU "OU=Pracownicy,DC=twojadomena,DC=local" -ConfigureExecutionPolicy -Force
  ```

---

## 🛡️ Security & PowerShell Standards

All PowerShell scripts in this repository adhere to strict quality and security standards:
1. **Unblock Downloaded Scripts:**
   ```powershell
   Get-ChildItem -Path . -Filter *.ps1 -Recurse | Unblock-File
   ```
2. **Zero-Parameter Help Menu:** Running any `.ps1` script without parameters or with `-h` / `-Help` displays full usage instructions without making system changes.
3. **Language-Independent UAC Auto-Elevation:** Administrator checks use Windows well-known SID `S-1-5-32-544` (`BuiltInAdministratorsSid`), supporting both Polish (`Administratorzy`) and English (`Administrators`) OS locales.
4. **Centralized Audit Logging:** Execution logs are saved automatically to `C:\Logs\<DateTime>-<ScriptName>-<ComputerName>-<UserName>.logs`.

---

## 👨‍💻 Author & Contact

* **Author:** Roman Pindela
* **Email:** [roman.pindela@gmail.com](mailto:roman.pindela@gmail.com)
* **GitHub:** [https://github.com/romanpindela](https://github.com/romanpindela)
* **License:** MIT
