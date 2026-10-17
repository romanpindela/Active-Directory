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
├── Get-InactiveUsersReport/             # Security audit report of inactive AD & Entra ID user accounts (>90 days)
│   ├── Get-InactiveUsersReport.ps1      # Main PowerShell security auditing script
│   └── README.md                        # Full technical documentation and Entra ID setup guide
├── New-ADUsersFromCSV/                  # Bulk Active Directory & Entra ID user provisioning from CSV
│   ├── New-ADUsersFromCSV.ps1           # Main PowerShell automation script
│   ├── uzytkownicy.csv                  # Ready-to-use sample CSV user import template
│   └── README.md                        # Full technical documentation and Entra ID setup guide
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
