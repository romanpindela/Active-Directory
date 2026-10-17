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
