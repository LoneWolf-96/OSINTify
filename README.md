# OSINTify
A Light weight Python executable to search common OSINT tooling.

---

## Features
- 📥 Pipe in a list of un-sorted and unorganised IOCs to search
- 📋 Formatted summary output tables
- 🏷️ Categorise IOCs
   * IPv4 & type e.g., Public, RFC1918, Loopback, etc.
   * SHA or Message-Digest Hashes e.g., SHA-1, SHA-256, MD5
- 🔍 Search Common OSINT Services
    * Shodan
    * VirusTotal

---

## Set up
API Secrets are stored as environment Variables
### Envioment Varaibles
| Name | Purpose |
| --- | --- |
| `SHO_API_KEY` | Shodan API Secret. | 
| `VT_API_KEY` | VirusTotal API Key. | 

#### Helpful Note
| OS | Type | Command |
| -- | -- | -- |
| Windows - PowerShell | Adhoc | ``$env:VAR="value"`` |
| Windows - PowerShell | Persistence | ``setx VAR "value"`` |
| Linux - bash | Adhoc | ``export VAR=value`` |
| Linux - Bash | Persistence | Add ``export VAR=value`` to `~/.bashrc` then reload with `source ~/.bashrc` |
