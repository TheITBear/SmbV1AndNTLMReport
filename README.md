# SMB-NTLM Audit Script

Audit SMBv1 and NTLMv1 protocol usage on a Windows Domain Controller.

## Features
- Detects SMBv1 status and recent activity
- Checks NTLMv1 compatibility level and usage (Event 4624)
- Displays result and saves audit in `C:\Temp`

## Usage
Run with administrative privileges on the DC:

```powershell
.\SMB_NTLM_Audit.ps1
```

## Output
- Detailed log in C:\Temp
- Console output
