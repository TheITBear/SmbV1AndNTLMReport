# ========================================================================
# Script Name: SMB_NTLM_Audit.ps1
# Description: Check SMBv1 and NTLMv1 usage on local Domain Controller
# Author: Raffaele Fusco
# Output: Console + C:\Temp\SMB_NTLM_AuditReport-*.txt
# ========================================================================

# --- CONFIGURAZIONE ---
$LogPath = "C:\Temp"
If (!(Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory | Out-Null }
$Timestamp = Get-Date -Format "yyyyMMdd-HHmm"
$ServerName = $env:COMPUTERNAME
$ReportFile = "$LogPath\$ServerName_SMB_NTLM_AuditReport_$Timestamp.txt"

# --- OUTPUT FUNCTION ---
Function Write-Result {
    param ([string]$Text)
    Write-Host $Text
    Add-Content -Path $ReportFile -Value $Text
}

Write-Result "=============================================="
Write-Result " SMBv1 & NTLMv1 Audit - $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
Write-Result "==============================================`n"

# === SMBv1 STATUS CHECK ===
Write-Result "[SMBv1] STATUS CHECK:"
$smb1Status = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue

if ($smb1Status.State -eq 'Enabled') {
    Write-Result "SMBv1 is ENABLED on this system.`n"
} elseif ($smb1Status.State -eq 'Disabled') {
    Write-Result "SMBv1 is DISABLED on this system.`n"
} else {
    Write-Result "SMBv1 status could not be determined.`n"
}

# === SMBv1 USAGE CHECK ===
Write-Result "[SMBv1] CONNECTION AUDIT (last 7 days):"
$smbLogs = Get-WinEvent -LogName "Microsoft-Windows-SMBServer/Audit" -MaxEvents 500 |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-7) }

if ($smbLogs.Count -gt 0) {
    Write-Result "WARNING: SMBv1 connections detected in the last 7 days."
    $smbLogs | Select-Object TimeCreated, Id, Message | ForEach-Object {
        Write-Result ("{0} - ID:{1} - {2}" -f $_.TimeCreated, $_.Id, $_.Message.Split("`n")[0])
    }
    $smbUsage = $true
} else {
    Write-Result "No SMBv1 usage detected in the last 7 days.`n"
    $smbUsage = $false
}

# === NTLM POLICY CHECK ===
Write-Result "[NTLMv1] POLICY CHECK:"
$lmLevel = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -ErrorAction SilentlyContinue

switch ($lmLevel.LmCompatibilityLevel) {
    0 { $mode = "Send LM & NTLM responses"; $v1Allowed = $true }
    1 { $mode = "Send LM & NTLM - use NTLMv2 if negotiated"; $v1Allowed = $true }
    2 { $mode = "Send NTLM response only"; $v1Allowed = $true }
    3 { $mode = "Send NTLMv2 only"; $v1Allowed = $false }
    4 { $mode = "Refuse LM, Send NTLMv2 only"; $v1Allowed = $false }
    5 { $mode = "Refuse LM & NTLM, Send NTLMv2 only"; $v1Allowed = $false }
    default { $mode = "Unknown"; $v1Allowed = $true }
}

Write-Result "NTLM compatibility level: $($lmLevel.LmCompatibilityLevel) - $mode`n"

# === NTLM USAGE CHECK ===
Write-Result "[NTLMv1] LOGON AUDIT (Event 4624 - last 7 days):"
$start = (Get-Date).AddDays(-7).ToString("o")

$query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) and TimeCreated[@SystemTime>='$start']]]
      and *[EventData[Data[@Name='AuthenticationPackageName'] = 'NTLM']]
    </Select>
  </Query>
</QueryList>
"@

$ntlmEvents = Get-WinEvent -FilterXml $query -MaxEvents 5000

if ($ntlmEvents.Count -eq 0) {
    Write-Result "No NTLM logons detected in the last 7 days.`n"
    $ntlmUsage = $false
} else {
    Write-Result "WARNING: NTLM logons detected in the last 7 days:`n"
    $ntlmUsage = $true
    $ntlmEvents | Select-Object TimeCreated,
        @{Name="TargetUser"; Expression={$_.Properties[5].Value}},
        @{Name="IP Address"; Expression={$_.Properties[18].Value}},
        @{Name="Workstation"; Expression={$_.Properties[11].Value}} |
    ForEach-Object {
        Write-Result ("{0} - {1} - {2} - {3}" -f $_.TimeCreated, $_.TargetUser, $_."IP Address", $_.Workstation)
    }
}

# === RECOMMENDATION SUMMARY ===
Write-Result "`n=============================================="
Write-Result " DISMISSIBILITY REPORT SUMMARY"
Write-Result "=============================================="

# SMB Summary
Write-Result "`n[SMBv1]"
if ($smb1Status.State -eq 'Disabled') {
    Write-Result "Status: DISABLED ✅"
} elseif ($smbUsage -eq $false) {
    Write-Result "Status: ENABLED - NO USAGE DETECTED ✅"
    Write-Result "Recommended Action: Safe to disable SMBv1."
} else {
    Write-Result "Status: ENABLED - USAGE DETECTED ⚠️"
    Write-Result "Action Required: Identify and migrate clients using SMBv1 before disabling."
}

# NTLM Summary
Write-Result "`n[NTLMv1]"
if ($v1Allowed -eq $false -and $ntlmUsage -eq $false) {
    Write-Result "Status: NTLMv1 Refused - No usage detected ✅"
    Write-Result "Recommended Action: Already compliant."
} elseif ($v1Allowed -eq $false -and $ntlmUsage -eq $true) {
    Write-Result "Status: NTLMv1 Refused - Usage Detected ⚠️"
    Write-Result "WARNING: Clients might be falling back to cached/legacy NTLM."
} elseif ($v1Allowed -eq $true -and $ntlmUsage -eq $false) {
    Write-Result "Status: NTLMv1 Allowed - No usage detected ⚠️"
    Write-Result "Recommended Action: Change LAN Manager Authentication Level to refuse NTLMv1."
} else {
    Write-Result "Status: NTLMv1 Allowed - Usage Detected ❌"
    Write-Result "Action Required: Identify clients using NTLMv1 and upgrade or reconfigure them."
}

Write-Result "`nAudit complete. Log saved to: $ReportFile"
