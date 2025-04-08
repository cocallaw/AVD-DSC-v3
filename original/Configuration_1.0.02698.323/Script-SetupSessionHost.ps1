<#

.SYNOPSIS
Set up a VM as session host to existing/new host pool.

.DESCRIPTION
This script installs RD agent and verify that it is successfully registered as session host to existing/new host pool.

#>
param(
    [Parameter(mandatory = $true)]
    [string]$HostPoolName,

    [Parameter(Mandatory = $true)]
    [string]$RegistrationInfoToken,

    [Parameter(Mandatory = $false)]
    [bool]$AadJoin = $false,

    [Parameter(Mandatory = $false)]
    [bool]$AadJoinPreview = $false,

    [Parameter(Mandatory = $false)]
    [string]$MdmId = "",

    [Parameter(Mandatory = $false)]
    [string]$SessionHostConfigurationLastUpdateTime = "",

    [Parameter(mandatory = $false)] 
    [switch]$EnableVerboseMsiLogging,
    
    [Parameter(Mandatory = $false)]
    [bool]$UseAgentDownloadEndpoint = $false
)
$ScriptPath = [system.io.path]::GetDirectoryName($PSCommandPath)

# Dot sourcing Functions.ps1 file
. (Join-Path $ScriptPath "Functions.ps1")
. (Join-Path $ScriptPath "AvdFunctions.ps1")

# Setting ErrorActionPreference to stop script execution when error occurs
$ErrorActionPreference = "Stop"

# Checking if RDInfragent is registered or not in rdsh vm
Write-Log -Message "Checking whether VM was Registered with RDInfraAgent"
$RegistryCheckObj = IsRDAgentRegistryValidForRegistration

if ($RegistryCheckObj.result)
{
    Write-Log -Message "VM was already registered with RDInfraAgent, script execution was stopped"
}
else
{
    Write-Log -Message "Creating a folder inside rdsh vm for extracting deployagent zip file"
    $DeployAgentLocation = "C:\DeployAgent"
    ExtractDeploymentAgentZipFile -ScriptPath $ScriptPath -DeployAgentLocation $DeployAgentLocation

    Write-Log -Message "Changing current folder to Deployagent folder: $DeployAgentLocation"
    Set-Location "$DeployAgentLocation"

    Write-Log -Message "VM not registered with RDInfraAgent, script execution will continue"

    Write-Log "AgentInstaller is $DeployAgentLocation\RDAgentBootLoaderInstall, InfraInstaller is $DeployAgentLocation\RDInfraAgentInstall"

    if ($AadJoinPreview) {
        Write-Log "Azure ad join preview flag enabled"
        $registryPath = "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\AzureADJoin"
        if (Test-Path -Path $registryPath) {
            Write-Log "Setting reg key JoinAzureAd"
            New-ItemProperty -Path $registryPath -Name JoinAzureAD -PropertyType DWord -Value 0x01
        } else {
            Write-Log "Creating path for azure ad join registry keys: $registryPath"
            New-item -Path $registryPath -Force | Out-Null
            Write-Log "Setting reg key JoinAzureAD"
            New-ItemProperty -Path $registryPath -Name JoinAzureAD -PropertyType DWord -Value 0x01
        }
        if ($MdmId) {
            Write-Log "Setting reg key MDMEnrollmentId"
            New-ItemProperty -Path $registryPath -Name MDMEnrollmentId -PropertyType String -Value $MdmId
        }
    }

    InstallRDAgents -AgentBootServiceInstallerFolder "$DeployAgentLocation\RDAgentBootLoaderInstall" -AgentInstallerFolder "$DeployAgentLocation\RDInfraAgentInstall" -RegistrationToken $RegistrationInfoToken -EnableVerboseMsiLogging:$EnableVerboseMsiLogging -UseAgentDownloadEndpoint $UseAgentDownloadEndpoint

    Write-Log -Message "The agent installation code was successfully executed and RDAgentBootLoader, RDAgent installed inside VM for existing hostpool: $HostPoolName"
}

Write-Log -Message "Session Host Configuration Last Update Time: $SessionHostConfigurationLastUpdateTime"
$rdInfraAgentRegistryPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent"
if (Test-path $rdInfraAgentRegistryPath) {
    Write-Log -Message ("Write SessionHostConfigurationLastUpdateTime '$SessionHostConfigurationLastUpdateTime' to $rdInfraAgentRegistryPath")
    Set-ItemProperty -Path $rdInfraAgentRegistryPath -Name "SessionHostConfigurationLastUpdateTime" -Value $SessionHostConfigurationLastUpdateTime
}

if ($AadJoin -and -not $AadJoinPreview) {
    # 6 Minute sleep to guarantee intune metadata logging
    Write-Log -Message ("Configuration.ps1 complete, sleeping for 6 minutes")
    Start-Sleep -Seconds 360
    Write-Log -Message ("Configuration.ps1 complete, waking up from 6 minute sleep")
}

$SessionHostName = GetAvdSessionHostName
Write-Log -Message "Successfully registered VM '$SessionHostName' to HostPool '$HostPoolName'"
# SIG # Begin signature block
# MIIoTQYJKoZIhvcNAQcCoIIoPjCCKDoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA/CKbPlvATPvmx
# IVOTe4Ocl7sB/llMbGXOF2+Aw8Yg5aCCDWowggY1MIIEHaADAgECAhMzAAAACKqz
# iRzOy0aDAAAAAAAIMA0GCSqGSIb3DQEBDAUAMIGEMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1
# aWxkIFRvb2xzIFBDQSAyMDIwMB4XDTIzMDkxNDE5MDQwMFoXDTI0MDkwNDE5MDQw
# MFowgYQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNV
# BAMTJVdpbmRvd3MgSW50ZXJuYWwgQnVpbGQgVG9vbHMgQ29kZVNpZ24wggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9uL7jG2C2s7oMEevviXxKl7nlGCU0
# s7ulUUuc/YipMtAzPNg9M5rrePxHKEmElgI0lIS6Ltk/oGrKjPYi5e+FcYbmpFib
# gQfqaQ/HlTNvEgJly5Z8kQo+sIh4Fmuv656t6V5aGFW0Na9Zm38/wH105pAdos20
# 6RIa/1b3S6ju9zNtHh1Vg406mspSoWC4AfTp4GjHnUK19IpQHL55fAUqd8cSi66X
# rBK25A2fRpn1BCgr248dcs3+MlqzvQgqMZCtG6KalqMI73aQUPBuDBTX6QsTZVG0
# V19oV9x0ydefJyc1kZP4q8jTuekwDh3RhDiBvq+6ufiNwienhz3K2EULAgMBAAGj
# ggGcMIIBmDAgBgNVHSUEGTAXBggrBgEFBQcDAwYLKwYBBAGCN0w3AQEwHQYDVR0O
# BBYEFJ6mZFUzC6UndRJKaa4AzbVFqg2+MEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQL
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTQ1ODIwNCs1MDE0OTIw
# HwYDVR0jBBgwFoAUoH7qzmTrA0eRsqGw6GOA4/ZOZaEwaAYDVR0fBGEwXzBdoFug
# WYZXaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvV2luZG93cyUy
# MEludGVybmFsJTIwQnVpbGQlMjBUb29scyUyMFBDQSUyMDIwMjAuY3JsMHUGCCsG
# AQUFBwEBBGkwZzBlBggrBgEFBQcwAoZZaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9XaW5kb3dzJTIwSW50ZXJuYWwlMjBCdWlsZCUyMFRvb2xz
# JTIwUENBJTIwMjAyMC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEASZrRvo5C509NLy4KCkgXm8qWCaHq9UmWYpoQP7og4QHgi6qOykezDrkUr/9i
# pxur3TNo1SxihwwNydJHphJ+3QciRt8dCTdofQyGEsm18aKtA5c1f2oasan4Yw4S
# zWS7wDIoSx7fGcZR7wSSXr4xLdDHD45jjTRkXeB0iBXKslfjCl7FhOUPT1mYe7ap
# S2b1Lay8vM1GC2edFREO8HVl7Imgg/KNVsa01vBrgoYR2D4F2d8kMLOSWvzCClbP
# 0S6Fjzd1SuBr3l3+Kd2WKMHe6gmK6CXzYDDS4boIItf58o7Q/8pVzv2QpY8JzzLZ
# 1vc8BaP8JZmKxTcXUUz7bHoMlomPBIYukmlzos1JMoLYG4ZZV0PWwqlV7P0odsh3
# judtMWhliDZSg+LNIN1Wv17q1vH5mDwUMsg7tVgkdsaDMBl1e47OFy0ZFs6rQAqM
# 6hjXx6A8y7NReDrkOrx4rzYWB4qZ2E1RCUgNXaellA4A2+dVbyP1URhWPIFN/Epo
# hQoM6pOzcZWGJU+zAPj/Mulml1XXm2lZvHXmibEWTyG004tn7MIWBR0uyoaHmoyq
# KpFI1FxKhjrvphhUR51RciV2jTu8ztqk0I1xmibYCY/p+CakV/dkR6IXJn2VhquC
# Aa86W2qxNHiIJnmsdLpvGrKZiThLC8B07oYG2+TVV8hBjRkwggctMIIFFaADAgEC
# AhMzAAAAVlq1acsdlGgsAAAAAABWMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBT
# ZXJ2aWNlcyBQYXJ0bmVyIFJvb3QwHhcNMjAwMjA1MjIzNDEyWhcNMzUwMjA1MjI0
# NDEyWjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEuMCwG
# A1UEAxMlV2luZG93cyBJbnRlcm5hbCBCdWlsZCBUb29scyBQQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJeO8Bi8BZ0LmiWJmxhr8XqilrM9
# 8Le3i6/bgnolF1sE2w8obZr5HmO8FnkT+2TPpVMWsvnz8NaybPtns+i1a3lX+F85
# uM2pX+kBnaUPjRNZ4Nr4eYZeTNsu+fvJkkuFg1dcQqRypLdSbpSz4NSb6rjFxF7i
# Z2A7JnhVaR2eKSmFMCNH8fLz10ORthw/YwS1xvw/Lm5TU+YSRQWfydS+wgfMPapg
# oXtrOp28UH+HXoySBu0uQYC6azrB/eTPNiDQO4TlAJdWzV4yvLSpEKIVisUZTAQL
# cE9wVumQQvG8HKIF3v5hr+U/5aDEOJaqlNPqff99mYSuajKHQWPV4wJUHMohX93j
# nz7HhtJLhf/UeVglNcKayiiTI0NcCJbyPxD1/nCy2F3wnTmrF43lHJHHeNIunrNI
# sI6OhbELkWIZiVp83Dt9/5db2ULbdf564qRZAO2VUlvD0dFA1Ii9GZbqSThenYsY
# 0gnmZ1QIMJVJIt0zPUY1E0W+n/zkEedBM+jbaBw6De+zBNxTjpDg3qf1nRibmXGW
# SXv3uvyqzW+EnAozTUdr1LCCbsQTlEH+gzHG9nQy4zl1gTbbPMF77Lokxhueg/kr
# sHlsSGDI/GIBYu4fVvlU6uzAfahuQaFnIj5WHNkN6qwIFDFmNvpPRk+yOoMLAAm9
# XHKK1BxyOKixu/VTAgMBAAGjggGbMIIBlzAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFKB+6s5k6wNHkbKhsOhjgOP2TmWhMFQGA1Ud
# IARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSNuOM2u9Xe
# l8uvDk17vlofCBv6BjBRBgNVHR8ESjBIMEagRKBChkBodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3Js
# MF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3J0
# MA0GCSqGSIb3DQEBDAUAA4ICAQBhSN9+w4ld9lyw3LwLhTlDV2sWMjpAjfOdbLFa
# tPpsSjVGHLBrfL+Y97dUfqCYNMYS5ByP41eRtKvrkby60pPxDjow8L/3tOVZmENd
# BU3vn28f7wCNy5gilO444fz4cBbUUQHnc94nMsODly3N6ohm5gGq7p0h9klLX/l5
# hbe2Rxl5UsJo3EuK8yqP7xz7thbL4QosQNsKiEFM91o8Q/Frdt+/gni6OTWVjCNM
# YHVB4CWttzJyvP8A1IzH0HEBG95Rdd9HMeudsYOHRuM4A0elUvRqOnsfqP7Zs46X
# NtBogW/IacvPGeuy3AHXIgMfFk35P9Mrt/ipDuqPy07faWLr0d+2++fWGv0yMSEf
# 0VWsMIYUK7fnmO+WK2j74KO/hFj3c+G/psecslWdT6zpeLntMB0IkqxN+Gw+qzc9
# 1vol2TEMHP2pITosnXYt33nZ9XR9YQmvMHBxwcF6qUALem5nOYMu574bCK6iOJdF
# SMfaUiLGppk7LOID0saA965KSWyxcpsxgvGnovjeUV1rJkN/NyPI3m5+t5w0v54J
# V2iCjgnsuF90m0cb2E3UUdEsbC6gBppQ/038OBoWMeVcd2ppmwP5O5vL5s4fCUp5
# p/og24gdqwrLJMZ+dHYVf3MsRqm7Lx3OVuxTuqbguRui+FdJtoBR/dMGFCWho1JE
# 8Qud9TGCGjkwgho1AgEBMIGcMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1aWxkIFRvb2xz
# IFBDQSAyMDIwAhMzAAAACKqziRzOy0aDAAAAAAAIMA0GCWCGSAFlAwQCAQUAoIHU
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDltxb/agplOYEsoeuzzZLrw4npsG42
# +w9bmVt4NJklbjBoBgorBgEEAYI3AgEMMVowWKA6gDgAVwBpAG4AZABvAHcAcwAg
# AEIAdQBpAGwAZAAgAFQAbwBvAGwAcwAgAEkAbgB0AGUAcgBuAGEAbKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAPvZfVk8CV4iR
# uk601szgXHjQ7nCa/JXYjQ0EvaEyHzQBphHsKXNOQR15e5xv+q9DicZTSou1uRQw
# 5yCyyXmA+NA8GE9b9NEuge8Bt5GylW8PpYViOxAcetGuFA3vHLdTXufLAnV4/3Sy
# s85hf9T43xOLgsOkOMdYv8eOW3Y5PBr9GExl8f0ukOgER3TRJsUOMB3oux4pScAO
# hAuXVOH91ruFHeH3DkbpdvbaWiicdxVI8pODcU+s6I+VbOtqtS0fMEQFND+sAxVz
# 2XCJNso4xnv4J6o2LCzLNCYsuYmsdDjYczQ6yfi2cLf8NV756xS0lg/RB40JWvge
# 4M8F/OSPpKGCF5YwgheSBgorBgEEAYI3AwMBMYIXgjCCF34GCSqGSIb3DQEHAqCC
# F28wghdrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAE
# ggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCDKxDmozcnj
# 43iRsfLJxhr5iSNGKeSZeevoyQBbHxwsSAIGZkYiyMUNGBIyMDI0MDUyMjE5MjUx
# Ni44M1owBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjo3RjAwLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEe0wggcgMIIFCKADAgEC
# AhMzAAAB8Cp8HVk75h+tAAEAAAHwMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMTIwNjE4NDU1MVoXDTI1MDMwNTE4NDU1
# MVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjo3RjAwLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ALUeLVOjOHc7RzMTzF9GevKaUk0JoZaiaY/LR4g1/7gQmvut/y1LOWATwiXhmPjx
# Pl9NM4CHqchNF/aUrv66lydn/GDQAqgNikFA5asv05sVKHKUgd+v8NDg+xFfwZG0
# ie4mwyTBKDrdt8HhDZSKQwQ/8K1keLzFble0Aqn3lyzea9QIy8gADzcmv9TIAMAI
# ldVTiZpiKxzNTPsnXXV4PUqsb2ZD4hOCdFH9fbFMMwLP6KjxlkUcbARmD5ze+Y+n
# zubg6o4pbKFyoxS6k+947+BAL1G/izMs0YNqh494rohTQmpwaNerFtwShL+zWEKA
# 93tTHphZ5atRdrFtv4miyA5rNSBQazVqqmcuPPRgp9SqfyLlNuZHV2oSVHhAD45l
# 95WGlOiesziwT8yUnUkulHYXAAgdR4x+i1c1CLK1h9EFQ4kcV4lgR+VmBWTRfH/i
# RkF3OAVA85Z9V3Y2jNeULZ6ka1SNqW4Daiw69AdnMY6gpO9ZQ9f30yywY5s7TEkd
# 3QPKA/8kBWn5tEYmpra7sCoubb60BPbrIjm95xwOY1myDe8OHUdykIlr1ClFb8wP
# dr4AXbKBXWxGcZVRUbdU4NfcGEZPxMxT8aJTLeHsKVc7GZn7B4K4g7MKRMNsrk6U
# BLypI+mCn5caU4sQ9ozfUyB/phOmkBp4/SimHHfjmiG3AgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQU0IKyp1dHL8yaNkZVMC/HtgVamyUwHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBADgi9JueviMQ+CjlbjGPf/7R0IbCzPzrdAZnaYH1nhLC0YYsy/B+xFSz
# c0iU8P8uxYDF1VgeSUDPAtPBDkz49F3L3YMZ+3IQ4Ywd+63sarwvdFRy+u+vQAv8
# 0218SlsASQIXOx57G1jmzeHOPetfbC+gFmbbK2HBwt5mYyAdAKaNmn/bR8dYmCuM
# 9iOx7pEMm1ROW9SyOv7zvz+36+tAQiqWZ5sJ4SL5VBXFzvAXQu4xPD+AJZ1yoeio
# vnYmi3ErNjyNlJDtxw0eELh4cYVGlop6JJDQZe2VsYhs/iRbU7cnOUqN/AbrY0JK
# 9+YzWI8P3RdiIWbv/yaBHXoCap58Ox+MEJbB/eqF4gx+BnNap4TPyVoWYzwN2ReO
# 44JAT/YvRPGGuNS10yQBN9d1mNhGWxwEPKvzMYyWmsULstzGoJeWHGG13YIz6alx
# NzxEHYPcSivRR2g/fpD2vhdYJVX/YqfQBe29bG8h/I4WblouXR4TOSF+/9eZSUF4
# 4ISVLuN111akGVCMm4cdQeM5UZeWslPtfiGJwXWjbfHlT6Puo8oFx6vI/b/WjF+Y
# dzq4FeVcEq6RX9AJkFUCIExgmGeS1qRYemj24h5KdhPpDHvB/ZFq5gcgRHxItGZu
# UzM86z4kdDOu+HvFK3HfXQs6n7QNo5ezzGNm+Gmf5a5mKPlGZmKMMIIHcTCCBVmg
# AwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9z
# b2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgy
# MjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ck
# eb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+
# uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4
# bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhi
# JdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD
# 4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKN
# iOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXf
# tnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8
# P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMY
# ctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9
# stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUe
# h17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQID
# AQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4E
# FgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9
# AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38
# Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTlt
# uw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99q
# b74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQ
# JL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1
# ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP
# 9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkk
# vnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFH
# qfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g7
# 5LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr
# 4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghi
# f9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCA1AwggI4AgEBMIH5oYHRpIHO
# MIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046N0YwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAMIoBkoq/mWx0LbKgwYpiJDL
# v2n/oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDp+InbMCIYDzIwMjQwNTIyMTUxMjI3WhgPMjAyNDA1MjMxNTEy
# MjdaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOn4idsCAQAwCgIBAAICJuQCAf8w
# BwIBAAICFS8wCgIFAOn521sCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEA
# ZPIiUfcuO/fFskTbSILeSZ1rhUus0vd+3mk7g9h2gDXYgGRt28iy35+TRmspTbJu
# wKxuCeORyxjFZ4VPjEiKHySS+GWHZ5rsE61nXg86DVu+Sfm2ycuwbreP14paJMZE
# yyVESAFcDcPBO5cP63eUNmRopl1LvB1K1Eqr7tHhmUKh9AKKTe91ts63PuHKyR4H
# wF8M3cPEpiQRr2GGS3Lh6tV6abCBqFS0Ti7fOeqDqHKHc9tWnhfgXuiGYd/0i4DV
# rRxPnMVRTTeEYJRmTdutfG1je81Ys9BDPxVNRLBU2gFlxLYA9EZFgKazE04TRBwI
# jK7iG9Cmv25acV0LU/BqfjGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAAB8Cp8HVk75h+tAAEAAAHwMA0GCWCGSAFlAwQCAQUA
# oIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIE
# IIejsxs4lK4Dr3XkBsMwvp6Oj6lR1lAb16E/1KOUr+kIMIH6BgsqhkiG9w0BCRAC
# LzGB6jCB5zCB5DCBvQQgXAGao6Vy/eRTuYAHmxZHvhAUCJLqZv4IzpqycUBlS4sw
# gZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAfAqfB1Z
# O+YfrQABAAAB8DAiBCCzpPXAJy3WJwI3tDgPVhCZJG2jLECC4v+koriGgtLUijAN
# BgkqhkiG9w0BAQsFAASCAgBcVDAZtGzrvU2FO+miA3ZV9JT2frwJqEUA8prH/i2e
# i0mxihAF+HWhkRsdBhg82Gxy+nh9tQUKYtCFTvC0qMAFwbMoFtEvHNU2dNPipD+R
# 60gwJKvAoEhk6ZwSe/UJrsyP1Y1Fw1yFwxHBS2tbYQZpVvTXtg75IA3DtmjUDraf
# OXG+Yz2zHomzc5xzyxvWhbhfD9AAzXQiEIOZ8Zhf7ONox8tfmsedU4EU2VYybpI1
# l1VSgXfgBLpqzVecmvy6rbQmk0t2bwmvaXJn5PS37mddqhxL4hLo3ZOd4aYMIMpg
# PUriACk8UYVYgcVGdP7cfARKpGnqLDa5KF6kDUq0Rgv7vjixQjg15RR3VR/W/6t4
# lcNHBNeXsmzKpg+KqOfgcqieX7aFecBNoUWNPg8aJuNhb1u+GuARc/SLWspz07qT
# mY2HZBgyPnLjlTKZ44sZr180VHI11kkqNyrz0MFYAE2DMH7Vccszy71qe64NBDoD
# DyyLCZX/7k/skgVEF55ybh9es1txMyTG1GBGwPf0PQcqSTX+WWk1k7AEcy7C9tUN
# 0cWzVsvysSs+3MFTUP8sNtiTeWwW34fSuJSAEGwMf/mOq+RzHY3+PBMVCVxmay3l
# euDruX2dsZ5tEIF6rUKOgGXM9wCOSpsMvRA0bu77rhkAND3PM/EH9X+arZ3ZRQxi
# Qg==
# SIG # End signature block
