configuration AddSessionHost
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string]$RegistrationInfoToken = "",

        [Parameter(Mandatory = $false)]
        [PSCredential]$RegistrationInfoTokenCredential = $null,

        [Parameter(Mandatory = $false)]
        [bool]$AadJoin = $false,

        [Parameter(Mandatory = $false)]
        [bool]$AadJoinPreview = $false,

        [Parameter(Mandatory = $false)]
        [string]$MdmId = "",

        [Parameter(Mandatory = $false)]
        [string]$SessionHostConfigurationLastUpdateTime = "",

        [Parameter(Mandatory = $false)]
        [bool]$EnableVerboseMsiLogging = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseAgentDownloadEndpoint = $false
    )

    $ErrorActionPreference = 'Stop'
    
    $ScriptPath = [system.io.path]::GetDirectoryName($PSCommandPath)
    . (Join-Path $ScriptPath "Functions.ps1")

    $rdshIsServer = isRdshServer

    $RegistrationInfoTokenValue = ""
    if ($null -eq $RegistrationInfoTokenCredential) {
        $RegistrationInfoTokenValue = $RegistrationInfoToken
    } else {
        $RegistrationInfoTokenValue = $RegistrationInfoTokenCredential.GetNetworkCredential().Password
    }

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }

        if ($rdshIsServer)
        {
            "$(get-date) - rdshIsServer = true: $rdshIsServer" | out-file c:\windows\temp\rdshIsServerResult.txt -Append
            WindowsFeature RDS-RD-Server
            {
                Ensure = "Present"
                Name = "RDS-RD-Server"
            }

            Script ExecuteRdAgentInstallServer
            {
                DependsOn = "[WindowsFeature]RDS-RD-Server"
                GetScript = {
                    return @{'Result' = ''}
                }
                SetScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    try {
                        & "$using:ScriptPath\Script-SetupSessionHost.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoTokenValue -AadJoin $using:AadJoin -AadJoinPreview $using:AadJoinPreview -MdmId $using:MdmId -SessionHostConfigurationLastUpdateTime $using:SessionHostConfigurationLastUpdateTime -UseAgentDownloadEndpoint $using:UseAgentDownloadEndpoint -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer SetScript: $ErrMsg", $PSItem.Exception)
                    }
                }
                TestScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    
                    try {
                        return (& "$using:ScriptPath\Script-TestSetupSessionHost.ps1" -HostPoolName $using:HostPoolName)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer TestScript: $ErrMsg", $PSItem.Exception)
                    }
                }
            }
        }
        else
        {
            "$(get-date) - rdshIsServer = false: $rdshIsServer" | out-file c:\windows\temp\rdshIsServerResult.txt -Append
            Script ExecuteRdAgentInstallClient
            {
                GetScript = {
                    return @{'Result' = ''}
                }
                SetScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    try {
                        & "$using:ScriptPath\Script-SetupSessionHost.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoTokenValue -AadJoin $using:AadJoin -AadJoinPreview $using:AadJoinPreview -MdmId $using:MdmId -SessionHostConfigurationLastUpdateTime $using:SessionHostConfigurationLastUpdateTime -UseAgentDownloadEndpoint $using:UseAgentDownloadEndpoint -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient SetScript: $ErrMsg", $PSItem.Exception)
                    }
                }
                TestScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    
                    try {
                        return (& "$using:ScriptPath\Script-TestSetupSessionHost.ps1" -HostPoolName $using:HostPoolName)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient TestScript: $ErrMsg", $PSItem.Exception)
                    }

                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIoTgYJKoZIhvcNAQcCoIIoPzCCKDsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDtHFkH+e/fzlwZ
# f2aXDwOei4KUjQSwnAsbR5BIUv4TNKCCDWowggY1MIIEHaADAgECAhMzAAAACKqz
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
# 8Qud9TGCGjowgho2AgEBMIGcMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1aWxkIFRvb2xz
# IFBDQSAyMDIwAhMzAAAACKqziRzOy0aDAAAAAAAIMA0GCWCGSAFlAwQCAQUAoIHU
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAKSmbUWmdl/049hm5plThVqiULNGo1
# Pqn4qCrYEd/9jTBoBgorBgEEAYI3AgEMMVowWKA6gDgAVwBpAG4AZABvAHcAcwAg
# AEIAdQBpAGwAZAAgAFQAbwBvAGwAcwAgAEkAbgB0AGUAcgBuAGEAbKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEADe4GELS0B7uB
# +HNbyqk50+SqIdtzkV+yhaEli0NQxMcEO5tLMZ5l03JRdMPoi5CfCU3iGkCGjdob
# Rfu/T9sIbiHOVGPy04K/e/kXJrfVKQvHWEO9CCokYa+/DEEmJ7tlLf5zU7u5BUOF
# kV2QBt9NciUU2IW3fxxCsfWm+9HiwWTuewRheapUZlKzzRCQkavPOAud8zj+wCJe
# B9ayPBhunwvwllzbHoxB9IdJas4fOw+kCoJ8ZTo3Z5k0LhPZ8BpelEZeWrfX64JG
# cdSRbmgZuqZv3QnzJMz1MpOK9u40ig2PmBnFk2ynD+UqgTSo5fqDOLog5mwFGpPh
# SrFAe94D3KGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCCF38GCSqGSIb3DQEHAqCC
# F3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEE
# ggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCA/AOYaM5iI
# yeIY5nQyeWDGsVGxgZ0bpFXpoF9L7+NNaQIGZkZEqHNWGBMyMDI0MDUyMjE5MjUx
# Ni45ODJaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046RjAwMi0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHtMIIHIDCCBQigAwIB
# AgITMwAAAfI+MtdkrHCRlAABAAAB8jANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1NThaFw0yNTAzMDUxODQ1
# NThaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hp
# ZWxkIFRTUyBFU046RjAwMi0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC85fPLFwppYgxwYxkSEeYvQBtnYJTtKKj2FKxzHx0fgV6XgIIrmCWmpKl9IOzv
# OfJ/k6iP0RnoRo5F89Ad29edzGdlWbCj1Qyx5HUHNY8yu9ElJOmdgeuNvTK4RW4w
# u9iB5/z2SeCuYqyX/v8z6Ppv29h1ttNWsSc/KPOeuhzSAXqkA265BSFT5kykxvzB
# 0LxoxS6oWoXWK6wx172NRJRYcINfXDhURvUfD70jioE92rW/OgjcOKxZkfQxLlwa
# FSrSnGs7XhMrp9TsUgmwsycTEOBdGVmf1HCD7WOaz5EEcQyIS2BpRYYwsPMbB63u
# HiJ158qNh1SJXuoL5wGDu/bZUzN+BzcLj96ixC7wJGQMBixWH9d++V8bl10RYdXD
# ZlljRAvS6iFwNzrahu4DrYb7b8M7vvwhEL0xCOvb7WFMsstscXfkdE5g+NSacphg
# FfcoftQ5qPD2PNVmrG38DmHDoYhgj9uqPLP7vnoXf7j6+LW8Von158D0Wrmk7Cum
# ucQTiHRyepEaVDnnA2GkiJoeh/r3fShL6CHgPoTB7oYU/d6JOncRioDYqqRfV2wl
# pKVO8b+VYHL8hn11JRFx6p69mL8BRtSZ6dG/GFEVE+fVmgxYfICUrpghyQlETJPI
# TEBS15IsaUuW0GvXlLSofGf2t5DAoDkuKCbC+3VdPmlYVQIDAQABo4IBSTCCAUUw
# HQYDVR0OBBYEFJVbhwAm6tAxBM5cH8Bg0+Y64oZ5MB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEB
# CwUAA4ICAQA9S6eO4HsfB00XpOgPabcN3QZeyipgilcQSDZ8g6VCv9FVHzdSq9Xp
# AsljZSKNWSClhJEz5Oo3Um/taPnobF+8CkAdkcLQhLdkShfr91kzy9vDPrOmlCA2
# FQ9jVhFaat2QM33z1p+GCP5tuvirFaUWzUWVDFOpo/O5zDpzoPYtTr0cFg3uXaRL
# T54UQ3Y4uPYXqn6wunZtUQRMiJMzxpUlvdfWGUtCvnW3eDBikDkix1XE98VcYIz2
# +5fdcvrHVeUarGXy4LRtwzmwpsCtUh7tR6whCrVYkb6FudBdWM7TVvji7pGgfjes
# gnASaD/ChLux66PGwaIaF+xLzk0bNxsAj0uhd6QdWr6TT39m/SNZ1/UXU7kzEod0
# vAY3mIn8X5A4I+9/e1nBNpURJ6YiDKQd5YVgxsuZCWv4Qwb0mXhHIe9CubfSqZjv
# Dawf2I229N3LstDJUSr1vGFB8iQ5W8ZLM5PwT8vtsKEBwHEYmwsuWmsxkimIF5BQ
# bSzg9wz1O6jdWTxGG0OUt1cXWOMJUJzyEH4WSKZHOx53qcAvD9h0U6jEF2fuBjtJ
# /QDrWbb4urvAfrvqNn9lH7gVPplqNPDIvQ8DkZ3lvbQsYqlz617e76ga7SY0w71+
# QP165CPdzUY36et2Sm4pvspEK8hllq3IYcyX0v897+X9YeecM1Pb1jCCB3EwggVZ
# oAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jv
# c29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4
# MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvX
# JHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa
# /rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AK
# OG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rbo
# YiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIck
# w+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbni
# jYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F
# 37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZ
# fD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIz
# GHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR
# /bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1
# Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUC
# AwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0O
# BBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yD
# fQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9
# /Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5
# bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvf
# am++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn
# 0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlS
# dYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0
# j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5
# JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakUR
# R6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4
# O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVn
# K+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoI
# Yn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNQMIICOAIBATCB+aGB0aSB
# zjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UE
# CxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOkYwMDItMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBri943cFLH2TfQEfB05SLI
# Cg74CKCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBCwUAAgUA6firvzAiGA8yMDI0MDUyMjE3MzcwM1oYDzIwMjQwNTIzMTcz
# NzAzWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDp+Ku/AgEAMAoCAQACAg8VAgH/
# MAcCAQACAhRGMAoCBQDp+f0/AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEB
# AAu7QSQtCUT6UGB2EZB6l1aqPHxa8ElRx81U34wVrspusJfvHe+Ol4VsAtKnc4h9
# TV18KzFFY33ilACQDae8b437qykIKc641OqGaB6z9Zn8iL07QBOzNRwiBJdp94VB
# fuFQK4HjHpKzxOB5Vun51uDVu7avZ+aowR0iaPpRevSqartPnoVRnU1tkBjSCSef
# PG31lP1zfhkMzoiCkF8E3g1uPJJawPKAOuODT4XjkPX3iERvVfiLcoAepm3UelQG
# YfdUVV7/VbM7q7Ps6Gl93DVpcatUCDM8Og3+ekxxD65Kh3MmMEYHj3xNh2WAlSKL
# LPJijjB7y0HA74I/cWVvjkwxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAfI+MtdkrHCRlAABAAAB8jANBglghkgBZQMEAgEF
# AKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEi
# BCBguUzIXH7gMuJN2NOXbbc9hxw9W7sni3lV3AIOiLzV8zCB+gYLKoZIhvcNAQkQ
# Ai8xgeowgecwgeQwgb0EIPjaPh0uMVJc04+Y4Ru5BUUbHE4suZ6nRHSUu0XXSkNE
# MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHyPjLX
# ZKxwkZQAAQAAAfIwIgQgYJV0H+kWGCvi41W9S/ZkeLPQDSc5soEJOPv1U+4JOw4w
# DQYJKoZIhvcNAQELBQAEggIANJd1E6I0wozc9awEiVt5f25uZElJjkoq/sG02Z63
# +Nnfg6xdruUL3cp6v8JBdGGlQMupcyBsogqkyNJvWJ5kPt2RMBpD4yfjezH2nONT
# ENUUqT9dPytXAIOYe+0lB48DvexCouf4ozRxrRK2uNHiClClgFhvi8rrCsrF8Me8
# trL/DMA3baNGNXRIpsrWImA+J2s8T45I91PwpjEYLZOum5fWDCOJL8oST6VHDtl6
# 9izOMqb1PJEZTXuEYRASCNb0s0Qj3wqORfepLtLmGcgSrm6uvVrlb35bSHptP7dO
# PRHlj0/gn8EIVs6yBJMEIMolPdHgXna9leESq10AKJyPf1cQWeTlf1MhDL2QSDBO
# H5LrMLDl09LmCplu45aEIunwlWv8E/9HowoYmqYzbCumXd+Oc70R1rMwKrhLiYON
# znldNAX1qxnka7FxrCpccOUAQ71M2swAEAgTcGI+Ikjfeo7oBn3g8pCVuqiKY9MN
# h/Ple1qTlf73cc7B0IIMyTq1/6o1aJLttmldjeQWaGFFn2ixwM4T3p92bu4D4R4b
# Kv68sfX1WI2RonFowotvkiQWS2X4lBKhDLuuLkpog/Dj3zvfee6mxpS80V2HZr4/
# pf9bw86bqtRmX3yJsPEXmsQHkRUAFCf3YfNAPbahLSDeievME/gVhfHthZSjhdvU
# 86c=
# SIG # End signature block
