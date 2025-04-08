<#

.SYNOPSIS
Verify a VM is setup correctly and registered to existing/new host pool.

.DESCRIPTION
This script verifies RD agent installed and the VM is registered successfully as session host to existing/new host pool.

#>
param(
    [Parameter(mandatory = $true)]
    [string]$HostPoolName
)

$ScriptPath = [system.io.path]::GetDirectoryName($PSCommandPath)

# Dot sourcing Functions.ps1 file
. (Join-Path $ScriptPath "Functions.ps1")
. (Join-Path $ScriptPath "AvdFunctions.ps1")

Write-Log -Message "Check if RD Infra registry exists"
$RegistryCheckObj = IsRDAgentRegistryValidForRegistration
if (!$RegistryCheckObj.result) {
    Write-Log -Err "RD agent registry check failed ($($RegistryCheckObj.msg))"
    return $false;
}

$SessionHostName = GetAvdSessionHostName
Write-Log -Message "SessionHost '$SessionHostName' is registered. $($SessionHost | Out-String)"
return $true;
# SIG # Begin signature block
# MIIoTgYJKoZIhvcNAQcCoIIoPzCCKDsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAG12jm1kvsQM2t
# 285BuoFPuwNGQjknUCKMGM172L+AvKCCDWowggY1MIIEHaADAgECAhMzAAAACKqz
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCOcT0C6EB672QsQjgJzsG9/mMVSnUf
# 16LU4PaLs7jS9TBoBgorBgEEAYI3AgEMMVowWKA6gDgAVwBpAG4AZABvAHcAcwAg
# AEIAdQBpAGwAZAAgAFQAbwBvAGwAcwAgAEkAbgB0AGUAcgBuAGEAbKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAPVF0sTvVrerN
# sK++8veKlOsuJsGoYYplDqmpIbHH6zNwUByxysJIWUg6tJj3fXs5HgzhvWYGxpO4
# vbCotIxeJYPO+a8UkpRcEIWWpmVhwnW+dbDjf13YyorsZmTdBci+RNcWJAECNG27
# PG8tvghCD6tPPvE49CBxYwNvZpLK4fFDV/j0oWcqq3Pl5IpMyh7L2mc9A5KgM8Rk
# BhZJsSXL4Eoh+Gk8WumbtWXYciBo/E97awEDI1BV7wjZma6gyZVA14+wJQ9bBkxr
# q+Vm8tVlkHKaipFrC2tK0+E23Og/KaQvbdYw9YDt5K4P8sA6ORTpMO52uZE6u10F
# Bok5WSm9pKGCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCCF38GCSqGSIb3DQEHAqCC
# F3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEE
# ggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCBm9CKih+6N
# RltnyWd2BV51Wl6kpB6v3pT2T6Zewzu82gIGZkZMsWM4GBMyMDI0MDUyMjE5MjUx
# Ni44NTFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046RTAwMi0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHtMIIHIDCCBQigAwIB
# AgITMwAAAe4F0wIwspqdpwABAAAB7jANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1NDRaFw0yNTAzMDUxODQ1
# NDRaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hp
# ZWxkIFRTUyBFU046RTAwMi0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC+8byl16KEia8xKS4vVL7REOOR7LzYCLXEtWgeqyOVlrzuEz+AoCa4tBGESjbH
# TXECeMOwP9TPeKaKalfTU5XSGjpJhpGx59fxMJoTYWPzzD0O2RAlyBmOBBmiLDXR
# DQJL1RtuAjvCiLulVQeiPI8V7+HhTR391TbC1beSxwXfdKJqY1onjDawqDJAmtws
# A/gmqXgHwF9fZWcwKSuXiZBTbU5fcm3bhhlRNw5d04Ld15ZWzVl/VDp/iRerGo2I
# s/0Wwn/a3eGOdHrvfwIbfk6lVqwbNQE11Oedn2uvRjKWEwerXL70OuDZ8vLzxry0
# yEdvQ8ky+Vfq8mfEXS907Y7rN/HYX6cCsC2soyXG3OwCtLA7o0/+kKJZuOrD5HUr
# Sz3kfqgDlmWy67z8ZZPjkiDC1dYW1jN77t5iSl5Wp1HKBp7JU8RiRI+vY2i1cb5X
# 2REkw3WrNW/jbofXEs9t4bgd+yU8sgKn9MtVnQ65s6QG72M/yaUZG2HMI31tm9mo
# oH29vPBO9jDMOIu0LwzUTkIWflgd/vEWfTNcPWEQj7fsWuSoVuJ3uBqwNmRSpmQD
# zSfMaIzuys0pvV1jFWqtqwwCcaY/WXsb/axkxB/zCTdHSBUJ8Tm3i4PM9skiunXY
# +cSqH58jWkpHbbLA3Ofss7e+JbMjKmTdcjmSkb5oN8qU1wIDAQABo4IBSTCCAUUw
# HQYDVR0OBBYEFBCIzT8a2dwgnr37xd+2v1/cdqYIMB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEB
# CwUAA4ICAQB3ZyAva2EKOWSVpBnYkzX8f8GZjaOs577F9o14Anh9lKy6tS34wXoP
# XEyQp1v1iI7rJzZVG7rpUznay2n9csfn3p6y7kYkHqtSugCGmTiiBkwhFfSByKPI
# 08MklgvJvKTZb673yGfpFwPjQwZeI6EPj/OAtpYkT7IUXqMki1CRMJKgeY4wURCc
# cIujdWRkoVv4J3q/87KE0qPQmAR9fqMNxjI3ZClVxA4wiM3tNVlRbF9SgpOnjVo3
# P/I5p8Jd41hNSVCx/8j3qM7aLSKtDzOEUNs+ZtjhznmZgUd7/AWHDhwBHdL57TI9
# h7niZkfOZOXncYsKxG4gryTshU6G6sAYpbqdME/+/g1uer7VGIHUtLq3W0Anm8lA
# fS9PqthskZt54JF28CHdsFq/7XVBtFlxL/KgcQylJNnia+anixUG60yUDt3FMGSJ
# I34xG9NHsz3BpqSWueGtJhQ5ZN0K8ju0vNVgF+Dv05sirPg0ftSKf9FVECp93o8o
# gF48jh8CT/B32lz1D6Truk4Ezcw7E1OhtOMf7DHgPMWf6WOdYnf+HaSJx7ZTXCJs
# W5oOkM0sLitxBpSpGcj2YjnNznCpsEPZat0h+6d7ulRaWR5RHAUyFFQ9jRa7KWaN
# GdELTs+nHSlYjYeQpK5QSXjigdKlLQPBlX+9zOoGAJhoZfrpjq4nQDCCB3EwggVZ
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
# ZCBUU1MgRVNOOkUwMDItMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCIo6bVNvflFxbUWCDQ3YYK
# y6O+k6CBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBCwUAAgUA6fizyTAiGA8yMDI0MDUyMjE4MTEyMVoYDzIwMjQwNTIzMTgx
# MTIxWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDp+LPJAgEAMAoCAQACAhNbAgH/
# MAcCAQACAhLPMAoCBQDp+gVJAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEB
# ADS3IgZIltcSh6WYicNbNOJu3Ws7YAQ8cBC2IT3tnSVxDqqEvSMgz3irae8xOWZq
# 1n1cf9QROtWpizDjngo8EfHFA4n0UQTHStml+cyji3XmF2FSlLPwNxGa8fshvheI
# 7JyQ4+AB3m97ftyjh0RjQoG3HaciwkOn9uNYDJFcDhd2cDi2UX+arwCb/dXW0oVp
# qbk6zMj77zPL94/LJ3SMreqGGm+5uDN/X7iZ41Syk2IIc+OvnASwu78vH0EG793d
# PlfzGfAxRFRFvjBAl2b4i1YCRTSN6+9nI5gDTjlqWDtasflMYSixcstyAyEFixdy
# +skBgt9dQQXM2J8+8rneLz4xggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAe4F0wIwspqdpwABAAAB7jANBglghkgBZQMEAgEF
# AKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEi
# BCDAnMs5qA2M1OrCH8wK8oJkODl1MlANqP8Z3m1tj+0IyDCB+gYLKoZIhvcNAQkQ
# Ai8xgeowgecwgeQwgb0EIE9QdxSVhfq+Vdf+DPs+5EIkBz9oCS/OQflHkVRhfjAh
# MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHuBdMC
# MLKanacAAQAAAe4wIgQgtNeFboHOEDFhc/NhXl2wFwUTNqvsvfZUmGczPeDmxWAw
# DQYJKoZIhvcNAQELBQAEggIAHQQUKfaxyIJTO5vDF+QMbgMq82yJcpd02tWTDojO
# PhVvd+hsj/axRr+UW1nOc6OXCpPdlRCTZ98UEKIoFDpFfnJwznNLyOrb5xyUf8C2
# y0E4mmN/bY0yHS0TPNsXlm9yO+EoltKC20c10ZKAUjil6lBeM/Fcn77v3Anfq92x
# 3pNl45+CrOr4h1ajQ6sMVZn3WqJb7/mjU/KeBp+N5rK/ePx9e4cvPILzuvKTnGmc
# cO/n1W6PUSCV32WG1pSKiXse7xaYdxxAFOd5RpZpt9CoR9LnLKTTgdu6oIGBrtEp
# iPhMl5SS4iCcx+O9t+oErnxq+ELqoLRjZf7O7n8ZDleDWsfaAmfHqH6QETXXPCCk
# OWLSybxYEl7weg0MMMGT/4v4y9IWjtAK+GlSjf2PwfZFdCOUR3DLO9nEld9WTAJk
# /tkPgGyrWtmN0xxxhCZEc3qDyIZLF3aL4olOnQ+5+eEGQ3ipYnKshToPvWgX/E9h
# r01D/tfO+PQ35vFXTHVast72i/gY0z6mMsYKHbCwde47Cyz7lwplcZWy+eKbw0+W
# hrIpk3htbInOJQnsXOwgng2YI/XVgdm2DfTU2sFESXfcREimIOQHvLfUrPRV/hV7
# kbGWmmFqfgmj3xbkj0E0IY2cyADGuSi97o+Rx+5s+4WPEc5yfFIXQn5bEDDJSJgt
# YVs=
# SIG # End signature block
