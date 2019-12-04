# ------------------------------------------------------------
# Copyright (c) Microsoft Corporation.  All rights reserved.
# Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
# ------------------------------------------------------------

##
## TODO: Refactor the certificate generation and installation in smaller
## functions and move them (including enums) to ClusterSetupUtilities.psm1 module.
##
param
(
    [Parameter(Mandatory=$True, ParameterSetName = "Install")]
    [switch] $Install,
    
    [Parameter(Mandatory=$True, ParameterSetName = "Clean")]
    [switch] $Clean,

    [Parameter(Mandatory=$False)]
    [string] $CertSubjectName = "CN=ServiceFabricDevClusterCert"
)

function Cleanup-Cert([string] $CertSubjectName)
{
    Write-Host "Cleaning existing certificates..."

    $cerLocations = @("cert:\LocalMachine\My", "cert:\LocalMachine\root", "cert:\LocalMachine\CA", "cert:\CurrentUser\My")

    foreach($cerLoc in $cerLocations)
    {
        Get-ChildItem -Path $cerLoc | ? { $_.Subject -like "*$CertSubjectName*" } | Remove-Item
    }

    Write-Host "Certificates removed."
}

$warningMessage = @"
This will install certificate with '$CertSubjectName' in following stores:
    
    # LocalMachine\My
    # LocalMachine\root &
    # CurrentUser\My

The CleanCluster.ps1 will clean these certificates or you can clean them up using script 'CertSetup.ps1 -Clean -CertSubjectName $CertSubjectName'.

"@

$X509KeyUsageFlags = @{
DIGITAL_SIGNATURE = 0x80
KEY_ENCIPHERMENT = 0x20
DATA_ENCIPHERMENT = 0x10
}

$X509KeySpec = @{
NONE = 0
KEYEXCHANGE = 1
SIGNATURE = 2
}

$X509PrivateKeyExportFlags = @{
EXPORT_NONE = 0
EXPORT_FLAG = 0x1
PLAINTEXT_EXPORT_FLAG = 0x2
ARCHIVING_FLAG = 0x4
PLAINTEXT_ARCHIVING_FLAG = 0x8
}

$X509CertificateEnrollmentContext = @{
USER = 0x1
MACHINE = 0x2
ADMINISTRATOR_FORCE_MACHINE = 0x3
}

$EncodingType = @{
STRING_BASE64HEADER = 0
STRING_BASE64 = 0x1
STRING_BINARY = 0x2
STRING_BASE64REQUESTHEADER = 0x3
STRING_HEX = 0x4
STRING_HEXASCII = 0x5
STRING_BASE64_ANY = 0x6
STRING_ANY = 0x7
STRING_HEX_ANY = 0x8
STRING_BASE64X509CRLHEADER = 0x9
STRING_HEXADDR = 0xa
STRING_HEXASCIIADDR = 0xb
STRING_HEXRAW = 0xc
STRING_NOCRLF = 0x40000000
STRING_NOCR = 0x80000000
}

$InstallResponseRestrictionFlags = @{
ALLOW_NONE = 0x00000000
ALLOW_NO_OUTSTANDING_REQUEST = 0x00000001
ALLOW_UNTRUSTED_CERTIFICATE = 0x00000002
ALLOW_UNTRUSTED_ROOT = 0x00000004
}

if($Install)
{
    #cleanup previous installs of the certificate
    Cleanup-Cert -CertSubjectName $CertSubjectName
    
    Write-Host "Installing new certificates..."
    Write-Warning $warningMessage
    
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $name = new-object -com "X509Enrollment.CX500DistinguishedName"
    $name.Encode($CertSubjectName, 0x00100000)

    $key = new-object -com "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.ExportPolicy = $X509PrivateKeyExportFlags.PLAINTEXT_EXPORT_FLAG
    $key.KeySpec = $X509KeySpec.KEYEXCHANGE
    $key.Length = 1024
    $sd = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0xd01f01ff;;;NS)(A;;0xd01f01ff;;;" + $identity.User.Value + ")"
    $key.SecurityDescriptor = $sd
    $key.MachineContext = $TRUE
    $key.Create()

    #set server auth keyspec
    $serverauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = new-object -com "X509Enrollment.CObjectIds.1"

    $ekuoids.add($serverauthoid)

    $clientauthoid = new-object -com "X509Enrollment.CObjectId.1"
    $clientauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.2")

    $ekuoids.add($clientauthoid)

    $ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $keyUsageExt = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
    $keyUsageExt.InitializeEncode($X509KeyUsageFlags.KEY_ENCIPHERMENT -bor $X509KeyUsageFlags.DIGITAL_SIGNATURE)
 
    # Subject alternative names
    $x509AlternativeNames = new-object -com "X509Enrollment.CX509ExtensionAlternativeNames"
    $alternativeNames =  new-object -com "X509Enrollment.CAlternativeNames"
    $alternativeName = new-object -com "X509Enrollment.CAlternativeName"
    # Dns Alternative Name
    $alternativeName.InitializeFromString(3, $CertSubjectName)
    $alternativeNames.Add($alternativeName)
    $x509AlternativeNames.InitializeEncode($alternativeNames)
 
    $certTemplateName = ""
    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey($X509CertificateEnrollmentContext.MACHINE, $key, $certTemplateName)
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $notbefore = get-date
    $ts = new-timespan -Days 2
    $cert.NotBefore = $notbefore.Subtract($ts)
    $cert.NotAfter = $cert.NotBefore.AddYears(1)
    $cert.X509Extensions.Add($ekuext)
    $cert.X509Extensions.Add($keyUsageExt)
    $cert.X509Extensions.Add($x509AlternativeNames)
    $cert.Encode()

    #install certificate in LocalMachine My store
    $enrollment = new-object -com "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)

    $certdata = $enrollment.CreateRequest($EncodingType.STRING_BASE64HEADER)
    
    $password = ""
    $enrollment.InstallResponse($InstallResponseRestrictionFlags.ALLOW_UNTRUSTED_CERTIFICATE, $certdata, $EncodingType.STRING_BASE64HEADER, $password)

    if (!$?)
    {
        Write-Warning "Failed to create certificates required for cluster"
        return
    }

    $srcStoreScope = "LocalMachine"
    $srcStoreName = "My"

    $srcStore = New-Object System.Security.Cryptography.X509Certificates.X509Store $srcStoreName, $srcStoreScope
    $srcStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

    $cert = $srcStore.certificates -match "$CertSubjectName"
    Write-Output "$CertSubjectName has been successfully install ->"$cert.Thumbprint

    $dstStoreScope = "LocalMachine"
    $dstStoreName = "root"

    #copy cert to root store so chain build succeeds
    $dstStore = New-Object System.Security.Cryptography.X509Certificates.X509Store $dstStoreName, $dstStoreScope
    $dstStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    foreach($c in $cert)
    {
        $dstStore.Add($c)
    }

    $dstStore.Close()

    $dstStoreScope = "CurrentUser"
    $dstStoreName = "My"

    $dstStore = New-Object System.Security.Cryptography.X509Certificates.X509Store $dstStoreName, $dstStoreScope
    $dstStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    foreach($c in $cert)
    {
        $dstStore.Add($c)
    }
    $srcStore.Close()
    $dstStore.Close()
}

if($Clean)
{
    Cleanup-Cert -CertSubjectName $CertSubjectName
}
# SIG # Begin signature block
# MIIkcgYJKoZIhvcNAQcCoIIkYzCCJF8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGpzFgtkUmO6NZ
# gQoc/sFlY42MkN6RwnHH2QV8eo6TbqCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
# j0Bxow5BAAAAAAFRMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ2WhcNMjAwNTAyMjEzNzQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCVWsaGaUcdNB7xVcNmdfZiVBhYFGcn8KMqxgNIvOZWNH9JYQLuhHhmJ5RWISy1
# oey3zTuxqLbkHAdmbeU8NFMo49Pv71MgIS9IG/EtqwOH7upan+lIq6NOcw5fO6Os
# +12R0Q28MzGn+3y7F2mKDnopVu0sEufy453gxz16M8bAw4+QXuv7+fR9WzRJ2CpU
# 62wQKYiFQMfew6Vh5fuPoXloN3k6+Qlz7zgcT4YRmxzx7jMVpP/uvK6sZcBxQ3Wg
# B/WkyXHgxaY19IAzLq2QiPiX2YryiR5EsYBq35BP7U15DlZtpSs2wIYTkkDBxhPJ
# IDJgowZu5GyhHdqrst3OjkSRAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUV4Iarkq57esagu6FUBb270Zijc8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU0MTM1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAWg+A
# rS4Anq7KrogslIQnoMHSXUPr/RqOIhJX+32ObuY3MFvdlRElbSsSJxrRy/OCCZdS
# se+f2AqQ+F/2aYwBDmUQbeMB8n0pYLZnOPifqe78RBH2fVZsvXxyfizbHubWWoUf
# NW/FJlZlLXwJmF3BoL8E2p09K3hagwz/otcKtQ1+Q4+DaOYXWleqJrJUsnHs9UiL
# crVF0leL/Q1V5bshob2OTlZq0qzSdrMDLWdhyrUOxnZ+ojZ7UdTY4VnCuogbZ9Zs
# 9syJbg7ZUS9SVgYkowRsWv5jV4lbqTD+tG4FzhOwcRQwdb6A8zp2Nnd+s7VdCuYF
# sGgI41ucD8oxVfcAMjF9YX5N2s4mltkqnUe3/htVrnxKKDAwSYliaux2L7gKw+bD
# 1kEZ/5ozLRnJ3jjDkomTrPctokY/KaZ1qub0NUnmOKH+3xUK/plWJK8BOQYuU7gK
# YH7Yy9WSKNlP7pKj6i417+3Na/frInjnBkKRCJ/eYTvBH+s5guezpfQWtU4bNo/j
# 8Qw2vpTQ9w7flhH78Rmwd319+YTmhv7TcxDbWlyteaj4RK2wk3pY1oSz2JPE5PNu
# Nmd9Gmf6oePZgy7Ii9JLLq8SnULV7b+IP0UXRY9q+GdRjM2AEX6msZvvPCIoG0aY
# HQu9wZsKEK2jqvWi8/xdeeeSI9FN6K1w4oVQM4Mwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIWRzCCFkMCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgVy9Edrhe
# Agk4qRIC55yyfru0yD/fAcIDIGiAaPls0qIwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAg1wsSZjUIyOEqzplLlqPAe+zTCKdxn06yJw3oLP3C
# +x827VP9xewcxpUzfPthB/8udr0aTPfm3W8k+kmq7WhcX7yxt0M63i51C9LlW7lY
# jcrLGNCTzvDFA0cfiVsbWLMUUWNAwLF3SihxrbK7Je0gxN83TeLvnyZmHP69q5qz
# vOIaWpzlUZF7nooszkvUCzpGW+I4N8ZkllH3OKEHfkOYhAnn+CZRBIjVlBPW202/
# 3QLFnhD3ucRezVaMqoVKRYmtYjAaZBsrluxq6uVpsS6Pc23IdsEvwVnUS+CkzlNw
# f03skcKJUeOeIEuT+i/ekxwP/IeRYPaFAisnGTHmGZwtoYIT0TCCE80GCisGAQQB
# gjcDAwExghO9MIITuQYJKoZIhvcNAQcCoIITqjCCE6YCAQMxDzANBglghkgBZQME
# AgEFADCCAVcGCyqGSIb3DQEJEAEEoIIBRgSCAUIwggE+AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIIh41vw60Z7liq2uoIb1IhKEXorudEo3Gtna4nyc
# DsNlAgZdNcHwIB8YEjIwMTkwNzIzMTgxODA2LjcyWjAHAgEBgAIB9KCB1KSB0TCB
# zjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMg
# TWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjk4RkQtQzYxRS1FNjQxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIPIjCCBPUwggPdoAMCAQICEzMAAADLX3jLIw6Ul8MA
# AAAAAMswDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMTgwODIzMjAyNjI0WhcNMTkxMTIzMjAyNjI0WjCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjk4
# RkQtQzYxRS1FNjQxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxXjIHe/wHUFwHG00
# Sj9UAsoaeLMDVYIQhTbYMKnLLzfw7RWVbsPcpSiZk8hTeezHczFpBelqLQ6JWz4M
# +4ep2gq2y5gJozF4MeGh0KA9Z09P003SGeCcLTtHacMHY2G+1EGmvhXfrv3U+qLc
# KywoN0uMGs5BSGoSfxLRU/nGV0NA98wimpEVB0/pS3h29oj8y9rl7zodtrAnF0Yq
# tN0enss5p7dgdfbmSFuG41q2qnd0O7cOjrEMTUEhrYa5QZlrigdU3BYhaTdJnjFm
# VqtPd4CLvXbJbJ5OuMa/npHKN7zIOIG137VQKfru3RPBClNr5rZk8/a/wfJDFB6B
# z71OFQIDAQABo4IBGzCCARcwHQYDVR0OBBYEFCjk8ub2ydFNrm7I2yqWvzHD+9l2
# MB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGlt
# U3RhUENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAIv0YYWDBWJsyxSUl8PpJQNscrEv
# 2k3plgyD5o5MTwDIKH2gPody6KdSOSPpp9BTrdO+BVFYTFgkvOtAHKwCHYaBsaQo
# g+11XrJBAyUnFyVelHjy3WNLVW8FfQqSxHkGr/j/R7nz6Ne9RpTYlxRBXDeUef0j
# 9i1Al64C+c18sQ3EkoTcDsU6M4DD58Qfj04YrUgFH3KFdL6voeyUW4Ut+MrsNTz3
# 4K7XMCD0lMIKuqVZLJ1YCkBiH8AIic40scen05l2KULjbMaMHxGj/TtiowCM+Ert
# l7XaVZOGJkgWpzl9lPEKLcvZPylAj3X83G7gKekjMtdTBJdTGQil9I2wrs4wggZx
# MIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
# Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVa
# Fw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIB
# IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mU
# a3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZ
# sTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4Yy
# hB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQ
# YrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDa
# TgaRtogINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQID
# AQABo4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDz
# Q3t8RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQ
# W9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
# bS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBa
# BggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNV
# HSABAf8EgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggr
# BgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQA
# ZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2d
# o6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GC
# RBL7uVOMzPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZ
# eUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8y
# Sif9Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOc
# o6I8+n99lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz3
# 9L9+Y1klD3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSY
# Ighh2rBQHm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvY
# grRyzR30uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98is
# TtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8
# l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzV
# s341Hgi62jbb01+P3nSISRKhggOwMIICmAIBATCB/qGB1KSB0TCBzjELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0
# IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# Ojk4RkQtQzYxRS1FNjQxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiUKAQEwCQYFKw4DAhoFAAMVALmjk9JAdtG3HxWjBFGXrjgr25ohoIHe
# MIHbpIHYMIHVMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkw
# JwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEnMCUGA1UE
# CxMebkNpcGhlciBOVFMgRVNOOjRERTktMEM1RS0zRTA5MSswKQYDVQQDEyJNaWNy
# b3NvZnQgVGltZSBTb3VyY2UgTWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA
# 4OG6ujAiGA8yMDE5MDcyNDAwNTYyNloYDzIwMTkwNzI1MDA1NjI2WjB3MD0GCisG
# AQQBhFkKBAExLzAtMAoCBQDg4bq6AgEAMAoCAQACAgI5AgH/MAcCAQACAhcCMAoC
# BQDg4ww6AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwGgCjAIAgEA
# AgMW42ChCjAIAgEAAgMHoSAwDQYJKoZIhvcNAQEFBQADggEBAGydeqVbE4MAisco
# TVwPSEbSJ7L11/edetrSSnyJRnuRkAryJ4lTwOjTSQEE2KMxRVm3/t97YGsI4Iga
# WvDKS9IMUSsIpSppql6ejV/K39y0alKGxeALO9pIuZNAyr6N8BzsuPfGqyZ/HAlh
# oPeXgsvNZmnLYiU/t/M8o5HMvsK51qwRwaAjVukPdru3XpuuTHkB/TnZfV++Z2GL
# 4mzIyxOIoM0Cw6+LopykY3N27ZztSdrUrvfBocneyLuQTjU0Iyqym/FDjnhTrtpw
# DpMFJzjQg9MEsb58K4sBn7BdOhg/FuGZb1ETtUXwJbtUu46b2fs0wR2WbxMENckJ
# E3GRWpQxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAMtfeMsjDpSXwwAAAAAAyzANBglghkgBZQMEAgEFAKCCAUowGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCBXXA+7DPaAJK4g
# FptqsfKpTfCCUQKo4gou7z97+7DIgDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQw
# gb0EIDYnIaqpYKde63PQpL1LfC4X9p9L0y7uFEdeqmDdwR1kMIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAADLX3jLIw6Ul8MAAAAAAMsw
# IgQgoAC0tuLkyLSwcpur1Hyzm6psiq9QbpgUR9chB3/sB4YwDQYJKoZIhvcNAQEL
# BQAEggEAEHmsgnJQrl4EJKPcaDIbWA7LB1KJWZX0bMm2Sm5oiLoJN8KPUNmNy0mZ
# BYPzvtycooNwojbc4XiS6+d0gzhgSF+vQTQZXDuZFzBX9SuDXosP4GGiJixQbrpv
# M0xxylAc4GjHY3zWTtmWFjQPIZhRmyFUYHtQVi5WTZezjZ5121QQWEHVweDPTM+y
# NPz0RAjK0hmgqgRIjwI09gmN1HLU3TfsQ6/joFS8r6q5nGTDkPGhKk7VsIYB1ZJO
# PjnwdsdQI1w2r/rLlKRfL+Z+1DGkd+7ma+IWr8JCk0rQPDD4SIViLI3pcnhoA7OL
# Npd1z0LzvxLROX3IGY5IoR7F57Q7iA==
# SIG # End signature block
