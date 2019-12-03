# ------------------------------------------------------------
# Copyright (c) Microsoft Corporation.  All rights reserved.
# Licensed under the MIT License (MIT). See License.txt in the repo root for license information.
# ------------------------------------------------------------

function Publish-NewServiceFabricApplication
{
    <#
    .SYNOPSIS 
    Publishes a new Service Fabric application type to Service Fabric cluster.

    .DESCRIPTION
    This script registers & creates a Service Fabric application.

    .NOTES
    Connection to service fabric cluster should be established by using 'Connect-ServiceFabricCluster' before invoking this cmdlet.
    WARNING: This script creates a new Service Fabric application in the cluster. If OverwriteExistingApplication switch is provided, it deletes any existing application in the cluster with the same name.

    .PARAMETER ApplicationPackagePath
    Path to the folder containing the Service Fabric application package OR path to the zipped service fabric applciation package.

    .PARAMETER ApplicationParameterFilePath
    Path to the application parameter file which contains Application Name and application parameters to be used for the application.    

    .PARAMETER ApplicationName
    Name of Service Fabric application to be created. If value for this parameter is provided alongwith ApplicationParameterFilePath it will override the Application name specified in ApplicationParameter  file.

    .PARAMETER Action
    Action which this script performs. Available Options are Register, Create, RegisterAndCreate. Default Action is RegisterAndCreate.

    .PARAMETER ApplicationParameter
    Hashtable of the Service Fabric application parameters to be used for the application. If value for this parameter is provided, it will be merged with application parameters
    specified in ApplicationParameter file. In case a parameter is found in application parameter file and on commandline, commandline parameter will override the one specified in application parameter file.

    .PARAMETER OverwriteBehavior
    Overwrite Behavior if an application exists in the cluster with the same name. Available Options are Never, Always, SameAppTypeAndVersion. 
    Never will not remove the existing application. This is the default behavior.
    Always will remove the existing application even if its Application type and Version is different from the application being created. 
    SameAppTypeAndVersion will remove the existing application only if its Application type and Version is same as the application being created.

    .PARAMETER SkipPackageValidation
    Switch signaling whether the package should be validated or not before deployment.

    .PARAMETER CopyPackageTimeoutSec
    Timeout in seconds for copying application package to image store. Default is 600 seconds.

    .PARAMETER CompressPackage
    Switch signaling whether the package should be compressed or not before deployment.

    .PARAMETER RegisterApplicationTypeTimeoutSec
    Timeout in seconds for registering application type. Default is 600 seconds.

    .PARAMETER UnregisterApplicationTypeTimeoutSec
    Timeout in seconds for unregistering application type. Default is 600 seconds.

    .EXAMPLE
    Publish-NewServiceFabricApplication -ApplicationPackagePath 'pkg\Debug' -ApplicationParameterFilePath 'Local.xml'

    Registers & Creates an application with AppParameter file containing name of application and values for parameters that are defined in the application manifest.

    Publish-NewServiceFabricApplication -ApplicationPackagePath 'pkg\Debug' -ApplicationName 'fabric:/Application1'

    Registers & Creates an application with the specified application name.

    #>

    [CmdletBinding(DefaultParameterSetName="ApplicationName")]  
    Param
    (
        [Parameter(Mandatory=$true,ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(Mandatory=$true,ParameterSetName="ApplicationName")]
        [String]$ApplicationPackagePath,
    
        [Parameter(Mandatory=$true,ParameterSetName="ApplicationParameterFilePath")]
        [String]$ApplicationParameterFilePath,    

        [Parameter(Mandatory=$true,ParameterSetName="ApplicationName")]
        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [String]$ApplicationName,

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [ValidateSet('Register','Create','RegisterAndCreate')]
        [String]$Action = 'RegisterAndCreate',

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [Hashtable]$ApplicationParameter,

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [ValidateSet('Never','Always','SameAppTypeAndVersion')]
        [String]$OverwriteBehavior = 'Never',

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [Switch]$SkipPackageValidation,

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [int]$CopyPackageTimeoutSec = 600,

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [Switch]$CompressPackage,

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [int]$RegisterApplicationTypeTimeoutSec = 600,

        [Parameter(ParameterSetName="ApplicationParameterFilePath")]
        [Parameter(ParameterSetName="ApplicationName")]
        [int]$UnregisterApplicationTypeTimeoutSec = 600
    )


    if (!(Test-Path $ApplicationPackagePath))
    {
        $errMsg = "$ApplicationPackagePath is not found."
        throw $errMsg
    }

    # Check if the ApplicationPackagePath points to a compressed package.
    if (Test-Path $ApplicationPackagePath -PathType Leaf)
    {
        if((Get-Item $ApplicationPackagePath).Extension -eq ".sfpkg")
        {
            $AppPkgPathToUse=[io.path]::combine($env:Temp, (Get-Item $ApplicationPackagePath).BaseName)
            Expand-ToFolder $ApplicationPackagePath $AppPkgPathToUse
        }
        else
        {
            $errMsg = "$ApplicationPackagePath is not a valid Service Fabric application package"
            throw $errMsg
        }
    }
    else
    {
        $AppPkgPathToUse = $ApplicationPackagePath
    }

    if ($PSBoundParameters.ContainsKey('ApplicationParameterFilePath') -and !(Test-Path $ApplicationParameterFilePath -PathType Leaf))
    {
        $errMsg = "$ApplicationParameterFilePath is not found."
        throw $errMsg
    }

    try
    {
        [void](Test-ServiceFabricClusterConnection)
    }
    catch
    {
        Write-Warning "Unable to verify connection to Service Fabric cluster."
        throw
    }

    # Get image store connection string
    $clusterManifestText = Get-ServiceFabricClusterManifest
    $imageStoreConnectionString = Get-ImageStoreConnectionStringFromClusterManifest ([xml] $clusterManifestText)
    if(!$SkipPackageValidation)
    {
        $packageValidationSuccess = (Test-ServiceFabricApplicationPackage $AppPkgPathToUse)
        if (!$packageValidationSuccess)
        {
           $errMsg = "Validation failed for package: " +  $ApplicationPackagePath
           throw $errMsg
        }
    }

    $ApplicationManifestPath = "$AppPkgPathToUse\ApplicationManifest.xml"

    # If ApplicationName is not specified on command line get application name from Application Parameter file.
    if(!$ApplicationName)
    {
       $ApplicationName = Get-ApplicationNameFromApplicationParameterFile $ApplicationParameterFilePath
    }

    $names = Get-NamesFromApplicationManifest -ApplicationManifestPath $ApplicationManifestPath
    if (!$names)
    {
        Write-Warning "Unable to read Application Type and Version from application manifest file."
        return
    }

    if($Action.Equals("Register") -or $Action.Equals("RegisterAndCreate"))
    {
        # Apply OverwriteBehavior if an applciation with same name already exists.
        $app = Get-ServiceFabricApplication -ApplicationName $ApplicationName
        if ($app)
        {
            $removeApp = $false
            if($OverwriteBehavior.Equals("Never"))
            {
                $errMsg = "An application with name '$ApplicationName' already exists, its Type is '$($app.ApplicationTypeName)' and Version is '$($app.ApplicationTypeVersion)'.
                You must first remove the existing application before a new application can be deployed or provide a new name for the application."
                throw $errMsg
            }

            if($OverwriteBehavior.Equals("SameAppTypeAndVersion")) 
            {
                if($app.ApplicationTypeVersion -eq $names.ApplicationTypeVersion -and $app.ApplicationTypeName -eq $names.ApplicationTypeName)
                {
                    $removeApp = $true
                }
                else
                {
                    $errMsg = "An application with name '$ApplicationName' already exists, its Type is '$($app.ApplicationTypeName)' and Version is '$($app.ApplicationTypeVersion)'.
                    You must first remove the existing application before a new application can be deployed or provide a new name for the application."
                    throw $errMsg
                }             
            }

            if($OverwriteBehavior.Equals("Always"))
            {
                $removeApp = $true
            }            

            if($removeApp)
            {
                Write-Host "An application with name '$ApplicationName' already exists in the cluster with Application Type '$($app.ApplicationTypeName)' and Version '$($app.ApplicationTypeVersion)'. Removing it."

                try
                {
                    $app | Remove-ServiceFabricApplication -Force -ForceRemove
                }
                catch [System.TimeoutException]
                {
                    # Catch operation timeout and continue with force remove replica.
                }
                catch [System.Fabric.FabricElementNotFoundException]
                {
                    if ($_.Exception.ErrorCode -eq [System.Fabric.FabricErrorCode]::ApplicationNotFound)
                    {
                        # Ignore
                    }
                    else
                    {
                        throw
                    }
                }

                foreach ($node in Get-ServiceFabricNode)
                {
                    [void](Get-ServiceFabricDeployedReplica -NodeName $node.NodeName -ApplicationName $ApplicationName | Remove-ServiceFabricReplica -NodeName $node.NodeName -ForceRemove)
                }

                if($OverwriteBehavior.Equals("Always"))
                {                    
                    # Unregsiter AppType and Version if there are no other applciations for the Type and Version. 
                    # It will unregister the existing application's type and version even if its different from the application being created,
                    if((Get-ServiceFabricApplication | Where-Object {$_.ApplicationTypeVersion -eq $($app.ApplicationTypeVersion) -and $_.ApplicationTypeName -eq $($app.ApplicationTypeName)}).Count -eq 0)
                    {
                        Unregister-ServiceFabricApplicationType -ApplicationTypeName $($app.ApplicationTypeName) -ApplicationTypeVersion $($app.ApplicationTypeVersion) -Force -TimeoutSec $UnregisterApplicationTypeTimeoutSec
                    }
                }
            }
        }        

        $reg = Get-ServiceFabricApplicationType -ApplicationTypeName $names.ApplicationTypeName | Where-Object  { $_.ApplicationTypeVersion -eq $names.ApplicationTypeVersion }
        if ($reg)
        {
            Write-Host 'Application Type '$names.ApplicationTypeName' and Version '$names.ApplicationTypeVersion' was already registered with Cluster, unregistering it...'
            $reg | Unregister-ServiceFabricApplicationType -Force -TimeoutSec $UnregisterApplicationTypeTimeoutSec
            if(!$?)
            {
                throw "Unregistering of existing Application Type was unsuccessful."
            }
        }

        Write-Host 'Copying application to image store...'

        $applicationPackagePathInImageStore = $names.ApplicationTypeName
        Copy-ServiceFabricApplicationPackage -ApplicationPackagePath $AppPkgPathToUse -ImageStoreConnectionString $imageStoreConnectionString -ApplicationPackagePathInImageStore $applicationPackagePathInImageStore -TimeOutSec $CopyPackageTimeoutSec -CompressPackage:$CompressPackage
        if(!$?)
        {
            throw "Copying of application package to image store failed. Cannot continue with registering the application."
        }

        Write-Host 'Registering application type...'
        Register-ServiceFabricApplicationType -ApplicationPathInImageStore $applicationPackagePathInImageStore -Async
        if(!$?)
        {
            throw "Registration of application type failed."
        }

        # Wait for app registration to finish.
        $ready = $false
        $retryTimeInterval = 2
        $retryCount = $RegisterApplicationTypeTimeoutSec / $retryTimeInterval
        $prevStatusDetail = ""

        do
        {
            $appType = Get-ServiceFabricApplicationType -ApplicationTypeName $names.ApplicationTypeName -ApplicationTypeVersion $names.ApplicationTypeVersion

            if($appType.Status -eq "Available")
            {
                $ready = $true
            }
            elseif($appType.Status -eq "Failed")
            {
                if($appType.StatusDetails -ne "")
                {
                    Write-Host $appType.StatusDetails
                }

                throw "Registration of application type failed."
            }
            else
            {
                if($appType.StatusDetails -ne "")
                {
                    if($prevStatusDetail -ne $appType.StatusDetails)
                    {
                        Write-Host $appType.StatusDetails
                    }

                    $prevStatusDetail = $appType.StatusDetails
                }

                Start-Sleep -Seconds $retryTimeInterval
                $retryCount--
            }
        } while (!$ready -and $retryCount -gt 0)

        if(!$ready)
        {
            throw "Registration of application package is not completed in specified timeout of $RegisterApplicationTypeTimeoutSec seconds. Please consider increasing this timout by passing a value for RegisterApplicationTypeTimeoutSec parameter."
        }
        else
        {
            Write-Host "Application package is registered."
        }

        Write-Host 'Removing application package from image store...'
        Remove-ServiceFabricApplicationPackage -ApplicationPackagePathInImageStore $applicationPackagePathInImageStore -ImageStoreConnectionString $imageStoreConnectionString
    }

    if($Action.Equals("Create") -or $Action.Equals("RegisterAndCreate"))
    {
        Write-Host 'Creating application...'

        # If application parameters file is specified read values from and merge it with parameters passed on Commandline
        if ($PSBoundParameters.ContainsKey('ApplicationParameterFilePath'))
        {
           $appParamsFromFile = Get-ApplicationParametersFromApplicationParameterFile $ApplicationParameterFilePath        
           if(!$ApplicationParameter)
            {
                $ApplicationParameter = $appParamsFromFile
            }
            else
            {
                $ApplicationParameter = Merge-Hashtables -HashTableOld $appParamsFromFile -HashTableNew $ApplicationParameter
            }    
        }
    
        New-ServiceFabricApplication -ApplicationName $ApplicationName -ApplicationTypeName $names.ApplicationTypeName -ApplicationTypeVersion $names.ApplicationTypeVersion -ApplicationParameter $ApplicationParameter
        if(!$?)
        {
            throw "Creation of application failed."
        }

        Write-Host 'Create application succeeded.'
    }
}
# SIG # Begin signature block
# MIIkWwYJKoZIhvcNAQcCoIIkTDCCJEgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAA/JdgomJqGEog
# k/gbHoitPuH+HibhtmXczWWCOevCyqCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIWMDCCFiwCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgjdpPpAED
# hDJBLJ89pufWhsqCQirrSiHEuoQl0B/heCUwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAfs1cm6RaBz+ZIWXbqDObw13CMg0DrCAkI9rDXr94W
# WVCR52aC9CedhJb5/2AMJjoDBz86JAEdjlBx7Q3LkvnFH3q9oQSHiXlwazuz86Y4
# /OS5ADs+9nCjyvzSzdG5gss89W5Gn1+1Kf7mZKx1t+ASjfaZviR+lxFeAfcMTRw9
# olnY5Ep/kxEbO+SGkO/maWJ/454CgtCeyHvNGN3TiAR91+Gp66BPMVc3Z1HBbdY9
# dUc2mxfYkCQP0aPP6BJfi2VFYMSMOrYYsLQtXD+WmZpXp99IUR38jkSlWtfFl46p
# LBn5baDFl2uxlIYkz3vRicj5Ap6yGThogGg/YICKmhrQoYITujCCE7YGCisGAQQB
# gjcDAwExghOmMIITogYJKoZIhvcNAQcCoIITkzCCE48CAQMxDzANBglghkgBZQME
# AgEFADCCAVgGCyqGSIb3DQEJEAEEoIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIGQ1Z3X26uuMTLt3eyOZEJt6H65zCGE3WzLCgEZh
# m0DBAgZdNh7eNtQYEzIwMTkwNzIzMTgxOTE5Ljg5OFowBwIBAYACAfSggdSkgdEw
# gc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsT
# IE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFs
# ZXMgVFNTIEVTTjozMUM1LTMwQkEtN0M5MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCDyIwggT1MIID3aADAgECAhMzAAAAzabbOK+9LUEA
# AAAAAADNMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMB4XDTE4MDgyMzIwMjYyNloXDTE5MTEyMzIwMjYyNlowgc4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
# cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoz
# MUM1LTMwQkEtN0M5MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vy
# dmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALIajsUUtFeCVgqu
# 0PezmWTxSr1SBomjYc5Xeo1FuiVJKzZSkluQOg+OV2oZFN9lAEfgg/IMs0DgKzcC
# uOOmSj5op694z7bo8knqBC5VHeoMYkqjtkeeYvoRnCr+ZyQZp4KTZmsisyQQgkqy
# AWcjSt4P3a+jZ4DBTXzi6p2sUCiVyU0lQM0kqrBahXMI+aEHdVoGciFCVH6O4iTJ
# 9NuQqykOtOXbyJlbsUtrlIwkvfpVHQWxZ01vW9l3UG3CMI+EgLdItETnTskAktJP
# EPUvs98XfjVxgVRquXbhQpXKi4ECFZCzbym7H1axvPtoHnLGc/+avXtPcXvcQIQ5
# yBbbsdsCAwEAAaOCARswggEXMB0GA1UdDgQWBBS4HfRi4voKkipXIDEE2dC+yfIC
# DjAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEug
# SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
# AQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Rp
# bVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQBCQgAqKI99wPi5IOcedjU8nrBa
# QgXQYfjwLEM97A8I7l5Ai6IFywbXku39yQFrON0nBCrbSTULrLy/CuNJU7SGvyr6
# fPp3UFagLxeLKZNApqgZR8YE9mTO9jLSqmPuCGjrJHR4oiNGvqmPIrFstX2l0gcd
# +xFG1nvyQt+BmlHTAwLr7w+HaGTstsQT+ckpaplkOTV0dXfRYo+iRLXb5aKbCimg
# qih0G2TK90Z1DcdbNhAXD1reTve1N5TUrTnyBeVpeaEmGn8uwRRMDpdJMWkYfn5W
# JOBZPDJxcAe53rytSKheRqHvhMNM7b/fzlJ1NlrbR9ad+7vwIGw5yH2q1B+dMIIG
# cTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1
# WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9p
# lGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEw
# WbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeG
# MoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJ
# UGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw
# 2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0C
# AwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ
# 80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8E
# BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2U
# kFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
# b20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmww
# WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYD
# VR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYI
# KwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0
# AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9
# naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtR
# gkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzy
# mXlKkVIArzgPF/UveYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCf
# Mkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3D
# nKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs
# 9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110
# mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL
# 2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffI
# rE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxE
# PJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc
# 1bN+NR4Iuto229Nfj950iEkSoYIDsDCCApgCAQEwgf6hgdSkgdEwgc4xCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29m
# dCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjozMUM1LTMwQkEtN0M5MTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQCA9et0fWDvdjapvx/uKopPPxqnI6CB
# 3jCB26SB2DCB1TELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEp
# MCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJzAlBgNV
# BAsTHm5DaXBoZXIgTlRTIEVTTjo0REU5LTBDNUUtM0UwOTErMCkGA1UEAxMiTWlj
# cm9zb2Z0IFRpbWUgU291cmNlIE1hc3RlciBDbG9jazANBgkqhkiG9w0BAQUFAAIF
# AODhzTkwIhgPMjAxOTA3MjQwMjE1MjFaGA8yMDE5MDcyNTAyMTUyMVowdzA9Bgor
# BgEEAYRZCgQBMS8wLTAKAgUA4OHNOQIBADAKAgEAAgI8WgIB/zAHAgEAAgIZvjAK
# AgUA4OMeuQIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMBoAowCAIB
# AAIDFuNgoQowCAIBAAIDB6EgMA0GCSqGSIb3DQEBBQUAA4IBAQAjRzBOAAdOLWYe
# YBhYR3b8bqAmHN+14dNIFJfpnbtEWSkRZKvrKFuCiLXVfFfcx/HuotaHtHiOdYg4
# 9taDAawzzZbgstA/Uj6iNVB93bLneH6iQiP7bHdp5Y4ZEf5hwAIU2wMAQTZ18XHm
# jj90WHKImI4XGXs2KwVf63mDKH53EFU8oFDAcpeSaD/Ou8Uo2FRkADfXpQZXrBxd
# dxBZecMweXWArxIdOzahiyU0Eop9AXp4l216F2YyF9s5GiTMr90xEkbCrLwFI/5S
# dpY3KJLxoUoa/XhcYqXXMpFuPHFc8txYG8lhDeYz1CdNBvxFp9UFCgiKfxDXxI3P
# pQ++Bd12MYIC9TCCAvECAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAADNpts4r70tQQAAAAAAAM0wDQYJYIZIAWUDBAIBBQCgggEyMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQggMD2XltfRgf8
# TcYGDqY3RmQEfUGxCZy6T1onCwpjWwIwgeIGCyqGSIb3DQEJEAIMMYHSMIHPMIHM
# MIGxBBSA9et0fWDvdjapvx/uKopPPxqnIzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAAAzabbOK+9LUEAAAAAAADNMBYEFA/GJT/HHy6z
# 5ScD3VYZasXw2mDcMA0GCSqGSIb3DQEBCwUABIIBAJ0lwy2HpSV3caaS6LnuinTo
# E4uyIkKdYkgpKbfdvRvYwZMljxQm5WJkNEq1kEzlX6X6rLl1TqREWQSidaAZePRo
# SYB3HOJxkqqGBpdglWVFsvqwnaYxmnim++nJMMfLvk6b4pa/lkJSoSTLxUex3tka
# cIYLKUREbrBNQe2/Js+lswLGDGXXzQ+Mz3udH0zfWlfux31p9Fia4rGuhTfbj/zn
# TWC4gUswL32CaDDojcKC/56ecbfNhaZtdzz+Vd5FXOeaDIqp9tVtenswU/j3d9m8
# 1eiYCX3OkKeW0LMOexxURgaWoasm2YHlZPSSbYNVxeLmHEoMMdMmnl7IFEinyOM=
# SIG # End signature block
