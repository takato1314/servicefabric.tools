function EnsureAdminPrivileges([String]$mesageOnError)
{
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = new-object Security.Principal.WindowsPrincipal $identity
    if (!($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)))
    {
        Write-Error $mesageOnError
        throw
    }
}

function GetFabricDataRootFromRegistry
{
    return (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric').FabricDataRoot
}

function GetFabricLogRootFromRegistry
{
    return (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric').FabricLogRoot
}

function AddWindowsFabricAcl([String]$folderPath)
{
    $currAcl = Get-Acl "$folderPath"

    $accessRuleWinFabAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule("ServiceFabricAdministrators", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")

    $currAcl.SetAccessRule($accessRuleWinFabAdmin)

    Set-Acl "$folderPath" $currAcl
}

function TestPathRobust([string]$pathToTest)
{
    [int]$retryCount = 0;
    
    do
    {
        $testErrors = @()
        $isPathExists = (Test-Path -Path $pathToTest -ErrorAction SilentlyContinue -ErrorVariable testErrors)
            
        if ($testErrors.Count -eq 0)
        { 
            return $isPathExists
        }

        Start-Sleep -Seconds 1

        $retryCount++
        if($retryCount -eq 40)
        {
            $errorString = $testErrors -join ' '
            Write-Error $errorString
            throw
        }
    }
    while($True)
}

function GetClusterScriptRootDirectory
{ 
    $sdkInstallPath = (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK').FabricSDKInstallPath
    $clusterScriptDir = Join-Path -Path $sdkInstallPath -ChildPath "ClusterSetup"
    
    return $clusterScriptDir
}

function RemoveFolder([String]$folderPath)
{
    $pathExists = TestPathRobust($folderPath)
    
    if ($pathExists)
    {
        cmd /c rmdir /S /Q $folderPath > $null

        # Even after Remove-Item returns, sometimes the folders are still being 
        # deleted. Sleep for few seconds before we check for existence of path.
        Start-Sleep -Seconds 5

        return (!(TestPathRobust($folderPath)))
    }

    return $true
}

function GetCertificateSetupScriptFilePath
{
    $scriptDir = (GetClusterScriptRootDirectory)
    $certScript = Join-Path -Path $scriptDir -ChildPath "\Secure\CertSetup.ps1"

    return $certScript
}

function InstallCertificates
{
    $certScript = (GetCertificateSetupScriptFilePath)

    Write-Host "Installing certificates for secure cluster setup..."
    invoke-expression "& '$certScript' -Install"
    
    if (!$?)
    {
        Write-Error "Certificate Installation failed."
        throw
    }
}

function CleanExistingCluster([bool]$deleteFolders = $True)
{
    Write-Host "Removing cluster configuration..."
    Remove-ServiceFabricNodeConfiguration -Force > $null    

    # Wait for fabric processes to exit.
    Get-Process Fabric -ErrorAction Ignore | Foreach-Object { $_.WaitForExit() }
    Get-Process FabricGateway -ErrorAction Ignore | Foreach-Object { $_.WaitForExit() }
    Get-Process FabricHost -ErrorAction Ignore | Foreach-Object { $_.WaitForExit() }

    if(IsMeshClusterDeployed)
    {
        #Uninstall the SFVolume driver
        FabricSetupOperations "uninstallsfvolumedriver"

        Write-Output "Deleting Docker network and removing firewall rule..."
        DeleteNetworkAndRemoveFirewallRule 
    }

    # Clear out the reg key indicating the local cluster node count.
    Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name LocalClusterNodeCount -Value ""
    # Clear out the reg key indicating the isMeshCluster.
    Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name IsMeshCluster -Value ""
    
    $certScript = (GetCertificateSetupScriptFilePath)
    invoke-expression "& '$certScript' -Clean"

    Write-Host "Stopping all logman sessions..."
    logman stop FabricAppInfoTraces > $null
    logman stop FabricCounters > $null
    logman stop FabricLeaseLayerTraces > $null
    logman stop FabricSFBDMiniportTraces > $null
    logman stop FabricQueryTraces > $null
    logman stop FabricTraces > $null

    if($deleteFolders)
    {
        CleanClusterDataLogFolders
    }
}

function CleanClusterDataLogFolders
{
    $logFolder = GetFabricLogRootFromRegistry
    $dataFolder = GetFabricDataRootFromRegistry

    Write-Output "Cleaning log and data folder..."
    RemoveFolder $logFolder  > $null
    RemoveFolder $dataFolder > $null
}

function CleanExistingClusterShallow
{
    # Stop FabricHostSvc
    PerformServiceOperationWithWaitforStatus "FabricHostSvc" "Stop-Service" "Stopped" 10 5

    # Remove Service Fabric Node Configuration
    try
    {
        Remove-ServiceFabricNodeConfiguration -Force > $null
    }
    catch [System.Exception]
    {
        Write-Warning $_.Exception.ToString()
        Write-Warning "Remove-ServiceFabricNodeConfiguration throws exceptions"
    }

    if(IsMeshClusterDeployed)
    {
        #Uninstall the SFVolume driver
        FabricSetupOperations "uninstallsfvolumedriver"

        Write-Output "Deleting Docker network and removing firewall rule..."
        DeleteNetworkAndRemoveFirewallRule 
    }

    # Stop all logman sessions
    logman stop FabricAppInfoTraces > $null
    logman stop FabricCounters > $null
    logman stop FabricLeaseLayerTraces > $null
    logman stop FabricSFBDMiniportTraces > $null
    logman stop FabricQueryTraces > $null
    logman stop FabricTraces > $null
}

function FabricSetupOperations([string]$operationType)
{
    $runtimeInstallPath = (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric').FabricCodePath
    & "$runtimeInstallPath\FabricSetup.exe" /operation:$operationType
}

function ConstructManifestFileTemplate([string]$jsonTemplate)
{
    $runtimeInstallPath = (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric').FabricCodePath
    $deploymentmangager= Join-Path -Path $runtimeInstallPath -ChildPath "Microsoft.ServiceFabric.DeploymentManager.dll"

    [Reflection.Assembly]::LoadFrom($deploymentmangager) > $null
    $manifestFileTemplate = [Microsoft.ServiceFabric.DeploymentManager.Common.StandaloneUtility]::GetClusterManifestFromJsonConfig($jsonTemplate, "", "")

    return $manifestFileTemplate
}

function SelectJsonFileTemplate([bool]$isSecure,
                                [bool]$createOneNodeCluster,
                                [bool]$createMeshCluster = $false)
{
    $scriptDir = (GetClusterScriptRootDirectory)

    $jsonFileTemplate = $ScriptDir + "\NonSecure"

    if($isSecure)
    {
        $jsonFileTemplate = $ScriptDir + "\Secure"
    }

    # If Mesh SDK is installed, use the manifests specific to the mesh cluster 
    if($createMeshCluster -eq $true)
    {
        $jsonFileTemplate = $jsonFileTemplate + "_Mesh"
    }

    if($createOneNodeCluster)
    {
        $jsonFileTemplate = $jsonFileTemplate + "\OneNode"
    }
    else
    {
        $jsonFileTemplate = $jsonFileTemplate + "\FiveNode"
    }

    $jsonFileTemplate = $jsonFileTemplate + "\ClusterManifestTemplate.json"

    if (!(TestPathRobust($jsonFileTemplate)))
    {
        Write-Error "Json template file not found at '$jsonFileTemplate'. Please make sure Service Fabric SDK installed correctly."
        throw
    }

    return $jsonFileTemplate
}

function InstantiateJsonFromTemplate([string]$jsonFileTemplate,
                                     [string]$clusterDataRoot,
                                     [string]$clusterLogRoot,
                                     [bool]$configureFirewall)
{

    $configJson = Get-Content $jsonFileTemplate -Raw | ConvertFrom-Json
    $setupSetting = $configJson.properties.fabricSettings | where {$_.Name -eq "Setup"}
    if($setupSetting -eq $null){
        $setupSetting = New-Object PSObject -Property @{
                name="Setup"
                parameters = @()
        }
        $configJson.properties.fabricSettings += $setupSetting
    }
    
    $dataroot = $setupSetting.parameters | where {$_.Name -eq "FabricDataRoot"}
    if($dataroot -eq $null) {
        $parameter = New-Object PSObject -Property @{
            name="FabricDataRoot"
            value=$clusterDataRoot
        }
        $setupSetting.parameters += $parameter
    } else {
        $dataroot.value = $clusterDataRoot
    }
    
    $logroot = $setupSetting.parameters | where {$_.Name -eq "FabricLogRoot"}
    if($logroot -eq $null) {
        $parameter = New-Object PSObject -Property @{
            name="FabricLogRoot"
            value=$clusterLogRoot
        }
        $setupSetting.parameters += $parameter
    } else {
        $logroot.value = $clusterLogRoot
    }

    $skipFirewallConfigurationSetting = $setupSetting.parameters | where {$_.Name -eq "SkipFirewallConfiguration"}
    $skipFirewallConfiguration = "true"

    if($configureFirewall)
    {
        $skipFirewallConfiguration = "false"
    }

    if($skipFirewallConfigurationSetting -eq $null) {
        $parameter = New-Object PSObject -Property @{
            name="SkipFirewallConfiguration"
            value=$skipFirewallConfiguration
        }
        $setupSetting.parameters += $parameter
    } else {
        $skipFirewallConfigurationSetting.value = $skipFirewallConfiguration
    }
    
    $parameter = New-Object PSObject -Property @{
            name="IsDevCluster"
            value="true"
    }
    $setupSetting.parameters += $parameter

    $jsonObject = ConvertTo-Json $configJson -Depth 10
    $temporaryConfigPath = [System.IO.Path]::GetTempFileName() + ".json"
    $jsonObject > $temporaryConfigPath

    Write-Host "The generated json path is $temporaryConfigPath"

    return $temporaryConfigPath
}

function IsLocalClusterSetup
{
    try
    {
        if($null -eq (Get-ServiceFabricNodeConfiguration -WarningAction SilentlyContinue))
        {
            return $false;
        }

        return $true;
        
    }
    catch [System.Exception]
    {
        return $false;
    }
}

function IsDirectoryEmpty([string]$dirPath)
{
    if((TestPathRobust($dirPath)))
    {
        $dirInfo = Get-ChildItem -Path $dirPath | Measure-Object

        if($dirInfo.Count -eq 0)
        {
            return $True
        }

        return $False
    }

    return $True;
}

function EnsureDirectoryCleaned([string]$dirPath)
{
    if (!(RemoveFolder($dirPath)))
    {
        Write-Error "Cannot clean up $dirPath fully as references are likely being held to items in it. Please remove those and retry."
        Write-Warning "Hints: Is some other process holding on to references?"
        throw
    }
}

function GetDefaultClusterRootRelativePath([string]$rootName)
{
    if($rootName -ieq "data")
    {
        return "SfDevCluster\Data"
    }
    
    if($rootName -ieq "log")
    {
        return "SfDevCluster\Log"
    }

    if([System.String]::IsNullOrWhiteSpace($rootName))
    {
        throw
    }
}

function ComputeClusterRoot([string]$clusterRoot, [string]$rootName)
{
    if([System.String]::IsNullOrWhiteSpace($clusterRoot))
    {
        $clusterRoot = Join-Path -Path $env:SystemDrive -ChildPath (GetDefaultClusterRootRelativePath($rootName))
    }
    elseif(![System.IO.Path]::IsPathRooted($clusterRoot))
    {
        Write-Error "Invalid path provided for cluster $rootName root: $clusterRoot. Please provide a local full path."
        throw
    }
    elseif(($clusterRoot.Length -eq 2) -or ($clusterRoot.Length -eq 3))
    {
        # The path supplied by user is drive itself (e.g. C: or C:\)
        $clusterRoot = Join-Path -Path $clusterRoot -ChildPath (GetDefaultClusterRootRelativePath($rootName))
    }

    return $clusterRoot
}

function GetClusterRootValueFromJson([string]$jsonFileTemplate, [string]$name){
    $configJson = Get-Content $jsonFileTemplate -Raw | ConvertFrom-Json
    $setupSetting = $configJson.properties.fabricSettings | where {$_.Name -eq "Setup"}

    if(($setupSetting -eq $null) -or ($setupSetting.parameters -eq $null)){
        return $null
    }

    $clusteroot = $setupSetting.parameters | where {$_.Name -eq $name}
    if($clusteroot -eq $null){
        return $null
    }

    return  [System.Environment]::ExpandEnvironmentVariables($clusteroot.value)
}

function SetupDataAndLogRoot([string]$clusterDataRoot, [string]$clusterLogRoot, [string] $jsonFileTemplate, [bool]$isAuto = $False)
{
    if([System.String]::IsNullOrWhiteSpace($clusterDataRoot)){
        $clusterDataRoot = GetClusterRootValueFromJson -jsonFileTemplate $jsonFileTemplate -name "FabricDataRoot"
    }

    if([System.String]::IsNullOrWhiteSpace($clusterLogRoot)){
        $clusterLogRoot = GetClusterRootValueFromJson -jsonFileTemplate $jsonFileTemplate -name "FabricLogRoot"
    }    

    $clusterDataRoot = ComputeClusterRoot -clusterRoot $clusterDataRoot -rootName "data"
    $clusterLogRoot = ComputeClusterRoot -clusterRoot $clusterLogRoot -rootName "log"

    Write-Host ""
    Write-Host "Using Cluster Data Root: $clusterDataRoot" -ForegroundColor Green
    Write-Host "Using Cluster Log Root: $clusterLogRoot" -ForegroundColor Green
    Write-Host ""

    if(!$isAuto)
    {
        if(!(IsDirectoryEmpty -dirPath $clusterDataRoot))
        {
            Write-Host ""
            Write-Warning "The cluster data root ($clusterDataRoot) is not empty. All files and subfolders under it will be deleted."
            $response = Read-Host -Prompt "Do you want to continue [Y/N]?"
            if($response -ine "Y") { return @($False) }
        }

        if(!(IsDirectoryEmpty -dirPath $clusterLogRoot))
        {
            Write-Host ""
            Write-Warning "The cluster log root ($clusterLogRoot) is not empty. All files and subfolders under it will be deleted."
            $response = Read-Host -Prompt "Do you want to continue [Y/N]?"
            if($response -ine "Y") { return @($False) }
        }
    }

    EnsureDirectoryCleaned $clusterDataRoot
    EnsureDirectoryCleaned $clusterLogRoot
    
    return @($clusterDataRoot, $clusterLogRoot)
}

function SetupImageStore([string]$clusterDataRoot, [bool]$useImageStoreService)
{    
    $ImageStoreConnectionString = "fabric:ImageStore";
    
    if(!$useImageStoreService)
    {    
        $ImageStoreShare = Join-Path -Path $clusterDataRoot -ChildPath "ImageStoreShare"

        New-Item "$ImageStoreShare" -type directory -force > $null
        AddWindowsFabricAcl $ImageStoreShare
    
       $ImageStoreConnectionString = "file:" + $ImageStoreShare
    }

    return $ImageStoreConnectionString
}

function GetMachineName([bool]$useMachineName)
{
    $machineName = "localhost";

    if ($useMachineName)
    {
        $machineName = [System.Net.Dns]::GetHostEntry((Get-WmiObject Win32_ComputerSystem).DNSHostName).HostName;
    }

    return $machineName;
}

function FindAndReplace([string]$filePath, [string]$toReplace, [string]$newString)
{
    (Get-Content $filePath) | ForEach-Object {$_ -replace $toReplace, $newString } | Set-Content $filePath
}

function IsLocalClusterRunning
{
    try
    {
        $fabricService = Get-Service -Name "FabricHostSvc"
        
        if ($fabricService.Status -ne "Running")
        {
            return $false;
        } 
        
        return $true;
        
    }
    catch [System.Exception]
    {
        return $false;
    }
}

function DockerNetworkCommandFailed( [bool]$warningOnFail )
{
    Write-Warning "Unable to communicate with Docker. Validate the following"
    Write-Warning "    Docker is installed on the machine"
    Write-Warning "    Docker service is running"
    Write-Warning "    Docker is configured to run Windows containers"
    Write-Warning "    Open a command prompt and make sure the following command succeeds"
    Write-Warning "        docker network create -d=nat --subnet=`"$NetworkSubnet`" --gateway=`"$NetworkGateway`" $NetworkName"

    $message = "Unable to communicate with Docker. Visit FAQ at https://aka.ms/sfmesh for details"

    if ( -not $warningOnFail )
    {
        Write-Error $message
        throw
    }
    else 
    {
        Write-Warning $message
    }
}

function EnsureDockerIsRunningAndCheckVersion(
    [int] $operationMaxRetryCount = 10,
    [int] $operationRetryInterval = 10)
{
    # Check if docker service is present
    Get-service -Name docker -ErrorAction SilentlyContinue
    if(!$? )
    {
        Write-Error "Docker service not installed/configured to run Windows Containers. Visit FAQ at https://aka.ms/sfmesh for details"
        throw
    }

    # Run a docker command, if it fails Restart docker service.
    docker version > $null
    if(!$? )
    {
        Write-Output "Stopping docker service"
        PerformServiceOperationWithWaitforStatus "docker" "Stop-Service" "Stopped" $operationMaxRetryCount $operationRetryInterval "Unable to restart docker service, Ensure its running before setting up cluster. Visit FAQ at https://aka.ms/sfmesh for details"

        Write-Output "Starting docker service"
        PerformServiceOperationWithWaitforStatus "docker" "Start-Service" "Running" $operationMaxRetryCount $operationRetryInterval "Unable to restart docker service, Ensure its running before setting up cluster. Visit FAQ at https://aka.ms/sfmesh for details"

        # Wait for docker service to be in a state to process commands
        ExecuteDockerCommand -dockercommandParameters "network ls" -retryCommand $true -warningOnFail $true -dockerOperationMaxRetryCount $operationMaxRetryCount -dockerOperationRetryInterval $operationRetryInterval
    }

    # Run the command again and  check if docker is configured to run windows containers
    $versionContent = ExecuteDockerCommand -dockercommandParameters "version" -retryCommand $false
    if( $versionContent -match "linux")
    {
        Write-Error "Docker configured to run Linux containers. Configure it to run Windows Containers. Visit FAQ at https://aka.ms/sfmesh for details"
        throw
    }
}

function ExecuteDockerCommand(
    [string] $dockercommandParameters,
    [string] $successStringMatchOnError = "",
    [bool] $warningOnFail = $false,
    [bool] $retryCommand = $true,
    [int] $dockerOperationMaxRetryCount = 10,
    [int] $dockerOperationRetryInterval = 10)
{
    [int]$dockerOperationRetryCount = 0
    $dockerOperationSucceeded = $false
    $dockerOperationContent = ""

    $tempErrorFile = [System.IO.Path]::GetTempFileName()

    #Write-Host "Executing 'docker $dockercommandParameters'"
    while($dockerOperationRetryCount -lt $dockerOperationMaxRetryCount -and $dockerOperationSucceeded -eq $false)
    {
        $dockerOperationContent = docker $dockercommandParameters.Split(" ") 2> $tempErrorFile
        if( $? )
        {
            $dockerOperationSucceeded = $true
            break
        }
        if( -not $? -and -not [string]::IsNullOrEmpty($successStringMatchOnError) )
        {
            (Get-Content $tempErrorFile) -match $successStringMatchOnError
            if ( $? )
            {
                $dockerOperationSucceeded = $true
                break;
            }
        }

        if( -not $retryCommand )
        {
            break
        }

        Start-Sleep -s $dockerOperationRetryInterval
        $dockerOperationRetryCount += 1
    }

    if( -not $dockerOperationSucceeded )
    {
        DockerNetworkCommandFailed $warningOnFail
    }

    return $dockerOperationContent
}

function ExecuteDockerNetworkCommand(
    [string] $dockercommandParameters,
    [string] $successStringMatchOnError = "",
    [bool] $warningOnFail = $false,
    [bool] $retryCommand = $true)
{
    ExecuteDockerCommand -dockercommandParameters "network $dockercommandParameters" `
        -successStringMatchOnError $successStringMatchOnError `
        -warningOnFail $warningOnFail `
        -retryCommand $retryCommand
}

function PerformServiceOperationWithWaitforStatus(
    [string] $serviceName,
    [string] $operation,
    [string] $intendedState,
    [int] $serviceStateMaxRetryCount = 20,
    [int] $serviceStateRetryInterval = 5,
    [string] $failureMsg = "")
{
    Write-Host "Performing" $operation "on:" $serviceName ". This may take a few minutes..."

    & $operation $serviceName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue > $null
    # Check if IntendedServiceState is achieved
    [int]$retryCount = 0
    while($retryCount++ -le $serviceStateMaxRetryCount)
    {
        $serviceState = Get-Service -Name $serviceName
        if ($serviceState.Status -ne $intendedState)
        {
            Start-Sleep -s $serviceStateRetryInterval
        }
        else
        {
            return;
        }
    }

    if($failureMsg -eq "")
    {
        $errorStr = [string]::Format( "Could not perform the operation:{0} on the service:{1}.", $operation, $serviceName)
        Write-Error $errorStr
    }
    else
    {
        Write-Error $failureMsg
    }
    throw
}

function CreateNetworkAndAddFirewallRule(
    [string] $jsonFileTemplate)
{
    # unconditionally delete the firewall rule
    Remove-NetFirewallRule -Name "SF Container to host" -ErrorAction Ignore

    # check if docker is configured to run windows containers
    EnsureDockerIsRunningAndCheckVersion

    # get network configuration information from template file
    $configJson = Get-Content $jsonFileTemplate -Raw | ConvertFrom-Json
    $hostingSetting = $configJson.properties.fabricSettings | Where-Object {$_.Name -eq "Hosting"}
    if( $hostingSetting -eq $null )
    {
        Write-Error "Hosting section has to be specified in ClusterManifestTemplate.json"
        throw
    }

    $localNatIpProviderNetworkName = $hostingSetting.parameters | Where-Object {$_.Name -eq "LocalNatIpProviderNetworkName"}
    if( $localNatIpProviderNetworkName.value -eq $null )
    {
        Write-Error "LocalNatIpProviderNetworkName has to be specified in ClusterManifestTemplate.json under Hosting."
        throw
    }
    else 
    {
        $NetworkName = $localNatIpProviderNetworkName.value
        if( $NetworkName -eq $null )
        {
            Write-Error "LocalNatIpProviderNetworkName in ClusterManifestTemplate.json cannot be empty"
            throw
        }

        Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name LocalNatIpProviderNetworkName -Value $NetworkName
    }

    $localNatIpProviderNetworkRange = $hostingSetting.parameters | Where-Object {$_.Name -eq "LocalNatIpProviderNetworkRange"}
    if( $localNatIpProviderNetworkRange.value -eq $null ) 
    {
        Write-Error "LocalNatIpProviderNetworkRange has to be specified in ClusterManifestTemplate.json under Hosting."
        throw
    }
    else 
    {
        $NetworkSubnet = $localNatIpProviderNetworkRange.value
        if ( $NetworkSubnet -match '^(([0-9]{1,3}\.){3})[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$' )
        {
            $val = $Matches[1] + "1"
        }
        else
        {
            Write-Error "LocalNatIpProviderNetworkRange specified is not a valid subnet range. Please enter a valid CIDR format subnet."
            throw
        }
        $NetworkGateway = $val
    }

    # unconditionally try to delete the network
    $ignore = ExecuteDockerNetworkCommand -dockercommandParameters "rm $NetworkName" -successStringMatchOnError "No such network:"

    # try to create the network
    $ignore = ExecuteDockerNetworkCommand -dockercommandParameters "create -d=nat --subnet=`"$NetworkSubnet`" --gateway=`"$NetworkGateway`" $NetworkName"

    # inspect to check if the network was created
    $inspectContent = ExecuteDockerNetworkCommand -dockercommandParameters "inspect $NetworkName"

    # some additional checks to see if create succeeded
    $inspectSubnet = ($inspectContent | Convertfrom-Json)[0].IPAM.Config.Subnet
    $inspectGatewayIP = ($inspectContent | Convertfrom-Json)[0].IPAM.Config.Gateway
    if( $inspectSubnet -ne $NetworkSubnet -or $inspectGatewayIP -ne $NetworkGateway)
    {
        DockerNetworkCommandFailed $false
    }

    New-NetFirewallRule -Name "SF Container to host" -DisplayName "SF Container to host" -LocalAddress $NetworkGateway -RemoteAddress $NetworkSubnet > $null
}

function DeleteNetworkAndRemoveFirewallRule
{
    # unconditionally delete the firewall rule
    Remove-NetFirewallRule -Name "SF Container to host" -ErrorAction Ignore

    $NetworkName = (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK').LocalNatIpProviderNetworkName
    if( $NetworkName -eq $null  -or $NetworkName -eq "" )
    {
        return
    }

    EnsureDockerIsRunningAndCheckVersion

    # unconditionally try to delete the network
    $ignore = ExecuteDockerNetworkCommand -dockercommandParameters "rm $NetworkName" -successStringMatchOnError "No such network:" -warningOnFail $true

    # Clear out the reg key indicating the LocalNatIpProviderNetworkName.
    Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name LocalNatIpProviderNetworkName -Value ""
} 

function PrepareClusterManifest([string]$manifestFileTemplate,
                                [string]$imageStoreConnectionString,
                                [string]$machineName,
                                [bool]$isSecure = $False,
                                [bool]$isMeshCluster = $False)
{
    $manifestFile = Join-Path -Path $env:TEMP -ChildPath "$env:computername-Server-ScaleMin.xml"

    Copy-Item $manifestFileTemplate $manifestFile -Force

    FindAndReplace -filePath $manifestFile -toReplace "ComputerFullName" -newString $machineName
    FindAndReplace -filePath $manifestFile -toReplace "ImageStoreConnectionStringPlaceHolder" -newString $imageStoreConnectionString

    if ($isSecure -or $isMeshCluster)
    {
        $srcStoreScope = "LocalMachine"
        $srcStoreName = "My"

        $srcStore = New-Object System.Security.Cryptography.X509Certificates.X509Store $srcStoreName, $srcStoreScope
        $srcStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

        $cert = $srcStore.certificates -match "CN=ServiceFabricDevClusterCert"

        if($isSecure)
        {
            # Replace cluster cert thumbprint.
            FindAndReplace -filePath $manifestFile -toReplace "ServiceFabricDevClusterCertParameter" -newString $cert.Thumbprint.ToString()
        }

        # Replace EncryptionCertificateThumbprint used by SecretService, this certificate is needed both for secured and unsecured clusters.
        FindAndReplace -filePath $manifestFile -toReplace "EncryptionCertificateThumbprintParameter" -newString $cert.Thumbprint.ToString()
        $srcStore.Close()
    }

    Test-ServiceFabricClusterManifest -ClusterManifestPath "$manifestFile" > $null
    if (!$?)
    {
        Write-Error "Could not validate cluster manifest '$manifestFile'"
        throw
    }

    return $manifestFile
}

function DeployNodeConfiguration([string]$clusterDataRoot, 
                                 [string]$clusterLogRoot, 
                                 [bool]$isSecure = $False,
                                 [bool]$useMachineName = $True,
                                 [bool]$createOneNodeCluster = $False,
                                 [bool]$configureFirewall = $False,
                                 [bool]$createMeshCluster = $False,
                                 [bool]$useImageStoreService = $False)
{
    $jsonFileTemplate = SelectJsonFileTemplate -isSecure $isSecure -createOneNodeCluster $createOneNodeCluster -createMeshCluster $createMeshCluster
    $jsonTemplate = InstantiateJsonFromTemplate -jsonFileTemplate $jsonFileTemplate -clusterDataRoot $clusterDataRoot -clusterLogRoot $clusterLogRoot $configureFirewall
    $manifestFileTemplate = ConstructManifestFileTemplate -jsonTemplate $jsonTemplate

    if($createMeshCluster -eq $true)
    {
        #Install the SFVolume driver
        FabricSetupOperations "installsfvolumedriver"

        Write-Output "Creating Docker network and adding firewall rule..."
        CreateNetworkAndAddFirewallRule -jsonFileTemplate $jsonFileTemplate
    }

    # Use Image Store Service when configuring firewall.
    $imageStoreConnectionString = SetupImageStore -clusterDataRoot $clusterDataRoot -useImageStoreService $useImageStoreService
    $machineName = GetMachineName -useMachineName $useMachineName

    $manifestFile = PrepareClusterManifest $manifestFileTemplate $imageStoreConnectionString $machineName $isSecure $createMeshCluster

    # Stop Fabric Host Service (if running just in case)
    PerformServiceOperationWithWaitforStatus "FabricHostSvc" "Stop-Service" "Stopped" 10 5

    New-ServiceFabricNodeConfiguration -ClusterManifest "$manifestFile" -FabricDataRoot "$clusterDataRoot" -FabricLogRoot "$clusterLogRoot" -RunFabricHostServiceAsManual
    if (!$?) 
    { 
        Write-Error "Could not create Node configuration for '$manifestFile'"
        throw
    }

    if($createOneNodeCluster)
    {
        Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name LocalClusterNodeCount -Value 1
        if($createMeshCluster -eq $false)
        {
            Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name IsMeshCluster -Value "false"
        }
        else
        {
            Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name IsMeshCluster -Value "true"
        }
    }
    else
    {
        Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name LocalClusterNodeCount -Value 5
        if($createMeshCluster -eq $false)
        {
            Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name IsMeshCluster -Value "false"
        }
        else
        {
            Set-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK' -Name IsMeshCluster -Value "true"
        }
    }

    # Saves Connection Parameters in dataRoot for REST based powershell to consume.
    SaveConnectionParameters -dataRoot $clusterDataRoot -isSecure $isSecure -useMachineName $useMachineName
}

function StartLocalCluster
{
    # Start Service Fabric on this Node
    PerformServiceOperationWithWaitforStatus "FabricHostSvc" "Start-Service" "Running" 60 10
}

function GetConnectionParameters([bool]$isSecure = $False, [bool]$useMachineName = $False)
{
    [HashTable]$connParams = @{}
    
    $machineName = GetMachineName -useMachineName $useMachineName
    $connectionEndpoint = [string]::Concat($machineName, ":19000")

    $connParams.Add("ConnectionEndpoint", $connectionEndpoint)

    if ($isSecure)
    {
        $connParams.Add("X509Credential", $True)
        $connParams.Add("ServerCommonName", "ServiceFabricDevClusterCert")
        $connParams.Add("FindType", 'FindBySubjectName')
        $connParams.Add("FindValue", 'CN=ServiceFabricDevClusterCert')
        $connParams.Add("StoreLocation", 'LocalMachine')
        $connParams.Add("StoreName", "MY")
    }

    return $connParams
}

function SaveConnectionParameters([string] $dataRoot, [bool]$isSecure = $False, [bool]$useMachineName = $False)
{
    # Saves Connection Parameters in dataRoot for REST based powershell to consume.
    $connectInfoFile = $dataRoot + "\ServiceFabricLocalClusterConnectionParams.json"
    $httpConnectionEndpoint = "http://" + $machineName + ":19080"

    if ($isSecure)
    {
        $httpConnectionEndpoint = "https://" + $machineName + ":19080"
    }

    $connParams = GetConnectionParameters -isSecure $isSecure -useMachineName $useMachineName
    $connParams.Add("HttpConnectionEndpoint", $httpConnectionEndpoint)
    $connParams | ConvertTo-Json -Depth 10 | Out-File $connectInfoFile
}

function TryConnectToCluster([HashTable]$connParams, [int]$waitTime)
{
    [int]$connRetryInterval = 10
    [int]$maxExpConnTime = $waitTime
    [int]$timeSpentConn = 0

    $connParams.Add("TimeoutSec", $connRetryInterval)
    $connParams.Add("WarningAction", 'SilentlyContinue')

    $IsConnSuccesfull = $False

    Write-Host ""
    Write-Host "Waiting for Service Fabric Cluster to be ready. This may take a few minutes..."

    do
    {
        try
        {
            [void](Connect-ServiceFabricCluster @connParams)
        
            #Test the connection
            $testWarnings = @()
            $IsConnSuccesfull = (Test-ServiceFabricClusterConnection -TimeoutSec 5 -WarningAction SilentlyContinue -WarningVariable testWarnings)
            
            if (($IsConnSuccesfull -eq $True) -and ($testWarnings.Count -eq 0)) 
            { 
                Write-Host "Local Cluster ready status: 100% completed."
                return
            }
        }
        catch [System.Exception]
        {
            # Retry
        }

        if($timeSpentConn -ge $maxExpConnTime)
        {
            Write-Warning "Service Fabric Cluster is taking longer than expected to connect."
            return
        }

        Start-Sleep -s $connRetryInterval

        # Print progress and retry
        $timeSpentConn += $connRetryInterval
        $progress = [int]($timeSpentConn * 100 / $maxExpConnTime)
        Write-Host "Local Cluster ready status: $progress% completed."
    }
    while($True)
}

function CheckNamingServiceReady([HashTable]$connParams, [int]$waitTime)
{
    CheckServiceReady $connParams "fabric:/System/NamingService" $waitTime
}

function CheckServiceReady([HashTable]$connParams, [string]$serviceName, [int]$waitTime)
{
    [int]$RetryInterval = 10
    [int]$maxExpTime = $waitTime
    [int]$timeSpent = 0

    Write-Host ""
    Write-Host "Waiting for $serviceName to be ready. This may take a few minutes..."

    [void](Connect-ServiceFabricCluster @connParams)

    do
    {
        try
        {            
            $nsPartitions = Get-ServiceFabricPartition -ServiceName $serviceName
            $isReady = $true
    
            foreach ($partition in $nsPartitions)
            {
                if(!$partition.PartitionStatus.Equals([System.Fabric.Query.ServicePartitionStatus]::Ready))
                {
                    $isReady = $false
                    break
                }
            }

            if($isReady)
            {
                Write-Host "$serviceName is ready now..."
                Write-Host ""
                return;
            }
        }
        catch [System.Exception]
        {
            # Retry
        }

        if($timeSpent -ge $maxExpTime)
        {
            Write-Warning "$serviceName is taking longer than expected to be ready..."
            return
        }
        
        Start-Sleep -s $RetryInterval
        
        # Print progress and retry
        $timeSpent += $RetryInterval
        $progress = [int]($timeSpent * 100 / $maxExpTime)
        Write-Host "$serviceName ready status: $progress% completed."
    }
    while($true)
}

function CleanTicketFiles
{
    $clusterDataRoot = GetFabricDataRootFromRegistry
    $tktFileDirRelPath = "Fabric\Work"
    
    $firstLevelDirs = Get-ChildItem -Path $clusterDataRoot -Directory 

    ForEach($dir in $firstLevelDirs)
    {
        $ticketFileDir = Join-Path -Path $dir.FullName -ChildPath $tktFileDirRelPath
    
        if(Test-Path($ticketFileDir))
        {
            Get-ChildItem -Path $ticketFileDir -File -Filter *.tkt | 
            ForEach ($_) { Remove-Item $_.FullName -ErrorAction SilentlyContinue }
        }
    }
}

function LaunchLocalClusterManager
{
    Write-Output "Launching Service Fabric Local Cluster Manager..."
    Write-Output "You can use Service Fabric Local Cluster Manager (system tray application) to manage your local dev cluster."
    Start-Process "ServiceFabricLocalClusterManager.exe"
}

function DeployAddonService ([HashTable]$connParams, [string]$appName, [string]$nuPkgName, [int]$waitTime, [HashTable]$appParams)
{
    $version = (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric').FabricVersion

    # if add on service not present in the cluster
    if(!(IsApplicationDeployed $appName))
    {
        Write-Host "Deploying Addon Service:$appName in the cluster..."

        $tempAppDir = $env:temp + "\$appName"
        $tempAppPackage = $tempAppDir + "\$appName"

        Remove-Item $tempAppDir -Recurse -ErrorAction Ignore
        New-Item -ItemType directory -Path $tempAppDir
        $srcNugetPath = (Get-ChildItem -Path ((Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric').FabricBinRoot + "\AddonServices") | where-object {$_.Name -match $nuPkgName }).FullName

        #extract nuget at $tempAppDir location
        Add-Type -AssemblyName System.IO.Compression.FileSystem;
        [System.IO.Compression.ZipFile]::ExtractToDirectory($srcNugetPath,$tempAppDir);

        # deploy service from temp location
        Copy-ServiceFabricApplicationPackage -ApplicationPackagePath $tempAppPackage -ShowProgress -CompressPackage
        Register-ServiceFabricApplicationType $appName
        $appType = $appName+"Type"
        New-ServiceFabricApplication fabric:/$appName $appType $version -ApplicationParameter $appParams

        # wait for service ready
        CheckServiceReady $connParams "fabric:/$appName/Service" $waitTime

        Remove-Item -Path $tempAppDir -Recurse -Force
    }
    else
    {
        Write-Host "Addon Service:$appName already deployed in the cluster..."
    }
}

function DeployAddonServices ([HashTable]$connParams, [int]$waitTime, [bool]$oneNodeCluster)
{
    # is mesh SDK installed ?
    if(IsMeshSDKInstalled)
    {
        [void](Connect-ServiceFabricCluster @connParams)

        # App parameters:
        $InstanceCount = 1

        $ListenPort = 19100
        $appParams = @{"InstanceCount" = "$InstanceCount"; "ListenPort" = "$ListenPort" }
        DeployAddonService $connParams "AzureFilesVolumePlugin" "Microsoft.ServiceFabric.AzureFiles.VolumePlugin" $waitTime $appParams

        $ListenPort = 19101
        $appParams = @{"InstanceCount" = "$InstanceCount"; "ListenPort" = "$ListenPort" }
        DeployAddonService $connParams "ServiceFabricVolumeDriver" "Microsoft.ServiceFabric.VolumeDriver" $waitTime $appParams
    }
}

function IsMeshSDKInstalled
{
    $retVal = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Service Fabric SDK').FabricMeshSDKVersion

    if($retVal -ne $null)
    {
        return $true
    }
    else
    {
        return $false
    }
}

function IsMeshClusterDeployed
{
    $keyValue = (Get-ItemProperty 'HKLM:\Software\Microsoft\Service Fabric SDK').IsMeshCluster
    if($keyValue -match "true")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function IsApplicationDeployed([string]$appName)
{
    $retVal = Get-ServiceFabricApplication -ApplicationName fabric:/$appName
    if($retVal -ne $null)
    {
        return $true
    }
    return $false
}

# SIG # Begin signature block
# MIIkWgYJKoZIhvcNAQcCoIIkSzCCJEcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCh1E5xAND01hMQ
# 0OBwqkkp9yD355k7PURIazm0kqX0gaCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIWLzCCFisCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgwBS02/FJ
# Y9tZn2Jfa0HphH+hbOowkzhB0+iWVk3hfYMwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCN84YXIvbNgmUBpkYFbA7QKkAILqKf67kr9nhVS50J
# D5/0c2YfSMdTabx6H98JgZvsb3gGi7pmdGXrLs9M13dFggvQH/VsFWnJg/V8SsMU
# tUojceaFBSyZ/u8V5tv5PKTCDuh0PFOG926MPJE+kHL4syzOVNsfdLpFL/p7mA8W
# mho1yEfjqUC0ukHV0oz0M5rrW6xBXbxqLRLCQfDPbV0f2JTxeYCVLlfNo2njxZZ+
# plu3EIA3EajoQzsu0EZnEODDn9ASHVsoHGD7huEZF0+c0uLgr2ffuaOPmgtl2CHr
# PxTUh3UL3nuPm1qiqqIjip1EGSSpD6LKGMGbwNZ5OliooYITuTCCE7UGCisGAQQB
# gjcDAwExghOlMIIToQYJKoZIhvcNAQcCoIITkjCCE44CAQMxDzANBglghkgBZQME
# AgEFADCCAVcGCyqGSIb3DQEJEAEEoIIBRgSCAUIwggE+AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIAflWnIRyPYoLlimrCVHUcYktM3OFYjCdGBXdvsB
# qJXSAgZdNh7eNsAYEjIwMTkwNzIzMTgxOTE3LjA1WjAHAgEBgAIB9KCB1KSB0TCB
# zjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMg
# TWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOjMxQzUtMzBCQS03QzkxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIPIjCCBPUwggPdoAMCAQICEzMAAADNpts4r70tQQAA
# AAAAAM0wDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMTgwODIzMjAyNjI2WhcNMTkxMTIzMjAyNjI2WjCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMx
# QzUtMzBCQS03QzkxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAshqOxRS0V4JWCq7Q
# 97OZZPFKvVIGiaNhzld6jUW6JUkrNlKSW5A6D45XahkU32UAR+CD8gyzQOArNwK4
# 46ZKPminr3jPtujySeoELlUd6gxiSqO2R55i+hGcKv5nJBmngpNmayKzJBCCSrIB
# ZyNK3g/dr6NngMFNfOLqnaxQKJXJTSVAzSSqsFqFcwj5oQd1WgZyIUJUfo7iJMn0
# 25CrKQ605dvImVuxS2uUjCS9+lUdBbFnTW9b2XdQbcIwj4SAt0i0ROdOyQCS0k8Q
# 9S+z3xd+NXGBVGq5duFClcqLgQIVkLNvKbsfVrG8+2gecsZz/5q9e09xe9xAhDnI
# Ftux2wIDAQABo4IBGzCCARcwHQYDVR0OBBYEFLgd9GLi+gqSKlcgMQTZ0L7J8gIO
# MB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGlt
# U3RhUENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYI
# KwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAEJCACooj33A+Lkg5x52NTyesFpC
# BdBh+PAsQz3sDwjuXkCLogXLBteS7f3JAWs43ScEKttJNQusvL8K40lTtIa/Kvp8
# +ndQVqAvF4spk0CmqBlHxgT2ZM72MtKqY+4IaOskdHiiI0a+qY8isWy1faXSBx37
# EUbWe/JC34GaUdMDAuvvD4doZOy2xBP5ySlqmWQ5NXR1d9Fij6JEtdvlopsKKaCq
# KHQbZMr3RnUNx1s2EBcPWt5O97U3lNStOfIF5Wl5oSYafy7BFEwOl0kxaRh+flYk
# 4Fk8MnFwB7nevK1IqF5Goe+Ew0ztv9/OUnU2WttH1p37u/AgbDnIfarUH50wggZx
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
# OjMxQzUtMzBCQS03QzkxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiUKAQEwCQYFKw4DAhoFAAMVAID163R9YO92Nqm/H+4qik8/GqcjoIHe
# MIHbpIHYMIHVMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkw
# JwYDVQQLEyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEnMCUGA1UE
# CxMebkNpcGhlciBOVFMgRVNOOjRERTktMEM1RS0zRTA5MSswKQYDVQQDEyJNaWNy
# b3NvZnQgVGltZSBTb3VyY2UgTWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA
# 4OHNOTAiGA8yMDE5MDcyNDAyMTUyMVoYDzIwMTkwNzI1MDIxNTIxWjB3MD0GCisG
# AQQBhFkKBAExLzAtMAoCBQDg4c05AgEAMAoCAQACAjxaAgH/MAcCAQACAhm+MAoC
# BQDg4x65AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwGgCjAIAgEA
# AgMW42ChCjAIAgEAAgMHoSAwDQYJKoZIhvcNAQEFBQADggEBACNHME4AB04tZh5g
# GFhHdvxuoCYc37Xh00gUl+mdu0RZKRFkq+soW4KItdV8V9zH8e6i1oe0eI51iDj2
# 1oMBrDPNluCy0D9SPqI1UH3dsud4fqJCI/tsd2nljhkR/mHAAhTbAwBBNnXxceaO
# P3RYcoiYjhcZezYrBV/reYMofncQVTygUMByl5JoP867xSjYVGQAN9elBlesHF13
# EFl5wzB5dYCvEh07NqGLJTQSin0BeniXbXoXZjIX2zkaJMyv3TESRsKsvAUj/lJ2
# ljcokvGhShr9eFxipdcykW48cVzy3FgbyWEN5jPUJ00G/EWn1QUKCIp/ENfEjc+l
# D74F3XYxggL1MIIC8QIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAM2m2zivvS1BAAAAAAAAzTANBglghkgBZQMEAgEFAKCCATIwGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAaEP7AnczT1b5E
# xgCLFxVfKFCtMONqLB4mtEOKgYD2hTCB4gYLKoZIhvcNAQkQAgwxgdIwgc8wgcww
# gbEEFID163R9YO92Nqm/H+4qik8/GqcjMIGYMIGApH4wfDELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUt
# U3RhbXAgUENBIDIwMTACEzMAAADNpts4r70tQQAAAAAAAM0wFgQUD8YlP8cfLrPl
# JwPdVhlqxfDaYNwwDQYJKoZIhvcNAQELBQAEggEAmmZBzr+GOHqBUixlY7FSLRLZ
# Selr3iCv4/h+1V3bLLfv42qk0dhe897LyL6wMocTksJgvTMHIZ1hF4Z94X+Zrp0f
# rXhR/iZ0xpg/PLknhAZ6n8M8KDPOQjvUE3ispY9LRSQjHH3nJ8Ph3kaI7mfevW7h
# SFTIMGyRjncX0S0SaWGtyRYPiQKmTFcB7A6hsnrv5k6lLyZI6VxjYJaLBkytCwvM
# Luyq9hIMJSm1Vetbvkt7BpYfimWJoBT0+DDkej2EUnlxJfLkAA52+osmTyFvpFNy
# wAlaUN/ebfaa2y12aUHmrCun4xC0yCC3z0Dzvlcf+KMwEiH013Q2/1Rpett2kw==
# SIG # End signature block
