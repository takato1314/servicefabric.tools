# Powershell

All of the latest scripts can be found from the installed SDK version (ie. ```%ProgramFiles%\Microsoft SDKs\Service Fabric\Tools\PSModule\ServiceFabricSDK```).

## Pre-requisites

* Do build and [package](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-package-apps) your SF application using your compiler first.

* [Connection](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-deploy-remove-applications#connect-to-the-cluster) to service fabric cluster must be established by using ```Connect-ServiceFabricCluster``` before invoking this cmdlet.

  ```Console
  > $ConnectArgs = @{ ConnectionEndpoint = 'mycluster.cloudapp.net:19000';  X509Credential = $True;  StoreLocation = 'CurrentUser';  StoreName = "MY";  ServerCommonName = "mycluster.cloudapp.net";  FindType = 'FindByThumbprint';  FindValue = "AA11BB22CC33DD44EE55FF66AA77BB88CC99DD00" }

  > Connect-ServiceFabricCluster @ConnectArgs
  ```

* The [configuration file](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-how-to-parameterize-configuration-files) ```ApplicationParameterFilePath``` 'Local.xml' can be of any name with valid parameters as specified within the ApplicationManifest. You can [validate](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-package-apps#test-the-package) this via the following method

  ```Console
  > Test-ServiceFabricApplicationPackage -ApplicationPackagePath "C:\CalculatorApp" [-ImageStoreConnectionString <String>]-ApplicationParameter @{ "StatelessServiceInstanceCount"="-1" }
  ```

* Optionally, you can choose to [compress](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-package-apps#compress-a-package) your Service Fabric application before [uploading](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-deploy-remove-applications#upload-the-application-package) it Image Store.

  ```Console
  > Copy-ServiceFabricApplicationPackage -ApplicationPackagePath $path -CompressPackage -SkipCopy

  > tree /f $path
    Folder PATH listing for volume OSDisk
    Volume serial number is 0459-2393
    C:\USERS\USER\DOCUMENTS\VISUAL STUDIO 2015\PROJECTS\MYAPPLICATION\MYAPPLICATION\PKG\DEBUG
    |   ApplicationManifest.xml
    |
    └───Stateless1Pkg
        Code.zip
        Config.zip
        ServiceManifest.xml

  ```

## Publish-NewServiceFabricApplication.ps1

Publishes a new Service Fabric application type to Service Fabric cluster. Please read the synopsis in the script file for full information. See [here](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-deploy-remove-applications) for latest info.

* The script will validate application before deployment by default. Use ```SkipPackageValidation``` switch to skip this.

* If the application file is huge, do consider to [compress](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-package-apps#compress-a-package) it before running this script. You can also use the ```CompressPackage``` switch to pre-compress before deployment.

* If that doesn't help, you can consider to increase the ```Timeout``` for the following parameters:

  * CopyPackageTimeoutSec
  * RegisterApplicationTypeTimeoutSec
  * UnregisterApplicationTypeTimeoutSec

### Examples

* Registers & Creates an application with AppParameter file containing name of application and values for parameters that are defined in the application manifest to default image store..

  ```Console
  > Publish-NewServiceFabricApplication -ApplicationPackagePath 'pkg\Debug' -ApplicationParameterFilePath 'Local.xml'
  ```

* Registers & Creates an application with the specified application name to default image store. Application name must start with ```fabric:/```

  ```Console
  > Publish-NewServiceFabricApplication -ApplicationPackagePath 'pkg\Debug' -ApplicationName 'fabric:/Application1'
  ```

* Registers & Creates an application to external image store (available in version 6.x.x onwards).

  ```Console
  > Publish-NewServiceFabricApplication (tbd)
  ```
