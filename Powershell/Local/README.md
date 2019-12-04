# Local Powershell

All of the latest scripts can be found from the installed SDK version (ie. ```%ProgramFiles%\Microsoft SDKs\Service Fabric\ClusterSetup```).

## Usage

* Copy and replace the scripts within this folder to your SDK path (ie. ```%ProgramFiles%\Microsoft SDKs\Service Fabric\ClusterSetup```).

* Run the script from the SF SDK directory.

## CertSetup.ps1

* Clean the existing cluster with ```CleanCluster.ps1```.

* Replace the following line with your desired host alternative name

  Original

  ```Powershell
  $alternativeName.InitializeFromString(3, "<hostname>")
  ```  

  Edited

   ```Powershell
  $alternativeName.InitializeFromString(3, "asymykulnb00195.bert.group")
  ```  

* Run the ```DevClusterSetup.ps1``` script. This will also run the ```CertSetup.ps1``` as well.
