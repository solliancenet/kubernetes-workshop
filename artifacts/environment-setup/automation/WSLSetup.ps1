function SetupWSL()
{
    wsl --set-default-version 2
    wsl --set-version Ubuntu-18.04 2
    wsl --list -v
}

function InstallWSL2
{
    write-host "Installing WSL2";

    mkdir c:\temp -ea silentlycontinue
    cd c:\temp
    
    $downloadNotePad = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi";

    #download it...		
    Start-BitsTransfer -Source $DownloadNotePad -DisplayName Notepad -Destination "wsl_update_x64.msi"

    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList @($localusername,(ConvertTo-SecureString -String $password -AsPlainText -Force))

    #Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\wsl_update_x64.msi /quiet' -Credential $credentials
    Start-Process msiexec.exe -Wait -ArgumentList '/I C:\temp\wsl_update_x64.msi /quiet'
}

function InstallUbuntu()
{
    write-host "Installing Ubuntu (1604)";
    Add-AppxProvisionedPackage -Online -PackagePath C:\temp\Ubuntu1604.appx -skiplicense

    cd 'C:\Program Files\WindowsApps\'
    $installCommand = (Get-ChildItem -Path ".\" -Recurse ubuntu1604.exe)[0].Directory.FullName
    $installCommand += "\Ubuntu1604.exe"
    start-process $installCommand;

    write-host "Installing Ubuntu (1804)";
    Add-AppxProvisionedPackage -Online -PackagePath C:\temp\Ubuntu1804.appx -skiplicense

    $installCommand = (Get-ChildItem -Path ".\" -Recurse ubuntu1804.exe)[0].Directory.FullName + "\Ubuntu1804.exe"
    start-process $installCommand;

    #write-host "Installing Ubuntu (2004)";
    #Add-AppxProvisionedPackage -Online -PackagePath C:\temp\Ubuntu2004.appx -skiplicense
    #$installCommand = (Get-ChildItem -Path ".\" -Recurse ubuntu2004.exe)[0].Directory.FullName + "\Ubuntu2004.exe"
    #start-process $installCommand;

    start-sleep 30
}

function DownloadDockerImage($imageName)
{
    write-host "Downloading docker image [$imageName]";

	docker pull $imageName
}

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append

#load the creds
. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName                # READ FROM FILE
$global:password = $AzurePassword                # READ FROM FILE
$clientId = $TokenGeneratorClientId       # READ FROM FILE
$global:localusername = $username

Uninstall-AzureRm

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword
Connect-AzAccount -Credential $cred | Out-Null

$rg = Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*-02" };
$resourceGroupName = $rg.ResourceGroupName
$deploymentId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]

$uniqueId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]
$subscriptionId = (Get-AzContext).Subscription.Id
$subscriptionName = (Get-AzContext).Subscription.Name
$tenantId = (Get-AzContext).Tenant.Id
$global:logindomain = (Get-AzContext).Tenant.Id;

InstallWSL2

InstallUbuntu

SetupWSL

#start docker
write-host "Starting docker";
start-service -Name com.docker.service

$svc = get-service com.docker.service

while($svc.status -ne "Running")
{
    write-host "Waiting for docker to start";
    $svc = get-service com.docker.service

    start-sleep 5;
}

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

start "C:\Program Files\Docker\Docker\Docker Desktop.exe"

#install docker images
DownloadDockerImage "node:alpine"
DownloadDockerImage "mcr.microsoft.com/dotnet/core/sdk:3.1-alpine"
DownloadDockerImage "mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine"

#kubernetes images
DownloadDockerImage "docker/desktop-kubernetes:kubernetes-v1.19.3-cni-v0.8.5-critools-v1.17.0"
DownloadDockerImage "k8s.gcr.io/etcd:3.4.13-0"
DownloadDockerImage "k8s.gcr.io/kube-apiserver:v1.19.3"
DownloadDockerImage "k8s.gcr.io/kube-proxy:v1.19.3"

#login to acr
$acrname = "fabmedical$deploymentId";
$acrCreds = Get-AzContainerRegistryCredential -ResourceGroupName $resourceGroupName -Name $acrName

start-process "docker" -ArgumentList "login $acrName.azurecr.io -u $($acrCreds.Username) -p $($acrCreds.Password)"

Stop-Transcript

return 0;