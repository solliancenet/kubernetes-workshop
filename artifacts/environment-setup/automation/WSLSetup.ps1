<#
COPYRIGHT SOLLIANCE / CHRIS GIVENS
#>

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append

#load the creds
. C:\LabFiles\AzureCreds.ps1

#run the solliance package
. C:\LabFiles\Common.ps1

$userName = $AzureUserName                # READ FROM FILE
$global:password = $AzurePassword                # READ FROM FILE
$clientId = $TokenGeneratorClientId       # READ FROM FILE
$global:localusername = "wsuser"

AddShortcut $global:localusername "C:\Users\$localusername\Desktop" "Workshop" "C:\LabFiles\kubernetes-hands-on-workshop" $null;
AddShortcut $global:localusername "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" "Docker Desktop" "C:\Program Files\Docker\Docker\Docker Desktop.exe" $null;
AddShortcut $global:localusername "C:\Users\$localusername\Desktop" "WSL Setup" "C:\LabFiles\kubernetes-workshop\artifacts\environment-setup\automation\WSLSetup.bat" $null;

Uninstall-AzureRm

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword
Connect-AzAccount -Credential $cred | Out-Null
az login --username $username --password $password

$rg = Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*-02" };
$resourceGroupName = $rg.ResourceGroupName
$deploymentId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]

$uniqueId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]
$subscriptionId = (Get-AzContext).Subscription.Id
$subscriptionName = (Get-AzContext).Subscription.Name
$tenantId = (Get-AzContext).Tenant.Id
$global:logindomain = (Get-AzContext).Tenant.Id;

#InstallWSL2

#InstallUbuntu

#SetupWSL

UpdateDockerSettings $global:localusername;

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

reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f

reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 0 /f

#wsl --set-version docker-desktop

write-host "Stopping docker desktop";
#stop-process -name "docker desktop" -force -ea SilentlyContinue;

#start "C:\Program Files\Docker\Docker\Docker Desktop.exe"

write-host "Starting docker desktop";

$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential "labvm-$deploymentid\$localusername", $securePassword
Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe" -Credential $credential -LoadUserProfile
#Start-Process -FilePath "C:\Windows\System32\cmd.exe" -verb runas -ArgumentList {/c "C:\Program Files\Docker\Docker\Docker Desktop.exe"}

$proc = get-process -name com.docker.backend;

if (!$proc)
{
    write-host "Waiting for Docker backend";

    start-sleep 10;
    $proc = get-process -name com.docker.backend;
}

$proc = get-process -name com.docker.proxy;

if (!$proc)
{
    write-host "Waiting for Docker proxy";

    start-sleep 10;
    $proc = get-process -name com.docker.proxy;
}

#wait for services to stablize
write-host "Waiting a bit longer for docker to start (re-run if docker takes too long)";
start-sleep 30;

#install docker images
DownloadDockerImage "node:alpine"
DownloadDockerImage "mcr.microsoft.com/dotnet/core/sdk:3.1-alpine"
DownloadDockerImage "mcr.microsoft.com/dotnet/core/aspnet:3.1-alpine"

#kubernetes images
DownloadDockerImage "docker/desktop-kubernetes:kubernetes-v1.19.3-cni-v0.8.5-critools-v1.17.0"
DownloadDockerImage "k8s.gcr.io/etcd:3.4.13-0"
DownloadDockerImage "k8s.gcr.io/kube-apiserver:v1.19.3"
DownloadDockerImage "k8s.gcr.io/kube-proxy:v1.19.3"

#setup ask
write-host "Setting up AKS";
$aksName = "fabmedical-$deploymentId";
az aks get-credentials --resource-group $resourcegroupName --name $aksName; 

#login to acr
$acrname = "fabmedical$deploymentId";
$acrCreds = Get-AzContainerRegistryCredential -ResourceGroupName $resourceGroupName -Name $acrName

write-host "Setting docker login to ACR [$acrName]";
$cmd = "C:\Program Files\Docker\Docker\resources\docker"
start-process $cmd -argumentlist "login $acrName.azurecr.io -u $($acrCreds.Username) -p $($acrCreds.Password)";
#start-process "docker" -ArgumentList "login $acrName.azurecr.io -u $($acrCreds.Username) -p $($acrCreds.Password)"

kubectl config use-context docker-deskop

#open VS code to the repo docs.
cd c:\labfiles\kubernetes-hands-on-workshop
code -n .

Stop-Transcript

return 0;