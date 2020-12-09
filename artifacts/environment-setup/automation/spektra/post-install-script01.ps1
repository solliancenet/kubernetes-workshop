<#
COPYRIGHT SOLLIANCE / CHRIS GIVENS
#>

Param (
  [Parameter(Mandatory = $true)]
  [string]
  $azureUsername,

  [string]
  $azurePassword,

  [string]
  $azureTenantID,

  [string]
  $azureSubscriptionID,

  [string]
  $odlId,
    
  [string]
  $deploymentId
)

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append;

[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

mkdir c:\labfiles -ea silentlycontinue;

#download the solliance pacakage
$WebClient = New-Object System.Net.WebClient;
$WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/common-workshop/main/scripts/common.ps1","C:\LabFiles\common.ps1")
$WebClient.DownloadFile("https://raw.githubusercontent.com/solliancenet/common-workshop/main/scripts/httphelper.ps1","C:\LabFiles\httphelper.ps1")

#run the solliance package
. C:\LabFiles\Common.ps1

Set-Executionpolicy unrestricted -force

CreateLabFilesDirectory

mkdir c:\temp -ea silentlycontinue
cd c:\temp

cd "c:\labfiles";

CreateCredFile $azureUsername $azurePassword $azureTenantID $azureSubscriptionID $deploymentId $odlId

. C:\LabFiles\AzureCreds.ps1

$userName = $AzureUserName                # READ FROM FILE
$global:password = $AzurePassword                # READ FROM FILE
$clientId = $TokenGeneratorClientId       # READ FROM FILE
$global:sqlPassword = $AzureSQLPassword          # READ FROM FILE
$global:localusername = "wsuser";

$securePassword = $password | ConvertTo-SecureString -AsPlainText -Force
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $userName, $SecurePassword

InitSetup

DisableInternetExplorerESC

EnableIEFileDownload

InstallChocolaty;

InstallPutty

InstallGit

InstallAzureCli

InstallChrome

InstallNotepadPP

InstallAzPowerShellModule

InstallWSL

InstallWSL2

InstallDockerDesktop

DownloadUbuntu

InstallVisualStudioCode

#InstallVisualStudio "enterprise"

#UpdateVisualStudio "enterprise"

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")

#AddStartupItem "C:\Program Files\Docker\Docker\Docker Desktop.exe";

#AddShortcut $global:localusername "C:\Users\$localusername\Desktop" "Workshop" "C:\LabFiles\kubernetes-hands-on-workshop" $null;
AddShortcut $global:localusername "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" "Docker Desktop" "C:\Program Files\Docker\Docker\Docker Desktop.exe" $null;
#AddShortcut $global:localusername "C:\Users\$localusername\Desktop" "WSL Setup" "C:\LabFiles\kubernetes-workshop\artifacts\environment-setup\automation\WSLSetup.bat" $null;

Uninstall-AzureRm

Connect-AzAccount -Credential $cred | Out-Null
az login --username $username --password $password

#install sql server cmdlets
powershell.exe -c "`$user='$username'; `$pass='$password'; try { Invoke-Command -ScriptBlock { Install-Module -Name SqlServer -force } -ComputerName localhost -Credential (New-Object System.Management.Automation.PSCredential `$user,(ConvertTo-SecureString `$pass -AsPlainText -Force)) } catch { echo `$_.Exception.Message }" 

# Template deployment
$rg = Get-AzResourceGroup | Where-Object { $_.ResourceGroupName -like "*-02" };
$resourceGroupName = $rg.ResourceGroupName
$deploymentId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]

$scriptPath = "C:\LabFiles\kubernetes-workshop\artifacts\environment-setup\automation\spektra\post-install-script02.ps1"
CreateRebootTask "Setup WSL" $scriptPath $null "SYSTEM" $null;
CreateRebootTask "Setup WSL" $scriptPath $null "labvm-$deploymentid\$localusername" $password;

$ropcBodyCore = "client_id=$($clientId)&username=$($userName)&password=$($password)&grant_type=password"
$global:ropcBodySynapse = "$($ropcBodyCore)&scope=https://dev.azuresynapse.net/.default"
$global:ropcBodyManagement = "$($ropcBodyCore)&scope=https://management.azure.com/.default"
$global:ropcBodySynapseSQL = "$($ropcBodyCore)&scope=https://sql.azuresynapse.net/.default"
$global:ropcBodyPowerBI = "$($ropcBodyCore)&scope=https://analysis.windows.net/powerbi/api/.default"
$global:ropcBodyDevOps = "$($ropcBodyCore)&scope=https://app.vssps.visualstudio.com/.default"

cd c:\labfiles

git clone https://github.com/solliancenet/kubernetes-workshop.git

git clone https://github.com/robrich/kubernetes-hands-on-workshop.git

#add helper files...
. "C:\LabFiles\kubernetes-workshop\artifacts\environment-setup\automation\HttpHelper.ps1"

remove-item kubernetes-workshop/.git -Recurse -force -ea SilentlyContinue

$publicKey = get-content "./.ssh/fabmedical.pub" -ea SilentlyContinue;

if (!$publicKey)
{
    mkdir .ssh -ea SilentlyContinue
    ssh-keygen -t RSA -b 2048 -C admin@fabmedical -q -N $azurePassword -f "./.ssh/fabmedical"
    $publicKey = get-content "./.ssh/fabmedical.pub"
}

$uniqueId =  (Get-AzResourceGroup -Name $resourceGroupName).Tags["DeploymentId"]
$subscriptionId = (Get-AzContext).Subscription.Id
$subscriptionName = (Get-AzContext).Subscription.Name
$tenantId = (Get-AzContext).Tenant.Id
$global:logindomain = (Get-AzContext).Tenant.Id;

write-host "Adding AD Application"
$app = Get-AzADApplication -DisplayName "Fabmedical App $deploymentid"
$secret = ConvertTo-SecureString -String $azurePassword -AsPlainText -Force

if (!$app)
{
    $app = New-AzADApplication -DisplayName "Fabmedical App $deploymentId" -IdentifierUris "http://fabmedical-sp-$deploymentId" -Password $secret;
}

$appId = $app.ApplicationId;
$objectId = $app.ObjectId;

$sp = Get-AzADServicePrincipal -ApplicationId $appId;

if (!$sp)
{
    $sp = New-AzADServicePrincipal -ApplicationId $appId -DisplayName "http://fabmedical-sp-$deploymentId" -Scope "/subscriptions/$subscriptionId" -Role "Contributor";
}

$objectId = $sp.Id;
$orgName = "fabmedical-$deploymentId";

$TemplatesPath = "c:\labfiles\kubernetes-workshop\artifacts\environment-setup\automation\templates"
$templateFile = "c:\labfiles\kubernetes-workshop\artifacts\environment-setup\automation\00-core.json";
$parametersFile = "c:\labfiles\kubernetes-workshop\artifacts\environment-setup\automation\spektra\deploy.parameters.post.json";
$content = Get-Content -Path $parametersFile -raw;

$content = $content.Replace("GET-AZUSER-PASSWORD",$azurepassword);

$content = $content | ForEach-Object {$_ -Replace "GET-AZUSER-PASSWORD", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "GET-DEPLOYMENT-ID", "$deploymentId"};
$content = $content | ForEach-Object {$_ -Replace "#GET-REGION#", "$($rg.location)"};
$content = $content | ForEach-Object {$_ -Replace "#GET-REGION-PAIR#", "westus2"};
$content = $content | ForEach-Object {$_ -Replace "#ORG_NAME#", "$deploymentId"};
$content = $content | ForEach-Object {$_ -Replace "#SSH_KEY#", "$publicKey"};
$content = $content | ForEach-Object {$_ -Replace "#CLIENT_ID#", "$appId"};
$content = $content | ForEach-Object {$_ -Replace "#CLIENT_SECRET#", "$AzurePassword"};
$content = $content | ForEach-Object {$_ -Replace "#OBJECT_ID#", "$objectId"};
$content | Set-Content -Path "$($parametersFile).json";

New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -TemplateFile $templateFile -TemplateParameterFile "$($parametersFile).json"

$global:synapseToken = ""
$global:synapseSQLToken = ""
$global:managementToken = ""
$global:powerbiToken = "";
$global:devopsToken = "";

$global:tokenTimes = [ordered]@{
        Synapse = (Get-Date -Year 1)
        SynapseSQL = (Get-Date -Year 1)
        Management = (Get-Date -Year 1)
        PowerBI = (Get-Date -Year 1)
        DevOps = (Get-Date -Year 1)
}

git config --global user.email $AzureUserName
git config --global user.name "Spektra User"
git config --global credential.helper wincred

$username = $azureusername.split("@")[0];

$acrname = "fabmedical$deploymentId";

$aksName = "fabmedical-$deploymentId";
az aks get-credentials --resource-group $resourcegroupName --name $aksName; 

#set the ip DNS name for ingress steps.
$ipAddress = Get-AzPublicIpAddress -resourcegroup $resourcegroupname
$ip = $ipAddress.IpAddress;

write-host "Creating the setup script for remote build machine"

#inital login...
$script = "";
ExecuteRemoteCommand $ip $azurepassword $script 10 $true;

$script = "sudo apt-get --assume-yes update && sudo apt --assume-yes install apt-transport-https ca-certificates curl software-properties-common";
ExecuteRemoteCommand $ip $azurepassword $script 10;

#create a script...
$script = "sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "sudo add-apt-repository 'deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable'"
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "sudo apt-get --assume-yes install curl python-software-properties";
ExecuteRemoteCommand $ip $azurepassword $script 15;

$script = "sudo curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -";
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo apt-get --assume-yes update && sudo apt-get --assume-yes install -y docker-ce nodejs mongodb-clients"
ExecuteRemoteCommand $ip $azurepassword $script 75;

$script = "echo `"deb https://baltocdn.com/helm/stable/debian/ all main`" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list";
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo apt-get update";
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo apt-get install helm";
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo curl https://baltocdn.com/helm/signing.asc | sudo apt-key add -"
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo apt-get install apt-transport-https --yes"
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo apt-get install apt-transport-https --yes"
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo curl -L `"https://github.com/docker/compose/releases/download/1.21.2/docker-compose-Linux-x86_64`" -o /usr/local/bin/docker-compose"
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo chmod +x /usr/local/bin/docker-compose"
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo npm install -g --silent @angular/cli > /dev/null"
ExecuteRemoteCommand $ip $azurepassword $script 25;

$script = "export NG_CLI_ANALYTICS=ci"
ExecuteRemoteCommand $ip $azurepassword $script 25;

$script = 'sudo usermod -aG docker $USER'
ExecuteRemoteCommand $ip $azurepassword $script 10;

$script = "sudo chown -R adminfabmedical /home/adminfabmedical/.config";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "git config --global user.email $AzureUserName"
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "git config --global user.name 'Spektra User'"
ExecuteRemoteCommand $ip $azurepassword $script 5;

$script = "git config --global credential.helper cache"
ExecuteRemoteCommand $ip $azurepassword $script 5;

$acrCreds = Get-AzContainerRegistryCredential -ResourceGroupName $resourceGroupName -Name $acrName
$script = "`rdocker login $acrName.azurecr.io -u $($acrCreds.Username) -p $($acrCreds.Password)";
ExecuteRemoteCommand $ip $azurepassword $script 5;

$line = "echo y | plink.exe -t -ssh -l adminfabmedical -pw `"$password`" $ip";
add-content "c:\labfiles\login.bat" $line;

$line = "echo y | plink.exe -t -ssh -l adminfabmedical -pw `"$password`" -m `"c:\labfiles\setup.sh`" $ip";
add-content "c:\labfiles\setup.bat" $line;

#must do twice...
Start-Process c:\labfiles\login.bat
Start-sleep 10
Stop-Process -Name "plink" -force;

Start-Process c:\labfiles\login.bat
Start-sleep 10
Stop-Process -Name "plink" -force;

#run the script...
write-host "Running setup script"
Start-Process c:\labfiles\setup.bat

#wait 10 minutes
write-host "Waiting 10 mins before reboot"
Start-sleep 600

Stop-Transcript

restart-computer -force;

return 0;