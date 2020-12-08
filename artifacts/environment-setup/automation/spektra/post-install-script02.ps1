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
    $app = Add-AppxProvisionedPackage -Online -PackagePath C:\temp\Ubuntu1604.appx -skiplicense
    start-sleep 10;

    cd 'C:\Program Files\WindowsApps\'

    if ($app.Online)
    {
        $installCommand = (Get-ChildItem -Path ".\" -Recurse ubuntu1604.exe)[0].Directory.FullName + "\Ubuntu1604.exe"

        write-host "Starting $installCommand";
        start-process $installCommand;
        start-sleep 20;
        stop-process -name "ubuntu1604" -force
    }

    write-host "Installing Ubuntu (1804)";
    $app = Add-AppxProvisionedPackage -Online -PackagePath C:\temp\Ubuntu1804.appx -skiplicense
    start-sleep 10;

    if ($app.Online)
    {
        $installCommand = (Get-ChildItem -Path ".\" -Recurse ubuntu1804.exe)[0].Directory.FullName + "\Ubuntu1804.exe"
        write-host "Starting $installCommand";
        start-process $installCommand;

        start-sleep 20;
        stop-process -name "ubuntu1804" -force
    }

    #write-host "Installing Ubuntu (2004)";
    #Add-AppxProvisionedPackage -Online -PackagePath C:\temp\Ubuntu2004.appx -skiplicense
    #$installCommand = (Get-ChildItem -Path ".\" -Recurse ubuntu2004.exe)[0].Directory.FullName + "\Ubuntu2004.exe"
    #start-process $installCommand;
}

function UpdateDockerSettings($user)
{
    $filePath = "C:\Users\$user\AppData\Roaming\Docker\settings.json"
    write-host "Updating docker settings [$filePath]";

    $data = get-content $filePath -raw;

    $json = ConvertFrom-json $data;

    $json.autoStart = $true;
    $json.kubernetesEnabled = $true;

    $data = ConvertTo-Json $json;
    Set-content $filePath $data;
}

Start-Transcript -Path C:\WindowsAzure\Logs\CloudLabsCustomScriptExtension.txt -Append

#load the creds
. C:\LabFiles\AzureCreds.ps1

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

InstallWSL2

InstallUbuntu

SetupWSL

UpdateDockerSettings $global:localusername;

Stop-Transcript

return 0;