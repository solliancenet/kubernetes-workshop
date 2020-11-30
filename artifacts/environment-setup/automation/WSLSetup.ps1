function SetupWSL()
{
    wsl --set-default-version 2
    wsl --set-version Ubuntu-18.04 2
    #wsl --set-version Ubuntu-18.04 2
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

    <#
    wsl --set-default-version 2
    wsl --set-version Ubuntu 2
    wsl --list -v
    #>
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

    write-host "Installing Ubuntu (2004)";
    Add-AppxProvisionedPackage -Online -PackagePath C:\temp\Ubuntu2004.appx -skiplicense

    $installCommand = (Get-ChildItem -Path ".\" -Recurse ubuntu2004.exe)[0].Directory.FullName + "\Ubuntu2004.exe"
    start-process $installCommand;

    start-sleep 30
}

InstallWSL2

InstallUbuntu

SetupWSL