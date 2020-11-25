function SetupWSL()
{
    wsl --set-default-version 2
    wsl --set-version Ubuntu-18.04 2
    #wsl --set-version Ubuntu-18.04 2
    wsl --list -v
}

SetupWSL