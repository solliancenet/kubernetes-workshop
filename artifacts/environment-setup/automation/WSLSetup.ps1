function SetupWSL()
{
    wsl --set-default-version 2
    wsl --set-version Ubuntu 2
    wsl --list -v
}

SetupWSL