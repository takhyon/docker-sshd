FROM microsoft/windowsservercore

RUN powershell -Command  \
    Invoke-WebRequest -Uri 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/v0.0.4.0/OpenSSH-Win64.zip' -OutFile "$env:TEMP\OpenSSH-Win64.zip"; \
    Expand-Archive -Path "$env:TEMP\OpenSSH-Win64.zip" -DestinationPath "$env:ProgramFiles"; \
    Move-Item -Path "$env:ProgramFiles\OpenSSH-Win64" -Destination "$env:ProgramFiles\OpenSSH"; \
    Remove-Item -Path "$env:TEMP\OpenSSH-Win64.zip"

RUN powershell -executionpolicy bypass -file "C:\Program Files\OpenSSH\install-sshd.ps1"

WORKDIR "C:\\Program Files\\OpenSSH"

RUN ssh-keygen.exe -A

RUN powershell -Command Start-Service ssh-agent

RUN cmd.exe \
    ssh-add.exe ssh_host_dsa_key; \
    ssh-add.exe ssh_host_rsa_key; \
    ssh-add.exe ssh_host_ecdsa_key; \
    ssh-add.exe ssh_host_ed25519_key

RUN powershell -Command \
    Remove-Item -Path 'C:\Program Files\OpenSSH\ssh_host_dsa_key.pub'; \
    Remove-Item -Path 'C:\Program Files\OpenSSH\ssh_host_rsa_key.pub'; \
    Remove-Item -Path 'C:\Program Files\OpenSSH\ssh_host_ecdsa_key.pub'; \
    Remove-Item -Path 'C:\Program Files\OpenSSH\ssh_host_ed25519_key.pub'

RUN powershell -executionpolicy bypass -file "C:\Program Files\OpenSSH\install-sshlsa.ps1"

RUN powershell -Command Set-Service sshd -StartupType Automatic
RUN powershell -Command Set-Service ssh-agent -StartupType Automatic

RUN powershell -Command \
    $userName = 'user'; \
    $password = 'Iseoptions1'; \
    $secureString = ConvertTo-SecureString $password -AsPlainText -Force; \
    New-LocalUser -Name user -Password $secureString; \
    $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $userName,$secureString; \
    Start-Process cmd /c -Credential $credential -ErrorAction SilentlyContinue -LoadUserProfile; \
    New-Item -Path c:\users\user\.ssh\ -Type Directory

ADD authorized_keys c:/users/user/.ssh/

EXPOSE 22
