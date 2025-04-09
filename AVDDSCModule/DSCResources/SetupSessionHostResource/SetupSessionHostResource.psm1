class SetupSessionHostResource : DSCResource {
    static SetupSessionHostResource() {
        # Static constructor to import helper functions
        $script:resourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
        $script:functionPath = Join-Path $script:resourceRoot 'Functions\Functions.psm1'

        if (Test-Path $script:functionPath) {
            . $script:functionPath
        }
        else {
            throw "Function module '$script:functionPath' not found."
        }
    }

    [DscProperty(Key)]
    [string]$HostPoolName

    [DscProperty(Mandatory)]
    [string]$RegistrationInfoToken

    [DscProperty()]
    [bool]$AadJoin = $false

    [DscProperty()]
    [bool]$AadJoinPreview = $false

    [DscProperty()]
    [string]$MdmId

    [DscProperty()]
    [string]$SessionHostConfigurationLastUpdateTime

    [DscProperty()]
    [bool]$EnableVerboseMsiLogging = $false

    [DscProperty()]
    [bool]$UseAgentDownloadEndpoint = $false

    [void] Get() {
        [System.Collections.Hashtable]$result = @{
            HostPoolName          = $this.HostPoolName
            RegistrationInfoToken = $this.RegistrationInfoToken
        }
        $result
    }

    [bool] Test() {
        #return (Test-Path "C:\Program Files\RDAgent")
        Write-Log -Message "Checking whether VM was Registered with RDInfraAgent"
        # TODO : verify function logic and what it returns
        return (IsRDAgentRegistryValidForRegistration)
    }

    # If Test() returns $false, Set() will be called
    [void] Set() {
        # Set directory variables 
        $deployPath = "C:\DeployAgent"
        $ScriptPath = "$PSScriptRoot\DeployAgent.zip"
        Write-Log -Message "VM not registered with RDInfraAgent, script execution will continue"
        #Expand-Archive -Path "$PSScriptRoot\DeployAgent.zip" -DestinationPath $deployPath -Force
        ExtractDeploymentAgentZipFile -ScriptPath $ScriptPath -DeployAgentLocation $deployPath
        Write-Log "AgentInstaller is $deployPath\RDAgentBootLoaderInstall, InfraInstaller is $deployPath\RDInfraAgentInstall"

        if ($this.AadJoinPreview) {
            Write-Log "Entra AD join preview flag enabled"
            $registryPath = "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\AzureADJoin"
            if (Test-Path -Path $registryPath) {
                Write-Log "Setting reg key JoinAzureAd"
                New-ItemProperty -Path $registryPath -Name JoinAzureAD -PropertyType DWord -Value 0x01
            }
            else {
                Write-Log "Creating path for azure ad join registry keys: $registryPath"
                New-item -Path $registryPath -Force | Out-Null
                Write-Log "Setting reg key JoinAzureAD"
                New-ItemProperty -Path $registryPath -Name JoinAzureAD -PropertyType DWord -Value 0x01
            }
            if ($this.MdmId) {
                Write-Log "Setting reg key MDMEnrollmentId"
                New-ItemProperty -Path $registryPath -Name MDMEnrollmentId -PropertyType String -Value $this.MdmId
            }
        }

        InstallRDAgents -AgentBootServiceInstallerFolder "$deployPath\RDAgentBootLoaderInstall" `
            -AgentInstallerFolder "$deployPath\RDInfraAgentInstall" `
            -RegistrationToken $this.RegistrationInfoToken `
            -EnableVerboseMsiLogging:$this.EnableVerboseMsiLogging `
            -UseAgentDownloadEndpoint:$this.UseAgentDownloadEndpoint

        Start-Service -Name "RDAgentBootLoader"

        Write-Log -Message "The agent installation code was successfully executed and RDAgentBootLoader, RDAgent installed inside VM for existing hostpool: $($this.HostPoolName)"
        if ($this.SessionHostConfigurationLastUpdateTime) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "SessionHostConfigurationLastUpdateTime" -Value $this.SessionHostConfigurationLastUpdateTime
        }

        if ($this.AadJoin -and -not $this.AadJoinPreview) {
            # 6 Minute sleep to guarantee intune metadata logging
            Write-Log -Message ("Configuration.ps1 complete, sleeping for 6 minutes")
            Start-Sleep -Seconds 360
            Write-Log -Message ("Configuration.ps1 complete, waking up from 6 minute sleep")
        }

        $SessionHostName = GetAvdSessionHostName
        Write-Log -Message "Successfully registered VM '$SessionHostName' to HostPool '$($this.HostPoolName)'"
    }
}