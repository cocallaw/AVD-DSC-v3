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
        return (Test-Path "C:\Program Files\RDAgent")
    }

    [void] Set() {
        $deployPath = "C:\DeployAgent"
        if (-not (Test-Path $deployPath)) {
            New-Item -ItemType Directory -Path $deployPath | Out-Null
        }

        Expand-Archive -Path "$PSScriptRoot\DeployAgent.zip" -DestinationPath $deployPath -Force

        if ($this.AadJoinPreview) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\AzureADJoin" -Name "JoinAzureAD" -Value 1 -Type DWord
            if ($this.MdmId) {
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\AzureADJoin" -Name "MDMEnrollmentId" -Value $this.MdmId -Type String
            }
        }

        # You can now call your custom function
        InstallRDAgents -AgentBootServiceInstallerFolder "$deployPath\RDAgentBootLoaderInstall" `
            -AgentInstallerFolder "$deployPath\RDInfraAgentInstall" `
            -RegistrationToken $this.RegistrationInfoToken `
            -EnableVerboseMsiLogging:$this.EnableVerboseMsiLogging `
            -UseAgentDownloadEndpoint:$this.UseAgentDownloadEndpoint

        Start-Service -Name "RDAgentBootLoader"

        if ($this.SessionHostConfigurationLastUpdateTime) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "SessionHostConfigurationLastUpdateTime" -Value $this.SessionHostConfigurationLastUpdateTime
        }
    }
}