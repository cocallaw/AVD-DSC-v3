Configuration SetupSessionHost
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true)]
        [string]$RegistrationInfoToken,

        [Parameter(Mandatory = $false)]
        [bool]$AadJoin = $false,

        [Parameter(Mandatory = $false)]
        [bool]$AadJoinPreview = $false,

        [Parameter(Mandatory = $false)]
        [string]$MdmId = $null,

        [Parameter(Mandatory = $false)]
        [string]$SessionHostConfigurationLastUpdateTime = $null,

        [Parameter(Mandatory = $false)]
        [switch]$EnableVerboseMsiLogging,

        [Parameter(Mandatory = $false)]
        [bool]$UseAgentDownloadEndpoint = $false
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        # Ensure the DeployAgent folder exists
        File DeployAgentFolder
        {
            DestinationPath = "C:\DeployAgent"
            Ensure = "Present"
            Type = "Directory"
        }

        # Extract the DeployAgent.zip file
        Archive ExtractDeployAgent
        {
            Ensure = "Present"
            Path = (Join-Path $using:ScriptPath "DeployAgent.zip")
            Destination = "C:\DeployAgent"
            DependsOn = "[File]DeployAgentFolder"
        }

        # Configure Azure AD Join registry keys if AadJoinPreview is enabled
        if ($AadJoinPreview)
        {
            Registry AzureADJoinRegistry
            {
                Key = "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\AzureADJoin"
                ValueName = "JoinAzureAD"
                ValueData = 1
                ValueType = "Dword"
                Ensure = "Present"
            }

            if ($MdmId)
            {
                Registry MDMEnrollmentIdRegistry
                {
                    Key = "HKLM:\SOFTWARE\Microsoft\RDInfraAgent\AzureADJoin"
                    ValueName = "MDMEnrollmentId"
                    ValueData = $MdmId
                    ValueType = "String"
                    Ensure = "Present"
                }
            }
        }

        # Install RD Infra Agent and Boot Loader using a Script resource
        Script InstallRDAgents
        {
            DependsOn = "[Archive]ExtractDeployAgent"
            GetScript = { @{} }
            SetScript = {
                InstallRDAgents -AgentBootServiceInstallerFolder "C:\DeployAgent\RDAgentBootLoaderInstall" `
                                -AgentInstallerFolder "C:\DeployAgent\RDInfraAgentInstall" `
                                -RegistrationToken $using:RegistrationInfoToken `
                                -EnableVerboseMsiLogging:$using:EnableVerboseMsiLogging `
                                -UseAgentDownloadEndpoint $using:UseAgentDownloadEndpoint
            }
            TestScript = { Test-Path "C:\Program Files\RDAgent" }
        }

        # Start the RDAgentBootLoader service
        Service RDAgentBootLoaderService
        {
            Name = "RDAgentBootLoader"
            State = "Running"
            DependsOn = "[Script]InstallRDAgents"
        }

        # Update SessionHostConfigurationLastUpdateTime in the registry
        Registry SessionHostConfigUpdateTime
        {
            Key = "HKLM:\SOFTWARE\Microsoft\RDInfraAgent"
            ValueName = "SessionHostConfigurationLastUpdateTime"
            ValueData = $SessionHostConfigurationLastUpdateTime
            ValueType = "String"
            Ensure = "Present"
        }
    }
}

# Generate the MOF file
SetupSessionHost -HostPoolName "YourHostPoolName" `
                 -RegistrationInfoToken "YourRegistrationToken" `
                 -AadJoinPreview $true `
                 -MdmId "YourMdmId" `
                 -SessionHostConfigurationLastUpdateTime "2025-04-07T00:00:00Z"