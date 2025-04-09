@{
    ModuleVersion = '1.0.0'
    GUID = '512f03f1-7cf8-4251-a964-0303dbd10b28'
    Author = 'Your Name'
    CompanyName = 'Your Company'
    Description = 'Custom functions for DSC configuration'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Write-Log',
        'LocateFile',
        'GetAvdSessionHostName',
        'IsRDAgentRegistryValidForRegistration',
        'GetAgentInstaller',
        'RunMsiWithRetry',
        'StartServiceWithRetry',
        'ExtractDeploymentAgentZipFile',
        'InstallRDAgents'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}