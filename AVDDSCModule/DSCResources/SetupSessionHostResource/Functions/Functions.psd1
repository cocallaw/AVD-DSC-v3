@{
    ModuleVersion = '1.0.0'
    GUID = '12345678-1234-1234-1234-123456789012'
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