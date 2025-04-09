@{
    RootModule           = 'SetupSessionHostResource.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'c0cdc5a7-c4d9-47f5-8d5c-8a4a57e582ef'
    Author               = 'Corey Callaway'
    CompanyName          = 'Microsoft'
    Description          = 'DSC v3 resource to configure an AVD session host with optional Entra join.'

    PowerShellVersion    = '5.1'
    DscResourcesToExport = @('SetupSessionHostResource')

    FunctionsToExport    = @()
    CmdletsToExport      = @()
    VariablesToExport    = '*'
    AliasesToExport      = @()
}