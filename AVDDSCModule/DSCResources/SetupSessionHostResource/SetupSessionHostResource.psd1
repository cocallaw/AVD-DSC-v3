@{
    RootModule           = 'SetupSessionHostResource.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'a1234567-b89c-40ab-9abc-1234567890ab'
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