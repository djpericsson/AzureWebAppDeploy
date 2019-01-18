$Location                  = "northeurope"
$Security_Admins           = "ADMPEER"
$DynamicsAXApiId           = "axtestdynamics365aos-addlevel.cloudax.dynamics.com"
$RepoURL                   = "https://raw.githubusercontent.com/djpericsson/AzureWebAppDeploy/master"

$Webclient                       = New-Object System.Net.Webclient
$Webclient.UseDefaultCredentials = $true
$Webclient.Proxy.Credentials     = $Webclient.Credentials
$Webclient.Encoding              = [System.Text.Encoding]::UTF8
$Webclient.CachePolicy           = New-Object System.Net.Cache.HttpRequestCachePolicy([System.Net.Cache.HttpRequestCacheLevel]::NoCacheNoStore)

$scriptPath = ($Webclient.DownloadString("$RepoURL/App-RegistrationDeployment.ps1"))
Invoke-Command -ScriptBlock ([scriptblock]::Create($scriptPath)) -ArgumentList $Location,$Security_Admins,$DynamicsAXApiId,$RepoURL










$stringHashName = 'aho35sqjs3j7s'

# Define global parameters
$globalParams = @{
    ResourceGroupName = 'SignUp-TST'
}

# Azure Arm Template Uri
$TemplateUri = "https://raw.githubusercontent.com/Optilon/Azure/master/Src/Templates/"

# Create Automation Runbook
$TemplateName = 'automationRunbook.json?token=APkeBgTw9TT-nVoeNap81VYSBlqxp6Mjks5cQaRxwA%3D%3D'

$params = @{
    AutomationAccountName = $stringHashName
    RunbookName           = 'New-AzureRmRunAsAccount'
    RunbookDescription    = 'Create a AzureRmRunAsAccount'
    RunbookVersion        = '1.0.0.0'
    ScriptUri             = 'https://raw.githubusercontent.com/Optilon/Azure/master/Src/Update-AzureModules.ps1?token=APkeBgW8NO6AhorjMQIt1Q7I02NCwsALks5cQXwowA%3D%3D'
    JobId                 = [System.Guid]::NewGuid().toString()
    Tags                  = $configurationData.Tags
}

Write-Output "New-AzureRmResourceGroupDeployment -$($globalParams.Keys.ForEach({"$_ '$($globalParams.$_)'"}) -join ' -') -TemplateUri $($TemplateUri + $TemplateName) -$($params.Keys.ForEach({"$_ '$($params.$_)'"}) -join ' -')"
New-AzureRmResourceGroupDeployment @globalParams -TemplateUri $($TemplateUri + $TemplateName) -TemplateParameterObject $params