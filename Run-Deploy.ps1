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








Connect-AzureRmAccount
$azureRmContext = Get-AzureRmContext
$token = ($azureRmContext.TokenCache.ReadItems() | Where-Object { $_.Resource -eq "https://management.core.windows.net/" } | Sort-Object -Property ExpiresOn -Descending | Select-Object -First 1)
$token.AccessToken | Set-Clipboard

$stringHashName = 'aho35sqjs3j7s'

# Define global parameters
$globalParams = @{
    ResourceGroupName = 'SignUp-TST'
}

# Azure Arm Template Uri
$TemplateUri = "https://raw.githubusercontent.com/djpericsson/AzureWebAppDeploy/master/"

# Create Automation Runbook
$TemplateName = 'automationRunbook.json'

$params = @{
    AutomationAccountName = $stringHashName
    RunbookName           = 'Set-AzureAutomationAccount'
    RunbookDescription    = 'Set-AzureAutomationAccount'
    RunbookVersion        = '1.0.0.0'
    ScriptUri             = 'https://raw.githubusercontent.com/djpericsson/AzureWebAppDeploy/master/Set-AzureAutomationAccount.ps1'
    JobId                 = [System.Guid]::NewGuid().toString()
    AccountId             = $azureRmContext.Account.Id
    AccessToken           = $token.AccessToken
}

Write-Output "New-AzureRmResourceGroupDeployment -$($globalParams.Keys.ForEach({"$_ '$($globalParams.$_)'"}) -join ' -') -TemplateUri $($TemplateUri + $TemplateName) -$($params.Keys.ForEach({"$_ '$($params.$_)'"}) -join ' -')"
New-AzureRmResourceGroupDeployment @globalParams -TemplateUri $($TemplateUri + $TemplateName) -TemplateParameterObject $params