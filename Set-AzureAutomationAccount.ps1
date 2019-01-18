param(
    [string]$AutomationResourceGroup,
    [string]$AutomationAccount,
    [string]$AccountId,
    [string]$AccessToken
)

Write-Output $AccountId
Write-Output $AccessToken

Login-AzureRmAccount -AccountId $AccountId -AccessToken $AccessToken

$modules = @(
    "AzureRM.Profile"
)

Write-Output "Install modules"

#Install AzureRmAutomationModule
foreach ($module in $modules) {
    
    if (-not($AzureRmAutomationModule = Get-AzureRmAutomationModule -Name $module -AutomationAccountName $AutomationAccount -ResourceGroupName $AutomationResourceGroup -ErrorAction SilentlyContinue)) {

        $ContentLinkUri = "https://www.powershellgallery.com/api/v2/package/$($module)/$($AzureRmAutomationModule.version)"

        $params = @{
            AutomationAccountName = $AutomationAccount
            ResourceGroupName     = $AutomationResourceGroup
            Name                  = $module
            ContentLinkUri        = $ContentLinkUri
        }

        try {
            Write-Output "New-AzureRmAutomationModule -$($params.Keys.foreach({"$_ '$($params.$_)'"}) -join ' -')"
            $AzureRmAutomationModule = New-AzureRmAutomationModule @params -ErrorAction Stop
            Write-Output $AzureRmAutomationModule
        }
        catch { 
            Write-Error ($_.Exception | Format-List -Force | Out-String) -ErrorAction Continue
            Write-Error ($_.InvocationInfo | Format-List -Force | Out-String) -ErrorAction Continue
        }
    }
}

Write-Output "Create Automation Credential"

# Create an Azure Automation Account
If (-not($AzureRmAutomationCredential = Get-AzureRmAutomationCredential -AutomationAccountName $AutomationAccount -Name $AutomationAccount -ResourceGroupName $AutomationResourceGroup -ErrorAction SilentlyContinue)) {
    Write-Output "Creating an AzureRmAutomationCredential"

    $pw = ConvertTo-SecureString $( -join ([char[]](65..90 + 97..122) * 100 | Get-Random -Count 19) + "!") -AsPlainText -Force

    try {
        $AzureRmAutomationCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AutomationAccount, $pw
        $nAzureRmAutomationCredential = New-AzureRmAutomationCredential -AutomationAccountName $AutomationAccount -Name $AutomationAccount -Description $AutomationAccount -Value $AzureRmAutomationCredential -ResourceGroupName $AutomationResourceGroup -ErrorAction Stop
        Write-Output $nAzureRmAutomationCredential
    }
    catch {
        Write-Error ($_.Exception | Format-List -Force | Out-String) -ErrorAction Continue
        Write-Error ($_.InvocationInfo | Format-List -Force | Out-String) -ErrorAction Continue
    }
}