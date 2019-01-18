#Clear-AzureRMContext -Scope -Process -Force
Connect-AzureRmAccount
$azureRmContext = Get-AzureRmContext
$token = ($azureRmContext.TokenCache.ReadItems() | Where-Object { $_.Resource -eq "https://management.core.windows.net/" } | Sort-Object -Property ExpiresOn -Descending | Select-Object -First 1)
$token.AccessToken | Set-Clipboard
# Login-AzureRmAccount -AccessToken $token.AccessToken -AccountId $azureRmContext.Account.Id