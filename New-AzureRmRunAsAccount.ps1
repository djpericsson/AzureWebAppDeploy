param(
    [string]$AutomationAccountName = 'aho35sqjs3j7s',
    [string]$ResourceGroupName = 'SignUp-TST',
    [string]$SubscriptionId = '692529f0-a0ae-4fb6-aa9e-a16df69f87cb',
    [string]$Location = 'westeurope',
    [string]$KeyVaultName = 'aho35sqjs3j7s'
)

Write-Output ""

Get-AzureRmSubscription -SubscriptionId $SubscriptionId | Select-AzureRmSubscription | Out-Null

[String] $SelfSignedCertPlainPassword = ([char[]]([char]65..[char]90) + [char[]]([char]97..[char]122) + ([char[]]([char]48..[char]57) + [char[]]([char]33) + [char[]]([char]35..[char]38)) + 0..1 | Sort-Object {Get-Random})[0..23] + ([char[]]([char]33) + [char[]]([char]35..[char]38) | Sort-Object {Get-Random})[0] -join ''
[int] $NoOfMonthsUntilExpired = 36

$CertifcateAssetName = "AzureRunAsCertificate"
$CertificateName = $AutomationAccountName + $CertifcateAssetName
$PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
$PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
$CerCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".cer")

Write-Output "Generating the certificate using Key Vault..."

$certSubjectName = "cn=" + $certificateName

$Policy = New-AzureKeyVaultCertificatePolicy -SecretContentType "application/x-pkcs12" -SubjectName $certSubjectName  -IssuerName "Self" -ValidityInMonths $noOfMonthsUntilExpired -ReuseKeyOnRenewal
$AddAzureKeyVaultCertificateStatus = Add-AzureKeyVaultCertificate -VaultName $KeyVaultName -Name $certificateName -CertificatePolicy $Policy 

While ($AddAzureKeyVaultCertificateStatus.Status -eq "inProgress") {
    Start-Sleep -s 10
    $AddAzureKeyVaultCertificateStatus = Get-AzureKeyVaultCertificateOperation -VaultName $KeyVaultName -Name $certificateName
}

if ($AddAzureKeyVaultCertificateStatus.Status -ne "completed") {
    Write-Error -Message "Key Vault certificate creation was not sucessfull with status: $($status.Status)"
}

$secretRetrieved = Get-AzureKeyVaultSecret -VaultName $KeyVaultName -Name $certificateName
$pfxBytes = [System.Convert]::FromBase64String($secretRetrieved.SecretValueText)
$certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$certCollection.Import($pfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

#Export  the .pfx file 
$protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxCertPlainPasswordForRunAsAccount)
[System.IO.File]::WriteAllBytes($PfxCertPathForRunAsAccount, $protectedCertificateBytes)

#Export the .cer file 
$cert = Get-AzureKeyVaultCertificate -VaultName $KeyVaultName -Name $certificateName
$certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes($CerCertPathForRunAsAccount, $certBytes)

# Create Service Principal
Write-Output "Creating a Service Principal..."
$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
    
$keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
$KeyId = [Guid]::NewGuid() 

$startDate = Get-Date
$endDate = (Get-Date $PfxCert.GetExpirationDateString()).AddDays(-1)

# Use Key credentials and create AAD Application
$Application = New-AzureRmADApplication -DisplayName $AutomationAccountName -HomePage ("http://" + $AutomationAccountName) -IdentifierUris ("http://" + $KeyId)
New-AzureRmADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $startDate -EndDate $endDate 
New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId 

# Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
Start-Sleep -s 15

$NewRole = $null
$Retries = 0
While ($NewRole -eq $null -and $Retries -le 6) {
    New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -scope ("/subscriptions/" + $subscriptionId) -ErrorAction SilentlyContinue
    Start-Sleep -s 10
    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
    $Retries++
}

# Create the automation certificate asset
Write-Output "Creating Certificate in the Asset..."
$CertPassword = ConvertTo-SecureString $PfxCertPlainPasswordForRunAsAccount -AsPlainText -Force
Remove-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $certifcateAssetName -ErrorAction SilentlyContinue
New-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Path $PfxCertPathForRunAsAccount -Name $certifcateAssetName -Password $CertPassword -Exportable  | write-verbose

# Populate the ConnectionFieldValues
$ConnectionTypeName = "AzureServicePrincipal"
$ConnectionAssetName = "AzureRunAsConnection"
$ApplicationId = $Application.ApplicationId 
$SubscriptionInfo = Get-AzureRmSubscription -SubscriptionId $SubscriptionId
$TenantID = $SubscriptionInfo | Select-Object TenantId -First 1
$Thumbprint = $PfxCert.Thumbprint
$ConnectionFieldValues = @{"ApplicationId" = $ApplicationID; "TenantId" = $TenantID.TenantId; "CertificateThumbprint" = $Thumbprint; "SubscriptionId" = $SubscriptionId} 

Write-Output "Creating Connection in the Asset..."
Remove-AzureRmAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue
New-AzureRmAutomationConnection -ResourceGroupName $ResourceGroupName -AutomationAccountName $AutomationAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues 

Write-Output "AzureRmRunAsAccount Creation Completed..."