param(
    [Parameter(Mandatory=$False)]
    [string]$Location = "westeurope",

    [Parameter(Mandatory=$False)]
    [string]$StorageConnection,

    [Parameter(Mandatory=$False)]
    [string]$KeyValueStorageConnection,

    [Parameter(Mandatory=$False)]
    [string]$Security_Admins = ""
)

Function GetAuthorizationToken
{
    param
    (
            [Parameter(Mandatory=$true)]
            $TenantName
    )
    $adal             = "$($FilePath.Replace("\\","\"))\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms        = "$($FilePath.Replace("\\","\"))\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    $clientId         = "1950a258-227b-4e31-a9cf-717495945fc2" 
    $resourceAppIdURI = "https://graph.windows.net"
    $authority        = "https://login.windows.net/$TenantName"
    $creds            = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential" -ArgumentList $($Credential.UserName),$($Credential.GetNetworkCredential().password)
    $authContext      = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $authResult       = $authContext.AcquireToken($resourceAppIdURI, $clientId, $creds)
    return $authResult
}

Function Create-AesManagedObject($key, $IV) {
    $aesManaged           = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode      = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding   = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize   = 256
    If ($IV) {
        If ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        Else {
            $aesManaged.IV = $IV
        }
    }
    If ($key) {
        If ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        Else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

Function Create-AesKey() {
    $aesManaged = Create-AesManagedObject 
    $aesManaged.GenerateKey()
    [System.Convert]::ToBase64String($aesManaged.Key)
}

Clear-Host

If (-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
    Write-Warning "This script requires elevated permissions."
    Write-Warning "Please start PowerShell as an Administrator and run this script again."
    exit
}

$Measure = [System.Diagnostics.Stopwatch]::StartNew()

#region Log in to Azure Automation
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Logging in to azure automation"
Write-Output "--------------------------------------------------------------------------------"

[PSCredential]$Credential = (Get-Credential -Message "Azure tenant administrator account")
If (!($Credential)) { Write-Output "Script aborted..." ; exit }

Import-Module AzureRM.Automation
Login-AzureRmAccount  -Credential $Credential
#endregion

#region Define parameters
$_TenantId                 = "dax$(((Get-AzureRmTenant).TenantId).Replace('-','').Substring(0,21))"
                           
$ResourceGroupName         = $_TenantId
                           
$StorageAccountName        = $_TenantId
$StorageContainer          = "artifacts"
$StorageType               = "Standard_LRS"
                           
$DeploymentName            = $_TenantId
                           
$WebApplicationName        = $_TenantId
$HomePage                  = "http://$($_TenantId).azurewebsites.net"
$IdentifierUris            = "http://$($_TenantId).azurewebsites.net"
                           
$FileName                  = "package.zip"                                       
$FilePath                  = $env:TEMP
                                     
$RedistPath                = "https://github.com/djpericsson/AzureWebAppDeploy/raw/master"
$AzureSDKDllLocation       = $RedistPath
                           
$AzureSDKDlls              = @(
                              "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
                              "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
                             )
                           
$requiredResourceAccess    = @{
    "resourceAppId"        = "00000015-0000-0000-c000-000000000000"
    "resourceAccess"       = @(
        @{                 
            "id"           = "a849e696-ce45-464a-81de-e5c5b45519c1"
            "type"         = "Scope"
        },                 
        @{                 
            "id"           = "ad8b4a5c-eecd-431a-a46f-33c060012ae1"
            "type"         = "Scope"
        },                 
        @{                 
            "id"           = "6397893c-2260-496b-a41d-2f1f15b16ff3"
            "type"         = "Scope"
        },                 
        @{                 
            "id"           = "add75854-3691-457b-84bc-76bc249f1b6f"
            "type"         = "Scope"
        }                  
    )                      
}                          
                           
$CorsRules = @{            
    AllowedHeaders         = @("x-ms-meta-abc","x-ms-meta-data*","x-ms-meta-target*")
    AllowedOrigins         = @("https://website43ueoaeknvyeu.azurewebsites.net")
    MaxAgeInSeconds        = 200
    ExposedHeaders         = @("x-ms-meta-*")
    AllowedMethods         = @("Get")
}

$aad_TenantId              = "8779117d-772e-4ea5-94ec-44a1a1d0427b"
$aad_ExternalApiId         = "https://axtestdynamics365aos.cloudax.dynamics.com/"
#$security_Admins           = ""

#$CorsRules.AllowedOrigins = @("https://www.sunet.se")
#endregion

#region Create AzureRmResourceGroup
If (-not($AzureRmResourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue))
{

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmResourceGroup"
    Write-Output "--------------------------------------------------------------------------------"

    $AzureRmResourceGroupParams = @{
        Name     = $ResourceGroupName
        Location = $Location
    }

    $AzureRmResourceGroup = New-AzureRmResourceGroup @AzureRmResourceGroupParams

    $x = 0
    While ((-not(Get-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction SilentlyContinue)) -and ($X -lt 10))
    {
        Write-Host "SLEEP: $((Get-Date).ToString("hh:mm:ss")) - Awaiting AzureRmResourceGroup status for $(5*$x) seconds" -ForegroundColor "cyan"
        Start-Sleep 5
        $x++
    }

    Write-Output $AzureRmResourceGroup

}
#endregion

#region Create/Get AzureRmStorageAccount
If ($AzureRmResourceGroup -and -not (Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue))
{

    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmStorageAccount"
    Write-Output "--------------------------------------------------------------------------------"

    $AzureRmStorageAccountParams = @{
        Name              = $StorageAccountName
        ResourceGroupName = $ResourceGroupName
        Type              = $StorageType
        Location          = $Location
    }

    $AzureRmStorageAccount = New-AzureRmStorageAccount @AzureRmStorageAccountParams

    Write-Output $AzureRmStorageAccount

    $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
    $StorageContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $Keys[0].Value
}
Else
{
    $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
    $StorageContext = New-AzureStorageContext -StorageAccountName $StorageAccountName $Keys[0].Value
}
#endregion

#region Create AzureStorageContainer
If ($AzureRmResourceGroup -and -not(Get-AzureStorageContainer -Name $StorageContainer -Context $StorageContext -ErrorAction SilentlyContinue))
{

    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureStorageContainer"
    Write-Output "--------------------------------------------------------------------------------"

    $AzureStorageContainerParams = @{
        Name       = $StorageContainer
        Permission = "Off"
        Context    = $StorageContext
    }

    New-AzureStorageContainer @AzureStorageContainerParams

}
#endregion

#region Create AzureStorageCORSRule
$cRules = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

$cUpdate = $False
ForEach ($CorsRule in $CorsRules.Keys)
{
    If (!([string]$cRules.$CorsRule -eq [string]$CorsRules.$CorsRule))
    {
        $cUpdate = $True
        Break
    }
}

If ($cUpdate)
{

    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Create AzureStorageCORSRule"
    Write-Output "--------------------------------------------------------------------------------"

    Set-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext -CorsRules $CorsRules

    Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext
}
#endregion

#region Create AzureRmADApplication
If (-not($AzureRmADApplication = Get-AzureRmADApplication -DisplayNameStartWith $WebApplicationName -ErrorAction SilentlyContinue))
{

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating PSADCredential"
    Write-Output "--------------------------------------------------------------------------------"

    $psadCredential           = New-Object Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADPasswordCredential
    $startDate                = Get-Date
    $psadCredential.StartDate = $startDate
    $psadCredential.EndDate   = $startDate.AddYears(1)
    $psadCredential.KeyId     = [guid]::NewGuid()
    $psadKeyValue             = Create-AesKey
    $psadCredential.Password  = $psadKeyValue

    $psadCredential | Export-Clixml "$env:USERPROFILE\PSADUsr.xml"

    Write-Output $psadCredential

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmADApplication"
    Write-Output "--------------------------------------------------------------------------------"

    $AzureRmADApplicationParams = @{
        DisplayName         = $WebApplicationName
        HomePage            = $HomePage
        IdentifierUris      = $IdentifierUris
        PasswordCredentials = $psadCredential
    }

    $AzureRmADApplication = New-AzureRmADApplication @AzureRmADApplicationParams

    Write-Output $AzureRmADApplication
}
Else
{
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Importing PSADCredential"
    Write-Output "--------------------------------------------------------------------------------"

    If (!(Test-Path -Path "$($env:USERPROFILE)\PSADUsr.csv" -ErrorAction SilentlyContinue))
    {
        $psadCredential = Import-Clixml "$env:USERPROFILE\PSADUsr.xml"
        $psadKeyValue   = $psadCredential.Password

        Write-Output $psadCredential
    }
    Else
    {
        Write-Warning "A PSADCredential could not be found, aborting"
        exit
    }
}
#endregion

#region Create AzureRmADServicePrincipal
If (-not($AzureRmADServicePrincipal = Get-AzureRmADServicePrincipal -SearchString $AzureRmADApplication.DisplayName -ErrorAction SilentlyContinue))
{

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmADServicePrincipal"
    Write-Output "--------------------------------------------------------------------------------"

    $AzureRmADServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $AzureRmADApplication.ApplicationId

    $x = 0
    While ($X -lt 6)
    {
        Write-Host "SLEEP: $((Get-Date).ToString("hh:mm:ss")) - Awaiting AzureRmADServicePrincipal completion for $(30-(5*$x)) seconds" -ForegroundColor "cyan"
        Start-Sleep 5
        $x++
    }

    $x = 0
    While ((-not($AzureRmADServicePrincipal = Get-AzureRmADServicePrincipal -SearchString $AzureRmADApplication.DisplayName -ErrorAction SilentlyContinue)) -and ($X -lt 10))
    {
        Write-Host "SLEEP: $((Get-Date).ToString("hh:mm:ss")) - Awaiting AzureRmADServicePrincipal status for $(5*$x) seconds" -ForegroundColor "cyan"
        Start-Sleep 5
        $x++
    }

    Write-Output $AzureRmADServicePrincipal
}
#endregion

#region Create AzureRmRoleAssignment
If (-not($AzureRmRoleAssignment = Get-AzureRmRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $AzureRmADApplication.ApplicationId -ErrorAction SilentlyContinue))
{

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmRoleAssignment"
    Write-Output "--------------------------------------------------------------------------------"

    $x = 0
    While ((-not($AzureRmRoleAssignment)) -and ($X -lt 15))
    {
        $AzureRmRoleAssignment = $null
        Try
        {
            $AzureRmRoleAssignment = New-AzureRmRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $AzureRmADApplication.ApplicationId -ErrorAction Stop
        }
        Catch
        {
            Write-Host "SLEEP: $((Get-Date).ToString("hh:mm:ss")) - Awaiting AzureRmRoleAssignment status for 5 seconds" -ForegroundColor "cyan"
            Start-Sleep 5
            $x++
        }
    }

    Write-Output $AzureRmADServicePrincipal
}
#endregion


#region Deploy Azure Resource Manager Template
Write-Output ""
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Deploying Azure Resource Manager Template"
Write-Output "--------------------------------------------------------------------------------"

$TemplateParameters = @{
    Name                          = $DeploymentName
    ResourceGroupName             = $AzureRmResourceGroup.ResourceGroupName
    TemplateFile                  = "$($RedistPath)/WebSite.json"
    webApplicationPackageFolder   = $RedistPath
    WebApplicationPackageFileName = $FileName
    WebSiteName                   = $WebApplicationName
    StorageAccountName            = $StorageAccountName
    hostingPlanName               = $WebApplicationName
    aad_ClientId                  = $AzureRmADApplication.ApplicationId
    aad_ClientSecret              = $psadKeyValue
    aad_TenantId                  = "8779117d-772e-4ea5-94ec-44a1a1d0427b"
    aad_PostLogoutRedirectUri     = "$($HomePage)/close.aspx?signedout=yes"
    aad_ExternalApiId             = $aad_ExternalApiId
    StorageConnection             = $StorageConnection
    KeyValueStorageConnection     = $KeyValueStorageConnection
    Security_Admins               = $Security_Admins
}

New-AzureRmResourceGroupDeployment @TemplateParameters -Verbose

$x = 0
While ($X -lt 3)
{
    Write-Host "SLEEP: $((Get-Date).ToString("hh:mm:ss")) - Awaiting AzureRmResourceGroupDeployment for $(15-(5*$x)) seconds" -ForegroundColor "cyan"
    Start-Sleep 5
    $x++
}
#endregion

#region Web App registration with Microsoft Graph REST Api
$WebClient = New-Object System.Net.WebClient
$SDKHeader = $True
ForEach ($DllFile in $AzureSDKDlls)
{
    If (!(Test-Path -Path "$($FilePath)\$($DllFile)" -ErrorAction SilentlyContinue))
    {
        If ($SDKHeader)
        {
            Write-Output ""
            Write-Output "--------------------------------------------------------------------------------"
            Write-Output "Downloading Azure SDK DLL:s"
            Write-Output "--------------------------------------------------------------------------------"
            $SDKHeader = $False
        }
        Write-Output "Downloading: $($DllFile)"
        $WebClient.DownloadFile("$($RedistPath)\$($DllFile)?raw=true", "$($FilePath)\$($DllFile)")
    }
}

$newGuid = New-Guid
$guidToBytes = [System.Text.Encoding]::UTF8.GetBytes($newGuid)

$mySecret = @{
    "type"      = "Symmetric"
    "usage"     = "Verify"
    "endDate"   = [DateTime]::UtcNow.AddDays(365).ToString("u").Replace(" ", "T")
    "keyId"     = $newGuid
    "startDate" = [DateTime]::UtcNow.AddDays(-1).ToString("u").Replace(" ", "T")
    "value"     = [System.Convert]::ToBase64String($guidToBytes)
}

$restPayload = @{
    "keyCredentials" = @($mySecret)
}

$restPayload.Add("requiredResourceAccess",@($requiredResourceAccess))

$restPayload = ConvertTo-Json -InputObject $restPayload -Depth 4

$tenantName = (Get-AzureRmTenant).Domain
$token = GetAuthorizationToken -TenantName $tenantName

$authorizationHeader = @{
    "Content-Type"  = "application/json"
    "Authorization" = $token.CreateAuthorizationHeader()
}

$restUri = "https://graph.windows.net/$($tenantName)/applications/$($AzureRmADApplication.ObjectId)?api-version=1.6"

$restResourceAccess = Invoke-RestMethod -Uri $restUri -Headers $authorizationHeader -Method GET | Select -ExpandProperty requiredResourceAccess

If ($restResourceAccess.resourceAppId -notcontains $requiredResourceAccess.resourceAppId)
{
    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Configure application settings"
    Write-Output "--------------------------------------------------------------------------------"

    Invoke-RestMethod -Uri $restUri -Headers $authorizationHeader -Body $restPayload -Method PATCH -Verbose
}
Else
{
    ForEach ($Resource in $restResourceAccess)
    {
        If ($resourceAccess.resourceAppId -eq $requiredResourceAccess.resourceAppId)
        {
            $resourceAccess = ($Resource | Select -ExpandProperty resourceAccess).id

            $updateResourceAccess = $False
            ForEach ($id in $requiredResourceAccess.resourceAccess.id)
            {
                If ($resourceAccess -notcontains $id)
                {
                    $updateResourceAccess = $True
                    Break
                }
            }

            If ($updateResourceAccess)
            {
                Write-Output ""
                Write-Output "--------------------------------------------------------------------------------"
                Write-Output "Configure application settings"
                Write-Output "--------------------------------------------------------------------------------"

                Invoke-RestMethod -Uri $restUri -Headers $authorizationHeader -Body $restPayload -Method PATCH -Verbose
            }
        }
    }
}

Write-Output ""
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Cleaning up Azure SDK DLL:s"
Write-Output "--------------------------------------------------------------------------------"

ForEach ($DllFile in $AzureSDKDlls)
{
    Write-Output "Removing: $($DllFile)"
    Remove-Item -Path "$($FilePath)\$($DllFile)" -Force
}
#endregion

$Measure.Stop()

Write-Output ""
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Completed in $(($Measure.Elapsed).TotalSeconds) seconds"