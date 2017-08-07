#Parameters for input as arguments or parameters
param(
    [Parameter(Mandatory=$True)]
    [string]$Location,

    [Parameter(Mandatory=$True)]
    [string]$Security_Admins,

    [Parameter(Mandatory=$True)]
    [string]$DynamicsAXApiId,

    [Parameter(Mandatory=$True)]
    [string]$RepoURL,

    [Parameter(Mandatory=$False)]
    [string]$ExFlowUserSecret,

    [Parameter(Mandatory=$False)]
    [string]$Prefix,

    [Parameter(Mandatory=$False)]
    [string]$PackageVersion = "latest",

    [Parameter(Mandatory=$False)]
    [string]$TenantGuid,

    [Parameter(Mandatory=$False)]
    [string]$WebAppSubscriptionGuid
)

Function Get-UrlStatusCode
{
    Param
    (
        [ValidateNotNullOrEmpty()]
        [String]$Url
    )
    try
    {
        (Invoke-WebRequest -Uri $Url -UseBasicParsing -DisableKeepAlive).StatusCode
    }
    catch [Net.WebException]
    {
        [int]$_.Exception.Response.StatusCode
    }
}

Clear-Host

#We client download options
$Webclient                       = New-Object System.Net.Webclient
$Webclient.UseDefaultCredentials = $true
$Webclient.Proxy.Credentials     = $Webclient.Credentials
$Webclient.Encoding              = [System.Text.Encoding]::UTF8
$Webclient.CachePolicy           = New-Object System.Net.Cache.HttpRequestCachePolicy([System.Net.Cache.HttpRequestCacheLevel]::NoCacheNoStore)

#Start measuring time to complete script
$Measure = [System.Diagnostics.Stopwatch]::StartNew()

#Import script parameters and variables from a configuration data file
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Importing configuration"
Write-Output "--------------------------------------------------------------------------------"

$DependencyValidation = $True

#Download the Helper-Module
$StatusCodeHelper = Get-UrlStatusCode -Url "$RepoURL/Helper-Module.ps1"
If ($StatusCodeHelper -ne 200) {
    Write-Warning "Helper-Module location could not be verified."
    Write-Warning "Url: $RepoURL/Helper-Module.ps1"
    Write-Warning "StatusCode $StatusCodeHelper"
    $DependencyValidation = $False
} Else {
    $Webclient.DownloadString("$RepoURL/Helper-Module.ps1") | Invoke-Expression
}

#Download and convert the configuration data file as Hash Table
$StatusCodeConfiguration = Get-UrlStatusCode -Url "$RepoURL/ConfigurationData.psd1"
If ($StatusCodeConfiguration -ne 200) {
    Write-Warning "ConfigurationData.psd1 location could not be verified."
    Write-Warning "Url: $RepoURL/ConfigurationData.psd1"
    Write-Warning "StatusCode $StatusCodeConfiguration"
    $DependencyValidation = $False
} Else {
    [hashtable]$ConfigurationData = Get-ConfigurationDataAsObject -ConfigurationData ($Webclient.DownloadString("$RepoURL/ConfigurationData.psd1") | Invoke-Expression)
}

$LogFile = "$($ConfigurationData.LocalPath)\$($ConfigurationData.LogFile)"

Write-Host $LogFile

Invoke-Logger -Message "Helper-Module location was successfully verified." -Severity I -Category "Helper-Module"
Invoke-Logger -Message "Url: $RepoURL/Helper-Module.ps1" -Severity I -Category "Helper-Module"
Invoke-Logger -Message "StatusCode $UrlStatusCode" -Severity I -Category "Helper-Module"

Invoke-Logger -Message "ConfigurationData.psd1 location was successfully verified." -Severity I -Category "Configuration"
Invoke-Logger -Message "Url: $RepoURL/ConfigurationData.psd1" -Severity I -Category "Configuration"
Invoke-Logger -Message "StatusCode $UrlStatusCode" -Severity I -Category "Configuration"

break

If (!$DependencyValidation) { Write-Host "" ; Write-Warning "See SignUp's GitHub for more info and help." ; return }

Write-Output "$PSScriptRoot\ConfigurationData.psd1"
Write-Output ""

#region Checking PowerShell version and modules
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Checking PowerShell version and modules"
Write-Output "--------------------------------------------------------------------------------"

#Call function to verify installed modules and versions against configuration data file
$hasErrors = Get-RequiredModules -Modules $ConfigurationData.Modules

#Verify installed PowerShell version against the configuration data file
If ($PSVersionTable.PSVersion -lt $ConfigurationData.PowerShell.Version) {
    Write-Warning "PowerShell must be updated to at least $($ConfigurationData.PowerShell.Version). See SignUp's GitHub for more info and help."
    $hasErrors = $True
} Else {
    Write-Host "PowerShell version $($PSVersionTable.PSVersion) is valid."
    Write-Host ""
}

If ($hasErrors) {
    Write-Host ""
    Write-Warning "See SignUp's GitHub for more info and help."
    break
}
#endregion

#get the zip-file
If ($ExFlowUserSecret) {
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Checking package"
    Write-Output "--------------------------------------------------------------------------------"

    $packageURL = (New-Object System.Net.Webclient).DownloadString("$($ConfigurationData.PackageURL)/packages?s="+$ExFlowUserSecret+"&v="+$PackageVersion)

    Write-Output "Package URL: " 
    Write-Output $packageURL
    Write-Output ""

    $packgeUrlAr   = $packageURL.Split("?")
    $packageSAS    = "$($ConfigurationData.WebApplication)?"+$packgeUrlAr[1]
    $packageFolder = $packgeUrlAr[0].replace("/$($ConfigurationData.WebApplication)","")
}
#endregion 


#Import used AzureRM modules to memory
If (-not (Get-Module -Name AzureRM.Automation -ErrorAction SilentlyContinue)) { Import-Module AzureRM.Automation }
If (-not (Get-Module -Name AzureRM.Profile -ErrorAction SilentlyContinue))    { Import-Module AzureRM.Profile }

#region Log in to Azure Automation
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Logging in to azure automation"
Write-Output "--------------------------------------------------------------------------------"

#Determine logon status
$AzureRmLogon = Get-AzureRmContext -ErrorAction Stop

If (!$AzureRmLogon.Account) {

    #Determine if manual subscription id was provided
    If ($WebAppSubscriptionGuid) {
        Write-Host "Subscription co-admin account"
        $AzureRmLogon = Set-AzureRmLogon -SubscriptionGuid $SubscriptionGuid
    }
    Else {
        $AzureRmLogon = Set-AzureRmLogon
    }

    #If logon failed abort script
    If (!$AzureRmLogon) { return }

    #Determine Azure subscription
    If (-not($AzureRmLogon.Context.Subscription)){
        Write-Warning "The account is not linked to an Azure subscription! Please add account to a subscription in the Azure portal."
        return
    }
    Else {
        #Get all subscriptions
        $SubscriptionIds = Get-AzureRmSubscription -TenantId $AzureRmLogon.Context.Tenant.Id | Select-Object Name,Id

        #Multiple subscriptions detected
        If ($SubscriptionIds.Id.count -gt 1) {
            $mChoices = @()
            $choice = $null
            [int]$i = 0

            #Dynamically provide all subscriptions as a choice menu
            ForEach ($SubscriptionId in $SubscriptionIds) {
                $i++
                $choice = "`$$i = new-Object System.Management.Automation.Host.ChoiceDescription '`&$($SubscriptionId.Id)','$($SubscriptionId.Id)'"
                Invoke-Expression $choice
                $mChoices += $($SubscriptionId.Name)
            }

            #Call functions to return answer from choice menu
            $answer = Get-ChoiceMenu -Choices $choices -mChoices $mChoices
        
            #Select the chosen AzureRmSubscription
            Select-AzureRmSubscription -SubscriptionId $SubscriptionIds[$answer].Id -TenantId $AzureRmLogon.Context.Tenant.Id
        }
    }

    #Set AzureRM context
    Set-AzureRmContext -Context $AzureRmLogon.Context

}
Else {
    #Get all subscriptions
    $SubscriptionIds = Get-AzureRmSubscription -TenantId $AzureRmLogon.Tenant.Id | Select-Object Name,Id

    #Multiple subscriptions detected
    If ($SubscriptionIds.Id.count -gt 1) {
        $mChoices = @()
        $choice = $null
        [int]$i = 0

        #Dynamically provide all subscriptions as a choice menu
        ForEach ($SubscriptionId in $SubscriptionIds) {
            $i++
            $choice = "`$$i = new-Object System.Management.Automation.Host.ChoiceDescription '`&$($SubscriptionId.Id)','$($SubscriptionId.Id)'"
            Invoke-Expression $choice
            $mChoices += $($SubscriptionId.Name)
        }

        #Call functions to return answer from choice menu
        $answer = Get-ChoiceMenu -Choices $choices -mChoices $mChoices
        
        #Select the chosen AzureRmSubscription
        Select-AzureRmSubscription -SubscriptionId $SubscriptionIds[$answer].Id -TenantId $AzureRmLogon.Tenant.Id
    }
    Else {
        #List currently logged on session
        $AzureRmLogon
    }
}

#Get tenant id information
If ($TenantGuid){
    $Tenant = Get-AzureRmTenant -TenantId $TenantGuid
} Else {
    $Tenant = Get-AzureRmTenant
}

$aad_TenantId = $Tenant.Id
$tenantName = $Tenant.Directory

If (!$aad_TenantId){
    Write-Warning "A tenant id could not be found."
    return
}

#Set tenant variables based on logged on session
If ($AzureRmLogon.Account.Id) {
    $SignInName   = $AzureRmLogon.Account.Id
    $Subscription = "/subscriptions/$($AzureRmLogon.Subscription.Id)"
    $TenantId     = $AzureRmLogon.Tenant.Id
}
Else {
    $SignInName   = $AzureRmLogon.Context.Account.Id
    $Subscription = "/subscriptions/$($AzureRmLogon.Context.Subscription.Id)"
    $TenantId     = $AzureRmLogon.Context.Tenant.Id
}

Write-Output "--------------------------------------------------------------------------------"
Write-Output "Tenant information"
Write-Output "--------------------------------------------------------------------------------"

$Tenant
#endregion

#Call function to set deployment name for resources based on DynamicsAXApiId name

Write-Output "--------------------------------------------------------------------------------"
Write-Output "Determining deployment name and availability"
Write-Output "--------------------------------------------------------------------------------"

$DeploymentName = Set-DeploymentName -String $DynamicsAXApiId

Write-Output "Deployment name: $DeploymentName"

If (!$DeploymentName) { Write-Warning "A deployment name could not be generated." ; return }

If (-not(Get-AzureRmResourceGroup -Name $DeploymentName -Location $Location -ErrorAction SilentlyContinue)) {
    Write-Output "New deployment detected"
    Write-Output ""
    If (-not(Test-AzureRmDnsAvailability -DomainNameLabel $DeploymentName -Location $Location)) {
        Write-Warning "A unique AzureRm DNS name could not be automatically determined."
    }
    If (Resolve-DnsName -Name "$($DeploymentName).$($ConfigurationData.AzureRmDomain)" -ErrorAction SilentlyContinue) {
        Write-Warning "A unique DNS name could not be automatically determined."
    }
}
Else {
    Write-Output "Existing deployment detected"
    Write-Output ""
}

<#
If (-not(Get-AzureRmResourceGroup -Name $DeploymentName -Location $Location -ErrorAction SilentlyContinue) -and `
   (-not(Test-AzureRmDnsAvailability -DomainNameLabel $DeploymentName -Location $Location)))
{
    Write-Warning "A unique AzureRm DNS name could not be automatically determined."
    return
}
#>

#Verify AzureRmRoleAssignment to logged on user
If ($ConfigurationData.AzureRmRoleAssignmentValidation) {
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Validating AzureRmRoleAssignment"
    Write-Output "--------------------------------------------------------------------------------"

    #Get AzureRmRoleAssignment for currently logged on user
    $AzureRmRoleAssignment = (Get-AzureRmRoleAssignment -SignInName $SignInName | Where-Object { $_.Scope -eq $Subscription } | Select-Object RoleDefinitionName).RoleDefinitionName

    $AzureRmRoleAssignment

    Write-Output ""

    #Determine that the currently logged on user has appropriate permissions to run the script in their Azure subscription
    If (-not ($AzureRmRoleAssignment -contains "Owner") -and -not ($AzureRmRoleAssignment -contains "Contributor")) {
        Write-Host ""
        Write-Warning "Owner or contributor permissions could not be verified for your subscription."
        Write-Host ""
        Write-Warning "See SignUp's GitHub for more info and help."
        return
    }
}

#region Create AzureRmResourceGroup
If (-not($AzureRmResourceGroup = Get-AzureRmResourceGroup -Name $DeploymentName -Location $Location -ErrorAction SilentlyContinue))
{

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmResourceGroup"
    Write-Output "--------------------------------------------------------------------------------"

    $AzureRmResourceGroupParams = @{
        Name     = $DeploymentName
        Location = $Location
    }

    Try {
        $AzureRmResourceGroup = New-AzureRmResourceGroup @AzureRmResourceGroupParams -ErrorAction Stop
    } Catch {
        Write-Error $_
        return
    }  

    $x = 0
    While ((-not(Get-AzureRmResourceGroup -Name $DeploymentName -Location $Location -ErrorAction SilentlyContinue)) -and ($X -lt 10))
    {
        Write-Host "SLEEP: $((Get-Date).ToString("hh:mm:ss")) - Awaiting AzureRmResourceGroup status for $(5*$x) seconds" -ForegroundColor "cyan"
        Start-Sleep 5
        $x++
    }

    Write-Output $AzureRmResourceGroup

}
#endregion

#region Create/Get AzureRmStorageAccount
If ($AzureRmResourceGroup -and -not (Get-AzureRmStorageAccount -ResourceGroupName $DeploymentName -Name $DeploymentName -ErrorAction SilentlyContinue))
{

    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmStorageAccount"
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "This process may take a few minutes..."

    $AzureRmStorageAccountParams = @{
        Name              = $DeploymentName
        ResourceGroupName = $DeploymentName
        Type              = $ConfigurationData.Storage.Type
        Location          = $Location
    }

    Try {
        $AzureRmStorageAccount = New-AzureRmStorageAccount @AzureRmStorageAccountParams -ErrorAction Stop
    } Catch {
        Write-Error $_
        return
    }

    Write-Output $AzureRmStorageAccount

    $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $DeploymentName -Name $DeploymentName
    $StorageContext = New-AzureStorageContext -StorageAccountName $DeploymentName -StorageAccountKey $Keys[0].Value
}
Else
{
    $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $DeploymentName -Name $DeploymentName
    $StorageContext = New-AzureStorageContext -StorageAccountName $DeploymentName $Keys[0].Value
}
#endregion

#region Create AzureStorageContainer
If ($AzureRmResourceGroup -and $AzureRmStorageAccount -and -not(Get-AzureStorageContainer -Name $ConfigurationData.Storage.Container -Context $StorageContext -ErrorAction SilentlyContinue))
{

    Write-Output ""
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureStorageContainer"
    Write-Output "--------------------------------------------------------------------------------"

    $AzureStorageContainerParams = @{
        Name       = $ConfigurationData.Storage.Container
        Permission = "Off"
        Context    = $StorageContext
    }

    New-AzureStorageContainer @AzureStorageContainerParams

}
#endregion

#region Create AzureStorageCORSRule
If ($StorageContext) {
    $ConfigurationData.CorsRules.AllowedOrigins = ($ConfigurationData.CorsRules.AllowedOrigins).Replace("[TenantId]",$DeploymentName)

    $cRules = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

    $cUpdate = $False
    ForEach ($CorsRule in $ConfigurationData.CorsRules.Keys)
    {
        If (!([string]$cRules.$CorsRule -eq [string]$ConfigurationData.CorsRules.$CorsRule))
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

        Try {
            Set-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext -CorsRules $ConfigurationData.CorsRules -ErrorAction Stop
            Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext
        } Catch {
            Write-Error $_
        }
    }
}
#endregion

#region Create AzureRmADApplication
If (-not($AzureRmADApplication = Get-AzureRmADApplication -DisplayNameStartWith $DeploymentName -ErrorAction SilentlyContinue))
{

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating PSADCredential"
    Write-Output "--------------------------------------------------------------------------------"

    $psadCredential           = New-Object Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADPasswordCredential
    $startDate                = Get-Date
    $psadCredential.StartDate = $startDate
    $psadCredential.EndDate   = $startDate.AddYears($ConfigurationData.PSADCredential.Years)
    $psadCredential.KeyId     = [guid]::NewGuid()
    $psadKeyValue             = Set-AesKey
    $psadCredential.Password  = $psadKeyValue

    $SecurePassword = $psadKeyValue | ConvertTo-SecureString -AsPlainText -Force
    $SecurePassword | Export-Clixml $ConfigurationData.PSADCredential.ClixmlPath

    Write-Output $psadCredential
    Write-Output ""

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmADApplication"
    Write-Output "--------------------------------------------------------------------------------"


    $AzureRmADApplicationParams = @{
        DisplayName         = $DeploymentName
        HomePage            = "https://$($DeploymentName).$($ConfigurationData.AzureRmDomain)/inbox.aspx"
        IdentifierUris      = "https://$($DeploymentName).$($ConfigurationData.AzureRmDomain)"
        ReplyUrls           = "https://$($DeploymentName).$($ConfigurationData.AzureRmDomain)/inbox.aspx"
        PasswordCredentials = $psadCredential
    }

    Try {
        $AzureRmADApplication = New-AzureRmADApplication @AzureRmADApplicationParams -ErrorAction Stop
        Write-Output $AzureRmADApplication
    } Catch {
        Write-Error $_
    }   
}
Else
{
    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Importing PSADCredential"
    Write-Output "--------------------------------------------------------------------------------"

    If (Test-Path -Path $ConfigurationData.PSADCredential.ClixmlPath -ErrorAction SilentlyContinue)
    {

        $SecurePassword = Import-Clixml $ConfigurationData.PSADCredential.ClixmlPath
        $psadKeyValue  = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword))

        Write-Output $psadKeyValue
    }
    Else
    {
        Write-Warning "A PSADCredential could not be found, aborting"
        return
    }
}
#endregion

#region Create AzureRmADServicePrincipal
If ($AzureRmADApplication -and -not($AzureRmADServicePrincipal = Get-AzureRmADServicePrincipal -SearchString $AzureRmADApplication.DisplayName -ErrorAction SilentlyContinue))
{

    Write-Output "--------------------------------------------------------------------------------"
    Write-Output "Creating AzureRmADServicePrincipal"
    Write-Output "--------------------------------------------------------------------------------"

    Try {
        $AzureRmADServicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $AzureRmADApplication.ApplicationId -ErrorAction Stop
    } Catch {
        Write-Error $_
    } 

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
If ($AzureRmADApplication -and -not($AzureRmRoleAssignment = Get-AzureRmRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $AzureRmADApplication.ApplicationId -ErrorAction SilentlyContinue))
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

    Write-Output $AzureRmRoleAssignment
}
#endregion

#region Deploy Azure Resource Manager Template
Write-Output ""
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Deploying Azure Resource Manager Template"
Write-Output "--------------------------------------------------------------------------------"

[bool]$ParamValidation = $True
If (!$DeploymentName)                                                                                          { Write-Warning "Deployment name parameter could not be determined." ; $ParamValidation = $False}
If ($(Get-UrlStatusCode -Url "$($ConfigurationData.RedistPath)/WebSite.json") -ne 200)                         { Write-Warning "Template file location could not be verified." ; $ParamValidation = $False}
If ($(Get-UrlStatusCode -Url "$($ConfigurationData.RedistPath)/$($ConfigurationData.WebApplication)") -ne 200) { Write-Warning "Web application file location could not be verified." ; $ParamValidation = $False}
If (!$AzureRmADApplication.ApplicationId)                                                                      { Write-Warning "Application ID parameter could not be verified." ; $ParamValidation = $False}
If (!$psadKeyValue)                                                                                            { Write-Warning "PSADCredential secret could not be verified." ; $ParamValidation = $False}
If (!$AzureRmADApplication.ApplicationId)                                                                      { Write-Warning "AAD client ID parameter could not be verified." ; $ParamValidation = $False}
If (!$aad_TenantId)                                                                                            { Write-Warning "AAD tenant ID parameter could not be verified." ; $ParamValidation = $False}
If (!$Keys[0].Value)                                                                                           { Write-Warning "Storage SAS key could not be verified." ; $ParamValidation = $False}

If (!$ParamValidation) { Write-Host "" ; Write-Warning "See SignUp's GitHub for more info and help." ; return }

$TemplateParameters = @{
    Name                          = $DeploymentName
    ResourceGroupName             = $DeploymentName
    TemplateFile                  = "$($ConfigurationData.RedistPath)/WebSite.json"
    webApplicationPackageFolder   = $ConfigurationData.RedistPath
    WebApplicationPackageFileName = $ConfigurationData.WebApplication
    WebSiteName                   = $DeploymentName
    StorageAccountName            = $DeploymentName
    hostingPlanName               = $DeploymentName
    aad_ClientId                  = $AzureRmADApplication.ApplicationId
    aad_ClientSecret              = $psadKeyValue
    aad_TenantId                  = $aad_TenantId
    aad_PostLogoutRedirectUri     = "https://$($DeploymentName).$($ConfigurationData.AzureRmDomain)/close.aspx?signedout=yes"
    aad_ExternalApiId             = "https://$($DynamicsAXApiId)"
    StorageConnection             = "DefaultEndpointsProtocol=https;AccountName=$($DeploymentName);AccountKey=$($Keys[0].Value);"
    KeyValueStorageConnection     = "DefaultEndpointsProtocol=https;AccountName=$($DeploymentName);AccountKey=$($Keys[0].Value);"
}

If ($Security_Admins)
{
    $TemplateParameters.Add("Security_Admins",$Security_Admins)
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
$SDKHeader = $True
ForEach ($DllFile in $ConfigurationData.AzureSDK.Dlls)
{
    If (!(Test-Path -Path "$($ConfigurationData.LocalPath)\$($DllFile)" -ErrorAction SilentlyContinue))
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

        Get-WebDownload -Source "$($ConfigurationData.RedistPath)/$($DllFile)?raw=true" -Target "$($ConfigurationData.LocalPath)/$($DllFile)"
    }
}

$newGuid = [guid]::NewGuid()
$guidToBytes = [System.Text.Encoding]::UTF8.GetBytes($newGuid)

$mySecret = @{
    "type"      = $ConfigurationData.ApplicationRegistration.Type
    "usage"     = "Verify"
    "endDate"   = [DateTime]::UtcNow.AddDays($ConfigurationData.ApplicationRegistration.Days).ToString("u").Replace(" ", "T")
    "keyId"     = $newGuid
    "startDate" = [DateTime]::UtcNow.AddDays(-1).ToString("u").Replace(" ", "T")
    "value"     = [System.Convert]::ToBase64String($guidToBytes)
}

$restPayload = @{
    "keyCredentials" = @($mySecret)
}

$restPayload.Add("requiredResourceAccess",@($ConfigurationData.RequiredResourceAccess,$ConfigurationData.RequiredResourceAccessAZ))

$restPayload = ConvertTo-Json -InputObject $restPayload -Depth 4

$token = Get-AuthorizationToken -TenantName $tenantName

Write-Output "ExpiresOn: $($token.ExpiresOn.LocalDateTime)"

$authorizationHeader = @{
    "Content-Type"  = "application/json"
    "Authorization" = $token.AccessToken
}

$restUri = "https://$($ConfigurationData.GraphAPI.URL)/$($tenantName)/applications/$($AzureRmADApplication.ObjectId)?api-version=$($ConfigurationData.GraphAPI.Version)"

$restResourceAccess = Invoke-RestMethod -Uri $restUri -Headers $authorizationHeader -Method GET | Select -ExpandProperty requiredResourceAccess

If ($restResourceAccess.resourceAppId -notcontains $ConfigurationData.RequiredResourceAccess.resourceAppId)
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
        If ($resourceAccess.resourceAppId -eq $ConfigurationData.RequiredResourceAccess.resourceAppId)
        {
            $resourceAccess = ($Resource | Select -ExpandProperty resourceAccess).id

            $updateResourceAccess = $False
            ForEach ($id in $ConfigurationData.RequiredResourceAccess.resourceAccess.id)
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

ForEach ($DllFile in $ConfigurationData.AzureSDK.Dlls)
{
    Write-Output "Removing: $($DllFile)"
    Remove-Item -Path "$($ConfigurationData.LocalPath)\$($DllFile)" -Force -ErrorAction SilentlyContinue
}
#endregion

$Measure.Stop()

Write-Output ""
Write-Output ""
Write-Output "Browse to the following URL to initialize the application:"
Write-Host "https://$($DeploymentName).$($ConfigurationData.AzureRmDomain)/inbox.aspx" -ForegroundColor Green

Write-Output ""
Write-Output "--------------------------------------------------------------------------------"
Write-Output "Completed in $(($Measure.Elapsed).TotalSeconds) seconds"