﻿$Location                  = "northeurope"
$Security_Admins           = "ADMPEER"
$DynamicsAXApiId           = "axtestdynamics365aos-adl2.cloudax.dynamics.com"

$Webclient                       = New-Object System.Net.Webclient
$Webclient.UseDefaultCredentials = $true
$Webclient.Proxy.Credentials     = $Webclient.Credentials
$Webclient.Encoding              = [System.Text.Encoding]::UTF8
$Webclient.CachePolicy           = New-Object System.Net.Cache.HttpRequestCachePolicy([System.Net.Cache.HttpRequestCacheLevel]::NoCacheNoStore)

$scriptPath = ($Webclient.DownloadString('https://raw.githubusercontent.com/djpericsson/AzureWebAppDeploy/master/App-RegistrationDeployment.ps1'))
Invoke-Command -ScriptBlock ([scriptblock]::Create($scriptPath)) -ArgumentList $Location,$Security_Admins,$DynamicsAXApiId