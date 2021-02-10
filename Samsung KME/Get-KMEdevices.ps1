<#
.SYNOPSIS
    This script gets devices from KME.
.DESCRIPTION
    This script uses assemblies created by Samsung to generate and sign JWT and access tokens with the keys.json file. To run this script you need a keys.json file downloaded from your
    Samsung Knox portal and a generated Client Identifier.
    All needed assemblies are stored in the "NotLoaded" folder and are copied to "SupportFiles" once the script runs.

    keys.json needs to be stored in "SupportFiles".
.NOTES
    Written by: Tobias Almen
    Version: 1.0
#>

$notLoaded = Get-ChildItem -Path "$PSScriptRoot\SupportFiles\NotLoaded" -File

#If assemblies has not benn copied to SupportFiles, copy each assembly
if ( -not (Test-Path -path "$PSScriptRoot\SupportFiles\*.dll")) {
    Write-Host -ForegroundColor Green "Copying assemblies to supportfiles"
    foreach ($file in $notLoaded) {
        Copy-Item -Path $file.FullName -Destination "$PSScriptRoot\SupportFiles" -Force
    }
}

sleep 2
function Get-SignedJwt {

    param(
        [Parameter(Mandatory = $true)]
        [string]$jsonPath,
        [string]$clientID
    )

    #Load assemblies
    Add-Type -Path "$PSScriptRoot\SupportFiles\Microsoft.CSharp.dll"
    Add-Type -Path "$PSScriptRoot\SupportFiles\Microsoft.IdentityModel.Logging.dll"
    Add-Type -Path "$PSScriptRoot\SupportFiles\System.Security.Cryptography.Cng.dll"
    Add-Type -Path "$PSScriptRoot\SupportFiles\Microsoft.IdentityModel.Tokens.dll"
    Add-Type -Path "$PSScriptRoot\SupportFiles\Microsoft.IdentityModel.JsonWebTokens.dll"
    Add-Type -Path "$PSScriptRoot\SupportFiles\Newtonsoft.Json.dll"
    Add-Type -Path "$PSScriptRoot\SupportFiles\BouncyCastle.Crypto.dll"
    Add-Type -Path "$PSScriptRoot\SupportFiles\knoxAPIUtility.dll"

    #Generate signed JWT
    try {
        $script:signedClientId = [knoxAPIUtility.KnoxTokenUtility]::generateSignedClientIdentifierJWT("$jsonPath", "$clientID")
    }
    catch {
        Write-Error $_.Exception | format-list -force
        Break
    }
}

function Get-AccessToken {

    param(
        [Parameter(Mandatory = $true)]
        [string]$jsonPath
    )

    #Get json content from keys.json
    $keyJson = Get-Content $jsonPath | ConvertFrom-Json
    $pubKey = $keyJson.public

    #Build body for access token request
    $body = [ordered]@{
        clientIdentifierJwt          = "$signedClientId"
        base64EncodedStringPublicKey = "$pubKey"
        #validityForAccessTokenInMinutes = 30
    }

    #Convert body to json format
    $requestObject = $body | ConvertTo-Json

    $requestbody = @"
$requestObject
"@

    #Set access token request headers
    $Headers = @{’Content-type’ = ‘application/json’ }

    #If JWT has been generated, request access token
    if ($body.clientIdentifierJwt) {
        $tokenquery = Invoke-RestMethod -Method Post -Uri "https://eu-kcs-api.samsungknox.com/ams/v1/users/accesstoken" -Body $requestBody -Headers $Headers
    }
    else {
        Write-Error "Not able to get JWT"
    }

    #If access token request failed, break
    if (!$tokenquery.accesstoken) {
        Write-Error "Not able to get access token"
        Break
    }
    else {
        try {
            $script:signedAccessToken = [knoxAPIUtility.KnoxTokenUtility]::generateSignedAccessTokenJWT("$jsonPath", $tokenquery.accessToken)
        }
        catch {
            Write-Error $_.Exception | format-list -force
            Break
        }
    }
}

#Generate JWT
Write-Host -ForegroundColor Cyan "Generating signed JWT"
Get-SignedJwt -jsonPath "$PSScriptRoot\SupportFiles\keys.json" -clientID "YOUR_CLIENT_ID"

sleep 2

#Get access token and sign with KnoxAPI utility
Write-Host -ForegroundColor Cyan "Getting access token and signing the token"
Get-AccessToken -jsonPath "$PSScriptRoot\SupportFiles\keys.json"

#Check if JTW and Token has been generated, if not, break
if (!$signedClientId -or !$signedAccessToken) {
    Write-Error "not able to generate signed JWT or access token"
    break
}

sleep 2

#If access token is generated get devices
if ($signedAccessToken) {
    $Headers = @{’Content-type’ = ‘application/json’; 'x-knox-apitoken' = "$signedAccessToken"; 'cache-control' = 'no-cache' }
    $devicequery = Invoke-RestMethod -Method Get -Uri "https://eu-kcs-api.samsungknox.com/kcs/v1/kme/devices/list" -Headers $Headers
    Write-Host -ForegroundColor Yellow "Found $($devicequery.totalCount) devices"
}