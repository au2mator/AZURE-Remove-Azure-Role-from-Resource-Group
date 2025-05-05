#########
# au2mator PS Services
# Type: PowerShell Question
#
# Title: AZURE - GetUserRoles
#
#################

#Param
param ($au2matorhook)

#Environment
[string]$CredentialStorePath = "C:\_SCOworkingDir\TFS\PS-Services\CredentialStore" #see for details: https://click.au2mator.com/PSCreds/?utm_source=github&utm_medium=social&utm_campaign=AZURE_RemoveResourceGroupRole&utm_content=PS1
[string]$LogPath = "C:\_SCOworkingDir\TFS\PS-Services\AZURE - Remove Role from Azure Resource Group\Logs"
[string]$LogfileName = "Question-GetUserRoles"

#Azure Rest Cred
$AzureRestAPICred_File = "AzureRestCreds.xml"
$AzureRestAPICred = Import-CliXml -Path (Get-ChildItem -Path $CredentialStorePath -Filter $AzureRestAPICred_File).FullName
$AzureRestAPI_clientId = $AzureRestAPICred.clientId
$AzureRestAPI_clientSecret = $AzureRestAPICred.clientSecret
$AzureRestAPI_tenantID = $AzureRestAPICred.tenantID

#MS Graph Cred
$MSGraphAPICred_File = "MSGraphAPICred.xml"
$MSGraphAPICred = Import-CliXml -Path (Get-ChildItem -Path $CredentialStorePath -Filter $MSGraphAPICred_File).FullName
$MSGraphAPI_clientId = $MSGraphAPICred.clientId
$MSGraphAPI_clientSecret = $MSGraphAPICred.clientSecret
$MSGraphAPI_tenantID = $MSGraphAPICred.tenantName

#API Version for Rest Cals
$apiversion = "2018-07-01"

#Parameters and Question Input
$au2matorJsonData = $au2matorhook | ConvertFrom-Json

$subscriptionID = $au2matorJsondata.c_Subscription
$RessourceGroupName = $au2matorJsondata.c_ResourceGroup
$User = $au2matorJsondata.c_User


#region Functions
function Write-au2matorLog {
    [CmdletBinding()]
    param
    (
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$Type,
        [string]$Text
    )

    # Set logging path
    if (!(Test-Path -Path $logPath)) {
        try {
            $null = New-Item -Path $logPath -ItemType Directory
            Write-Verbose ("Path: ""{0}"" was created." -f $logPath)
        }
        catch {
            Write-Verbose ("Path: ""{0}"" couldn't be created." -f $logPath)
        }
    }
    else {
        Write-Verbose ("Path: ""{0}"" already exists." -f $logPath)
    }
    [string]$logFile = '{0}\{1}_{2}.log' -f $logPath, $(Get-Date -Format 'yyyyMMdd'), $LogfileName
    $logEntry = '{0}: <{1}> <{2}> <{3}> {4}' -f $(Get-Date -Format dd.MM.yyyy-HH:mm:ss), $Type, $RequestId, $Service, $Text
    Add-Content -Path $logFile -Value $logEntry
}

#endregion Functions

try {
    Write-au2matorLog -Type INFO -Text "Try to connect to Azure Rest API"
    
    $param = @{
        Uri    = "https://login.microsoftonline.com/$AzureRestAPI_tenantID/oauth2/token?api-version=$apiversion";
        Method = 'Post';
        Body   = @{ 
            grant_type    = 'client_credentials'; 
            resource      = 'https://management.core.windows.net/'; 
            client_id     = $AzureRestAPI_clientId; 
            client_secret = $AzureRestAPI_clientSecret
        }
    }
      
    $result = Invoke-RestMethod @param
    $token = $result.access_token
      
    $headers = @{
        "Authorization" = "Bearer $($token)"
        "Content-type"  = "application/json"
    }

    try {
        Write-au2matorLog -Type INFO -Text "Try to connect to MS GRAPH API"

        #Connect to GRAPH API
        $tokenBody = @{  
            Grant_Type    = "client_credentials"  
            Scope         = "https://graph.microsoft.com/.default"  
            Client_Id     = $MSGraphAPI_clientId  
            Client_Secret = $MSGraphAPI_clientSecret  
        }   
      
        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$MSGraphAPI_tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody  
    
        $MSGraphAPI_headers = @{
            "Authorization" = "Bearer $($tokenResponse.access_token)"
            "Content-type"  = "application/json"
        }
        try {
            Write-au2matorLog -Type INFO -Text "Try to get User ID"

            $URLMember = "https://graph.microsoft.com/v1.0/users/$User"
            $ResultUser = Invoke-RestMethod -Headers $MSGraphAPI_headers -Uri $URLMember -Method Get

            try {
                Write-au2matorLog -Type INFO -Text "Try to get Assignments and Roles"
                $URL = "https://management.azure.com/subscriptions/$subscriptionID/resourceGroups/$RessourceGroupName/providers/Microsoft.Authorization/roleAssignments?`$filter=principalId eq '$($ResultUser.id)'&api-version=$apiversion"
                $Assignments = Invoke-RestMethod -Method GET -URI $URL -headers $headers 

                $URL = "https://management.azure.com/subscriptions/$subscriptionID/resourceGroups/$RessourceGroupName/providers/Microsoft.Authorization/roleDefinitions?api-version=$apiversion"
                $Roles = Invoke-RestMethod -Method GET -Uri $URL -Headers $headers

                $ReturnList = @()

                foreach ($Role in $Roles.value)
                {
                    if ($Assignments.value.properties.roleDefinitionId -contains $role.id)
                    {
                        $PSObject = New-Object -TypeName PSObject
                        
                        
                        $PSObject | Add-Member -MemberType NoteProperty -Name Name -Value $Role.properties.roleName
                        $PSObject | Add-Member -MemberType NoteProperty -Name Type -Value $Role.properties.type
                        $PSObject | Add-Member -MemberType NoteProperty -Name description -Value $Role.properties.description
    
                
                        $ReturnList += $PSObject
                    }
                }
            }
            catch {
                Write-au2matorLog -Type ERROR -Text "Error to get Subscriptions"
                Write-au2matorLog -Type ERROR -Text $Error
    
                $au2matorReturn = "Error to get Subscriptions, Error: $Error"
                $TeamsReturn = "Error to get Subscriptions" #No Special Characters allowed
                $AdditionalHTML = "Error to get Subscriptions
        <br>
        Error: $Error
            "
                $Status = "ERROR"
            }
        
        }
        catch {
            Write-au2matorLog -Type ERROR -Text "Failed to get User ID"
            Write-au2matorLog -Type ERROR -Text $Error

            $au2matorReturn = "Failed to get User ID, Error: $Error"
            $TeamsReturn = "Failed to get User ID" #No Special Characters allowed
            $AdditionalHTML = "Failed to get User ID
    <br>
    Error: $Error
        "
            $Status = "ERROR"
        }

    }
    catch {
        Write-au2matorLog -Type ERROR -Text "Failed to connect to MS GRAPH API"
        Write-au2matorLog -Type ERROR -Text $Error

        $au2matorReturn = "Failed to connect to MS GRAPH API, Error: $Error"
        $TeamsReturn = "Failed to connect to MS GRAPH API" #No Special Characters allowed
        $AdditionalHTML = "Failed to connect to MS GRAPH API
    <br>
    Error: $Error
        "
        $Status = "ERROR"
    }
}

catch {
    Write-au2matorLog -Type ERROR -Text "Failed to connect to Azure Rest API"
    Write-au2matorLog -Type ERROR -Text $Error

    $au2matorReturn = "Failed to connect to Azure Rest API, Error: $Error"
    $TeamsReturn = "Failed to connect to Azure Rest API" #No Special Characters allowed
    $AdditionalHTML = "Failed to connect to Azure Rest API
    <br>
    Error: $Error
        "
    $Status = "ERROR"
}



return $ReturnList