# Helper function to handle exit with user acknowledgment and display errors
function Exit-WithAcknowledgment {
    param(
        [string]$message,
        [string]$errorMessage
    )
    Write-Host $message
    if ($errorMessage) {
        Write-Host "Error: $errorMessage"
    }
    Read-Host -Prompt "Press Enter to acknowledge and exit" | Out-Null
    exit
}

function ConvertFrom-NexthinkNql {
    param (
        [Parameter(Mandatory=$true)]$nql_data_raw,
        [switch]$nql_export
    )

    if($nql_export.IsPresent){

        $nql_data_raw = Invoke-WebRequest -Uri $nql_data_raw.resultsFileUrl

        $nql_data_raw = $nql_data_raw.RawContent.Split('"user.name","user.uid"')[1]
        $nql_data_raw = $nql_data_raw.Replace('"', '').Replace(' ','')
        $nql_data_raw = $nql_data_raw -split "\n"
        $nql_data_raw = $nql_data_raw[1..$($nql_data_raw.count - 1)]

        $nql_data = $nql_data_raw | ForEach-Object {
            
            try{
                $element = $_.Split(","); 
                @{"SamAccountName"=$element[0].SubString(0, $element[0].IndexOf("@")); "uid" = $element[1]}
            }
            catch{}
        }
    }
    else{

        $nql_data = $nql_data_raw.data | ForEach-Object {

            try{
                
                @{"SamAccountName"=$_[0].SubString(0, $_[0].IndexOf("@")); "uid" = $_[1]}
            }
            catch{}
        
        }
        
    }

    return $nql_data
    
}

function Get-NexthinkUIDExport {
    param (
        [Parameter(Mandatory=$true)][String]$NexthinkType,
        [Parameter(Mandatory=$true)]$auth,
        [Parameter(Mandatory=$true)]$token,
        [String]$exportID = $null,
        [String]$UIDExportName = $null,
        [String]$Export_path = $pwd.Path,
        [String]$Large_Query_ID,
        [switch]$large_Query
    )

    $nql_response = $null
    $return_token = $null
    $create_file = $false

    $wait = $true
    $nql_Exp_Key = $null
    $nql_data = $null

    New-Variable -Name UIDExportVairableName -Value @{'user'='Nexthink_UserUIDExport'; 'device'='Nexthink_DeviceUIDExport'; 'package'='Nexthink_PackageUIDExport'; 'binary'='Nexthink_BinaryUIDExport'} -Option ReadOnly
    New-Variable -Name UIDExportVairableValue -Value @{'user'='get_nexthink_user_uids'} -Option ReadOnly

    Write-Host "large_Query: $($large_Query.IsPresent)"
    If(-not $large_Query.IsPresent){
        If(-not $UIDExportName){

            $UIDExportName = $UIDExportVairableName[$NexthinkType]

        }

        try{

            $file = Get-ChildItem -Path $Export_path -Filter "$($UIDExportVairableValue[$NexthinkType]).csv" -ErrorAction SilentlyContinue
            $content = Get-Content -Path $file -ErrorAction SilentlyContinue | ConvertFrom-Csv -ErrorAction SilentlyContinue
        }
        catch{
            $content = $null
        }

        Write-Host "File Exists: $($file.Exists)"
        Write-Host "File Date:   $($file.CreationTime.Date.DayOfYear -eq $(Get-Date).Date.DayOfYear)"
        Write-Host "content:     $('' -ne $content)"
        Write-Host $($($file.Exists) -and $(($file.CreationTime.Date.DayOfYear -eq $(Get-Date).Date.DayOfYear) -and $('' -ne $content)))

        if($file.Exists -and $($file.CreationTime.Date.DayOfYear -eq $(Get-Date).Date.DayOfYear) -and $('' -ne $content)){
            
            Remove-Item $file -ErrorAction SilentlyContinue
            $nql_data = $content

        }
        else{
            Write-Host "Executing NQL query for $($UIDExportVairableValue[$NexthinkType])..."
            $nql_body = @{
                "queryId" = "#$($UIDExportVairableValue[$NexthinkType])"
            }
            $create_file = $true
        }
    }
    else{
        Write-Host "Executing NQL query for $($Large_Query_ID)..."
        $nql_body = @{
            "queryId" = "#$($large_Query_ID)"
        }
    }

    if($null -eq $nql_data){

        $nql_response, $return_token = Invoke-NexThink -token $token -apiuri $auth.nqlExp -Accept 'application/json'  -Method 'Post' -Body $nql_body
        if($null -ne $return_token) { $token = $return_token }

        $wait_start = Get-Date

        while($wait){

            Start-Sleep -Seconds 1 

            if($null -ne $nql_Exp_Key){

                $nql_response, $return_token = Invoke-NexThink -token $token -apiuri $nql_status_api -Accept 'application/json' -Method 'GET'
                if($null -ne $return_token) { $token = $return_token }

            }

            if($($nql_response | Get-Member).Name -contains 'exportId'){

                $nql_Exp_Key = $nql_response.exportId
                $nql_status_api = "$($auth.nqlStat)$($nql_Exp_Key)"
            
            }
            elseif($($nql_response | Get-Member).Name -notcontains 'exportId' -and $('' -ne $nql_Exp_Key)){

                if($nql_response.status -in 'SUBMITTED', "IN_PROGRESS"){
                    Write-Host "Waiting for nql export to complete"
                }
                elseif($nql_response.status -eq 'COMPLETED'){

                    $nql_data = ConvertFrom-NexthinkNql -nql_data_raw $nql_response -nql_export

                }
                elseif($nql_response.status -eq 'ERROR'){
                    Write-Host "Request Errored out - $($nql_response.errorDescription)"
                }

                if($($nql_response.status -in 'COMPLETED', 'ERROR') -or $(((Get-Date) - ($wait_start)).TotalSeconds -ge 300)){ 
                    $wait=$false 
                }
            }
        }
    }

    if($create_file){

        $file | Remove-Item -ErrorAction SilentlyContinue -Force
        $nql_data | Export-Csv -Path "$Export_path\$($UIDExportVairableValue[$NexthinkType]).csv" -Verbose

    }

    return $nql_data, $return_token
    
}

# Function to retrieve the token
function Get-ApiToken {
    param(
        [string]$clientID,
        [string]$clientKey,
        [string]$tokenUri
    )

    # Encode the client ID and client key in Base64
    $authString = "${clientID}:${clientKey}"
    $encodedAuthString = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($authString))

    # Prepare headers for token generation
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $encodedAuthString")

    # Request the token
    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenUri -Method 'POST' -Headers $headers
        return @{"token"=$tokenResponse.access_token; "timestamp"=$(Get-Date)}
    } catch {
        Exit-WithAcknowledgment "Failed to retrieve token from the API. Please check your Client ID and Client Key." $_.Exception.Message
    }
}

function Get-AuthInfo {
    param (
        [string]$path=".\auth.json"
    )

    $authInfoStatus = 0x0
    
    if(Test-Path $path){

        try{
            $authInfo = Get-Content $path | ConvertFrom-Json

            if($null -eq $authInfo.clientID){$authInfoStatus += 0x1}
            if($null -eq $authInfo.clientKey){$authInfoStatus += 0x2}
            if($null -eq $authInfo.tokenUri){$authInfoStatus += 0x4}
            if($null -eq $authInfo.apiUri){$authInfoStatus += 0x8}

            if($authInfoStatus -eq 0x0){
                Write-Host "Auth Info Successuflly Loaded"
                return $authInfo
            }
            else{
                Exit-WithAcknowledgment "Missing Auth Info exitig with error $authInfoStatus" -errorMessage $_.Exception.Message
            }

        }
        catch{
            Exit-WithAcknowledgment "Failed to read Auth Info" -errorMessage $_.Exception.Message
        }

    }
    else{
        Exit-WithAcknowledgment "Failed to load Auth Info" -errorMessage $_.Exception.Message
    }

}

function Test-NexThinkToken{
    param(
        [Parameter(Mandatory=$true)][System.Collections.Hashtable]$token,
        [string]$apiUri,
        [ValidateRange(1, 900)][Int16]$ageThreshold = 830,
        [switch]$testConnection
    )

    $token_value = $token.token
    $token_age = $($(Get-Date) - $token.timestamp).TotalSeconds
    $error_value = 0x0

    if($token_age -ge $ageThreshold){  
        Write-Host "Token Expired"
        $error_value =+ 0x1
    }
    
    if($testConnection.IsPresent){
        if($null -ne $apiUri){
            $response_result = Invoke-NexThink -token $token_value -apiuri $apiUri -test

            if($response_result -eq 0x0){
                Write-Host "Connect Test Passed"
            }
            else{
                Write-Host "Connect Test Failed - error_value: $response_result"
                $error_value =+ 0x4
            }
        }
        else{
            Write-Host "URI Not provided"
            $error_value =+ 0x2
        }
    }

    return $error_value
}
function Invoke-NexThink {
    param (
        [switch]$test,
        [Parameter(Mandatory=$true)][System.Collections.Hashtable]$token,
        [Parameter(Mandatory=$true)][string]$apiuri,
        [Parameter(Mandatory=$true)][string]$Method,
        [Parameter(Mandatory=$true)][string]$Accept,
        $body = $null
    )

    $return_token = $null
    $token_errorValue = Test-NexThinkToken -token $token

    if($token_errorValue -ne 0x0){
        $authInfo = Get-AuthInfo
        $token = Get-ApiToken -clientID $authInfo.clientID -clientKey $authInfo.clientKey -tokenUri $authInfo.tokenUri
        $return_token = $token
    }

    if($test.IsPresent){

        $error_value = 0x0

        # Perform an initial test connection using the token
        $testBody = @{
            "enrichments" = @()
            "domain" = "test_connection"
        } | ConvertTo-Json

        # Try connection and ignore any response other than 403
        try {
            $response = Invoke-RestMethod -Uri $apiuri -Method POST -Headers $apiHeaders -Body $testBody -ErrorAction Stop
            Write-Host "Connection test passed (ignoring response code)."
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 403) {
                Write-Host "Failed to connect to the Nexthink API with the initial token. Status: 403 Forbidden."
                $error_value =+ 0x1
            } else {
                Write-Host "Initial connection test passed (non-403 error ignored)."
            }
        }

        return $error_value

    }
    else{

        if($null -ne $body){    
            
            $apiHeaders = @{
                "Content-Type" = "application/json"
                "Accept" = "$Accept"
                "Authorization" = "Bearer $($token.token)"
                }

            try{
                Write-Host $body['enrichments']
            }
            catch{
                Write-Host $body
            }

            $body = $body | ConvertTo-Json -Depth 5

            $response = Invoke-RestMethod -Uri $apiuri -Method $Method -Headers $apiHeaders -Body $body
        }
        else{
            $apiHeaders = @{
                "Accept" = "$Accept"
                "Authorization" = "Bearer $($token.token)"
                }

            $response = Invoke-RestMethod -Uri $apiuri -Method $Method -Headers $apiHeaders
        }
    }

    return $response, $return_token
    
}

function New-NexhtinkEnrichmentBody {
    param(
        [Parameter(Mandatory=$true)]$targets,            # List of target accounts for enrichment
        [Parameter(Mandatory=$true)]$ParameterSets,      # Dictionary of parameter sets for enrichment
        [Parameter(Mandatory=$true)]$nql,               # NQL query results containing user data
        [Parameter(Mandatory=$true)]$type,              # Type of the object being enriched (e.g., 'user')
        [switch]$_true                                  # Optional switch to influence value selection
    )

    # Mapping 'type' to the correct Nexthink field (for user, it's 'user/user/uid')
    $type_values = @{'user' = 'user/user/uid'}

    # Inform user that the filtering process is starting
    Write-Host "Filtering targets based on the NQL results..."

    # Parse targets from the NQL data, matching the username with SamAccountName and selecting UID
    $parsed_Targets = $nql | Where-Object {$_.SamAccountName -in $targets.SamAccountName} | Select-Object -Property uid

    # Initialize an array to store enrichments, with the same count as parsed targets
    $wrapper = [Object[]]::new($parsed_Targets.count)
    $i = 0;

    # Inform the user that the enrichment creation process has started
    Write-Host "Creating enrichments for each parsed target..."

    # Loop through each parsed target to create an enrichment entry
    $parsed_Targets | ForEach-Object {

        # Create the identification object with the type (user/user/uid) and target UID
        $identification = @(@{"name" = $($type_values[$type]);"value" = $_.uid;})

        # Initialize an array to hold fields for the current target's enrichment
        $fields = [Object[]]::new($ParameterSets.keys.count)
        $j = 0;

        # Loop through each parameter set and create a field entry
        Write-Host "Processing parameter sets for target UID..."

        $ParameterSets.keys | ForEach-Object {
           # Create a field entry, with values depending on the $_true flag
            if($_true.IsPresent){
                $fields[$j] = @{"name" = "$($_)"; "value" = "$($ParameterSets[$_][1])";}
            }
            else{
                $fields[$j] = @{"name" = "$($_)"; "value" = "$($ParameterSets[$_][0])";}
            }

           $j++
        }

        # Add the enrichment entry to the array of enrichments
        $wrapper[$i] = @{"identification" = $identification; "fields" = $fields;}
        $i++
    }

    $enrichments = @{'enrichments' = $wrapper; "domain" = "custom_fields";}

    # Inform user that the enrichment process is completed
    Write-Host "All enrichments have been created."

    # Convert the enrichment array to JSON for further processing
    $op_body = $enrichments

    # Return both the total number of targets and the JSON body
    return $op_body
}

function Invoke-NexThinkEnrichment {
    param(
        # NexthinkParemeterSets: Comma-separated key/value pairs formatted as "key=value"
        [parameter(Mandatory=$true)][string]$NexthinkParemeterSets,

        # NexthinkObjectType: Type of object being processed (e.g., 'user', 'device', etc.)
        [parameter(Mandatory=$true)][string]$NexthinkObjectType,

        # TargetObjects: Comma-separated list of target objects to process (e.g., "object1=param1,object2=param2")
        [parameter(Mandatory=$true)][string]$TargetObjects,

        [parameter(Mandatory=$false)][String]$csvPath,

        [switch]$test,
        [switch]$csv,
        [String]$ID_Type = "SamAccountName"
    )

    # Temporary storage for parameter sets, AD objects, and NQL queries
    $temp_ParameterSet = @{}
    $temp_ADObjects = [System.Collections.ArrayList]::new()
    $temp_NqlQueries = [System.Collections.ArrayList]::new()
    $final_Objects = [System.Collections.ArrayList]::new()
    $nql_reference = [System.Collections.Hashtable]::new()

    # Define valid object types for Nexthink, locked as ReadOnly
    $ObjectTypes = @{'device'='device/device/#'; 'user'=@{'var_path'='user/user/#'; 'nql_query'='#get_nexthink_user_uids'}; 'package'='packages/packages/#'; 'binary'='binary/binary/#'}

    # Obtain authentication information and API token
    Write-Host "Fetching authentication information..."
    $auth = Get-AuthInfo

    Write-Host "Retrieving API token..."
    $token = Get-ApiToken -clientID $auth.clientID -clientKey $auth.clientKey -tokenUri $auth.tokenUri

    # Parse Nexthink parameter sets and store in a hashtable
    Write-Host "Parsing Nexthink parameter sets..."
    $parsed_NexthinkParemeterSets = $NexthinkParemeterSets.Split(',')
    $parsed_NexthinkParemeterSets | ForEach-Object {
        $key, $value = $_.Split('=').Replace(' ','')
        $temp_ParameterSet[$ObjectTypes[$NexthinkObjectType]['var_path']+$($key)] = $value.Split('/')
    }
    $parsed_NexthinkParemeterSets = $temp_ParameterSet

    # Validate the provided NexthinkObjectType
    Write-Host "Validating Nexthink object type..."
    if($ObjectTypes.keys -notcontains $NexthinkObjectType) {
        Exit-WithAcknowledgment "Invalid NexthinkObjectType inputted" -errorMessage $null
    }

    # Parse TargetObjects and associate them with NQL queries and AD objects
    Write-Host "Parsing target objects and associating NQL queries..."
    $TargetObjects = $TargetObjects.Split(',').Replace(' ','')
    $TargetObjects | ForEach-Object {
        $ad, $nql = $_.split('=')
        $void = $temp_NqlQueries.Add($nql)
        $void = $temp_ADObjects.Add($ad)
    }

    # Map AD objects and NQL queries into a final hashtable for processing
    Write-Host "Mapping AD objects and NQL queries into final object set..."
    $temp_ADObjects | ForEach-Object {
        $void = $final_Objects.Add(@{'ad'=$_; 'nql'=$temp_NqlQueries[$temp_ADObjects.IndexOf($_)]})
    }

    # Process AD objects and group membership
    Write-Host "Processing AD objects and handling group membership..."
    $final_Objects | ForEach-Object {

        if($csv.IsPresent -eq $false){

            $group = Get-ADObject -LDAPFilter "(Name=$($_['ad']))"

            Write-Host "LDAP: `"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$group))`""

            $users = Get-ADUser -LDAPFilter "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=$group))" -Properties DistinguishedName, SamAccountName, Mail, ObjectClass
        }

        else{

            $users = [System.Collections.ArrayList]::new()

            $csv_data = Get-Content -Path $csvPath
            $csv_data = $csv_data | ConvertFrom-Csv | Select-Object -Property Username

            if($ID_Type -eq "SamAccountName"){
                $csv_data.Username | ForEach-Object {

                    try {
                        $current_user = Get-ADUser -Identity $(($_ -split "@")[0]) -Properties DistinguishedName, SamAccountName, Mail, ObjectClass -ErrorAction SilentlyContinue
                        Write-Host -ForegroundColor Red "$_ Found"
                    }
                    catch {
                        Write-Host -ForegroundColor Red "$_ Not Found"
                        $current_user = ""

                    }

                    if($current_user -ne ""){
                        $void = $users.add($current_user)
                    }

                }
            }
            if($ID_Type -eq "Email"){

                $csv_data.Username | ForEach-Object {

                    try {
                        $current_user = Get-ADUser -LDAPFilter "(mail=$_)" -Properties DistinguishedName, SamAccountName, Mail, ObjectClass -ErrorAction SilentlyContinue
                        Write-Host -ForegroundColor Red "$_ Found"
                    }
                    catch {
                        Write-Host -ForegroundColor Red "$_ Not Found"
                        $current_user = ""

                    }

                    if($current_user -ne ""){
                        $void = $users.add($current_user)
                    }

                }

            }

        }

        $users

        $final_Objects[$final_Objects.IndexOf($_)]['ad'] = $users
        
    }

    # Fetch AD object details and execute NQL queries for each object
    Write-Host "Fetching AD object details and executing NQL queries..."
    $final_Objects | ForEach-Object {

        if($_['ad'].count -ge 900){

            $nql_data, $return_token = Get-NexthinkUIDExport -NexthinkType $NexthinkObjectType -auth $auth -token $token -large_Query_ID "$($final_Objects[$_]['nql'])" -large_Query
        
        }
        else{

            $body = @{
                "queryId" = "#$($_['nql'])"
            }

            $nql_response, $return_token = Invoke-NexThink -token $token -apiuri $auth.nqlUri -Method "POST" -Accept "application/json" -body $body

            Write-Host "NQL_Resposne: $nql_response"

            $nql_data = ConvertFrom-NexthinkNql -nql_data_raw $nql_response
            
        }

        if($null -ne $return_token) { $token = $return_token }

        $final_Objects[$final_Objects.IndexOf($_)]['nql'] = $nql_data

    }

    $nql_data, $return_token = Get-NexthinkUIDExport -NexthinkType $NexthinkObjectType -auth $auth -token $token

    $nql_reference = $nql_data

    if($null -ne $return_token) { $token = $return_token }

    # Check if AD objects are missing
    Write-Host "Checking for missing AD objects..."
    $final_Objects | ForEach-Object {
        if($_['ad'].count -eq 0) {
            Write-Host "No AD Objects provided for $_"
            Exit-WithAcknowledgment -message "No AD Objects Provided for $_"
        }
    }

    # Compare AD objects with NQL response and mark changes
    #Write-Host "Comparing AD objects with NQL response..."
    $final_Objects | ForEach-Object {

        $key = $_

        Write-Host "Nql: $($key['nql'])"

        # Mark additions and deletions based on the comparison
        $add = $key['ad'] | Where-Object {$_.SamAccountName -notin $($key['nql'].SamAccountName) -and $_.SamAccountName -in $nql_reference.SamAccountName}
        $sub = $key['nql'] | Where-Object {$_.SamAccountName -notin $($key['ad'].SamAccountName)}

        $add | ForEach-Object {

            $add_body = New-NexhtinkEnrichmentBody -targets $_ -ParameterSets $parsed_NexthinkParemeterSets -nql $nql_reference -type $NexthinkObjectType -_true

            if($test.IsPresent -eq $false){
                $nql_response, $return_token = Invoke-NexThink -token $token -apiuri $auth.apiUri -Accept 'application/json' -Method 'Post' -Body $add_body
            }

            # If a new token is returned, update the current token
            if($null -ne $return_token) { $token = $return_token }

            Write-Host "Add Op Result: $($_.SamAccountName) $nql_response" -ForegroundColor Yellow

        }

        $sub | ForEach-Object {

            $sub_body = New-NexhtinkEnrichmentBody -targets $_ -ParameterSets $parsed_NexthinkParemeterSets -nql $nql_reference -type $NexthinkObjectType

            if($test.IsPresent -eq $false){
                $nql_response, $return_token = Invoke-NexThink -token $token -apiuri $auth.apiUri -Accept 'application/json' -Method 'Post' -Body $sub_body

            }
            
            # If a new token is returned, update the current token
            if($null -ne $return_token) { $token = $return_token }

            Write-Host "Sub Op Result: $($_.SamAccountName) $nql_response" -ForegroundColor Yellow

        }

        Write-Host "Total Users Added: $($add.count)"
        Write-Host "Total Users Removed: $($sub.count)"
        Write-Host "Total User Excluded: $($($Key['ad'] | Where-Object {$_.SamAccountName -notin $nql_reference.SamAccountName}).count)"
    }

    Write-Host "NexThink enrichment process completed."
}