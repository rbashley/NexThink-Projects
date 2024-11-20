<#
.SYNOPSIS
Reports user information.

.DESCRIPTION
Collects and reports information on the currently logged-in user sessions on a Windows system. This script filters sessions based on specified criteria (session type and state), retrieves details such as the username, SID, session state, and hostname, and writes the output to Nexthink's data layer for remote monitoring and action purposes. If multiple users match the criteria, only the first is reported, along with the total count of matching users.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID  Label                           Type            Description
1   Username                        String          Indicates the Username
2   SID                             String          Indicates the SID
3   Name                            String          Indicates the Name
4   Hostname                        String          Indicates the Hostname

.FURTHER INFORMATION

.NOTES
Context:            System
Version:            1.0
Created:            07 Nov 2024
Author:             Randall Ashley at Wayfair Inc., USA (rashley@wayfair.com)
#>

param(
    [string]$session_type = 'console',
    [string]$State = 'Active'
)

# Load Nexthink assembly and check for load success
try {
    Add-Type -Path "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"
} catch {
    Write-Error 'Failed to load Nexthink assembly'
    exit 101 # Unique exit code for assembly load failure
}

# Check WMI Repository health
try {
    $wmiRepoStatus = Get-WmiObject -Class __Namespace -Namespace 'root' -ErrorAction Stop
} catch {
    Write-Error 'WMI Repository check failed'
    exit 102 # Unique exit code for WMI Repository failure
}

# Retrieve session information
try {
    $quser = (quser).split([System.Environment]::NewLine)
} catch {
    Write-Error 'Failed to retrieve session information via quser'
    exit 103 # Unique exit code for quser failure
}

# Calculate total users found from quser
$total_users = if ($quser.length -gt 1) { $quser.Length - 1 } else { 0 }
[Nxt]::WriteOutputUInt32('TotalUsers', $total_users)

$quser_array = [System.Collections.ArrayList]::new()

if ($total_users -gt 0) {
    for ($i = 1; $i -lt $quser.length; $i++) {
        $quser_line = $quser[$i] -split '\s{2,}'  # Splits based on two or more spaces

        # Retrieve user data from WMI
        try {
            $wmi_response = Get-WmiObject -Class Win32_UserAccount -Filter "Name=`'$($quser_line[0].replace('>', ''))`'" -ErrorAction Stop
        } catch {
            Write-Error "Failed to retrieve WMI data for user $($quser_line[0])"
            exit 104 # Unique exit code for WMI retrieval failure
        }

        $quser_object = [PSCustomObject]@{
            UserName     = $quser_line[0].replace('>', '')  # Removes leading ">" if present
            Session_Name = $quser_line[1]
            State        = $quser_line[3]
            Idle_Time    = $quser_line[4]
            SID          = $wmi_response.SID
            Name         = $wmi_response.FullName
            HostName     = $env:COMPUTERNAME
        }

        [void]$quser_array.add($quser_object)
    }
}

# Filter based on parameters
try {
    $filtered_array = @($quser_array | Where-Object { $_.Session_Name -cmatch $session_type -and $_.State -eq $State })
} catch {
    Write-Error 'Failed during filtering process'
    exit 105 # Unique exit code for filtering failure
}

$user_count = $filtered_array.Count
$top_user = if ($user_count -gt 0) { $filtered_array[0] } else { $null }

# Write output to Nexthink data layer with inline null handling
try {
    [Nxt]::WriteOutputUInt32('UserCount', $user_count)
    [Nxt]::WriteOutputString('UserName', $(if ($top_user.UserName -ne $null) { $top_user.UserName } else { '' }))
    [Nxt]::WriteOutputString('Session_Name', $(if ($top_user.Session_Name -ne $null) { $top_user.Session_Name } else { '' }))
    [Nxt]::WriteOutputString('State', $(if ($top_user.State -ne $null) { $top_user.State } else { '' }))
    [Nxt]::WriteOutputString('Idle_Time', $(if ($top_user.Idle_Time -ne $null) { $top_user.Idle_Time } else { '' }))
    [Nxt]::WriteOutputString('SID', $(if ($top_user.SID -ne $null) { $top_user.SID } else { '' }))
    [Nxt]::WriteOutputString('Name', $(if ($top_user.Name -ne $null) { $top_user.Name } else { '' }))
    [Nxt]::WriteOutputString('HostName', $(if ($top_user.HostName -ne $null) { $top_user.HostName } else { '' }))
} catch {
    Write-Error "Failed to write outputs to Nexthink data layer: $_"
    exit 106 # Unique exit code for Nexthink output failure
}

# General error handling
trap {
    Write-Error "An unexpected error occurred: $_"
    exit 107 # Generic error code for any unhandled exceptions
}