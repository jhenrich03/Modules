Function global:Get-ComputerData {
<#
.SYNOPSIS
Gets basic information of the specified computers..
.DESCRIPTION
This command uses WMI. WMI must be enabled and you must run this with admin rights for any remote computer.
.PARAMETER ComputerName
One or more computer names to query.
.EXAMPLE
Get-ComputerData -ComputerName localhost
#>
[cmdletbinding()]

param( 
[parameter(Mandatory=$True)]
[ValidateNotNullOrEmpty()]
[string[]]$ComputerName)

foreach ($computer in $computerName) {
    Write-Verbose "Getting data from $computer"
    Write-Verbose "Win32_Computersystem"
        $cs = Get-WmiObject -Class Win32_Computersystem -ComputerName $Computer 

        #decode the admin password status
        Switch ($cs.AdminPasswordStatus) {
            1 { $aps="Disabled" }
            2 { $aps="Enabled" }
            3 { $aps="NA" }
            4 { $aps="Unknown" }
        }

        #Define a hashtable to be used for property names and values
        $hash=@{
            Computername=$cs.Name
            Domain=$cs.Domain
            Model=$cs.Model
            Manufacturer=$cs.Manufacturer
        }

        Write-Verbose "Win32_Bios"
        $bios = Get-WmiObject -Class Win32_Bios -ComputerName $Computer 

        $hash.Add("SerialNumber",$bios.SerialNumber)
                
        Write-Verbose "Win32_OperatingSystem"
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
        $hash.Add("Version",$os.Version)
        $hash.Add("ServicePackMajorVersion",$os.ServicePackMajorVersion)
           
        #create a custom object from the hash table
        New-Object -TypeName PSObject -Property $hash
           
} #foreach

}

Function global:Disable-Account {
<#
 .SYNOPSIS
 Disables a user account, moves it to the Disabled Users OU, and removes it from all AD groups.
 .DESCRIPTION
 The Disable-Account function takes each user entered and disables it, moves it to the Disabled Users OU, and remove it from all AD groups. The input can either be a username or a persons full name.
 .EXAMPLE
 Disable-Account -User testuser
 .EXAMPLE
 'testuser' | Disable-Account
 .INPUTS
 System.String[]

 You can pipe a username or a persons full name to Disable-Account.
#>
    [CmdletBinding()]
    
    Param
    ( 
       [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
       [string[]]$User
    )
    
    Begin
    {
    }
    Process
    {
            foreach ($U in $User) {

                Write-Host "Checking if $U exists..."

                # Check if the user(s) exist
                if ($Name = Get-ADUser -Filter {(name -eq $U) -or (samaccountname -eq $U)}) {

                        # Check if the account is already disabled
                        if ($Name.Enabled) {
                       
                            # Disable the account
                            Disable-ADAccount -Identity $Name -Confirm:$false
                            Write-Host "$($Name.name)'s account has been disabled."
                            
                             # Get a list of all AD groups the user is a member of
                            $Groups = Get-ADPrincipalGroupMembership -Identity $Name | Where-Object Name -ne 'Domain Users'
                          
                            # Set the EAP as AD errors can't be suppressed with the EA parameter  
                            $ErrorActionPreference = 'SilentlyContinue'

                            # Remove the user from above groups
                            Remove-ADPrincipalGroupMembership -Identity $Name -MemberOf $Groups -Confirm:$false

                            $ErrorActionPreference = 'Continue'                                
                    
                            # Move the disabled account to the Disabled Users OU                 
                            Move-ADObject -Identity $Name -TargetPath "OU=Disabled Users,DC=mastersoncompany,DC=com" 
                            Write-Host "Moved $($Name.name)'s account to the 'Disabled Users' OU."
                    
                           
                            Write-Host "$($Name.name)'s account been disabled, moved, and removed from all AD groups."
                            
                        }
                                                                                  
                        else {
                            # If the account is already disabled, inform the user
                            Write-Warning "$($Name.name)'s account is already disabled."
                        }
                }
                                  
                else {
                # If the account doesn't exist, inform the user
                Write-Warning "$U is not a valid user."
                } 

            }

    }
    End
    {
    }
}

Function global:Get-FreeSpace {
<#
.SYNOPSIS
Gets disk information from one or more computers.
.DESCRIPTION
This command uses WMI, and can accept computer names, CNAME aliases,and IP addresses. 
WMI must be enabled and you must run this with admin rights for any remote computer.
.PARAMETER ComputerName
One or more names or IP addresses to query.
.EXAMPLE
Get-FreeSpace -computername localhost
#>
    [cmdletbinding()]

    param( 
    [Parameter(ValueFromPipeline=$True)]
    [String[]]$ComputerName = $env:COMPUTERNAME
    )

    BEGIN { 
    Write-Verbose "Getting disk information..."
    }

    PROCESS {

        $nfi = New-Object System.Globalization.CultureInfo -ArgumentList "en-us",$false
        $nfi.NumberFormat.PercentDecimalDigits = 0

            foreach ($computer in $ComputerName) {
            $computerU = $computer.ToUpper()

                Write-Verbose "Querying $computerU..."

                try {
                    $noerror = $true
                    $disks = Get-WmiObject win32_logicaldisk -ComputerName $computer -ErrorAction Stop
                }

                catch {
                $noerror = $false
                Write-Warning "$computerU is either an invalid computer name, or is offline."
                }

                if ($noerror) {
                    $disks = Get-WmiObject win32_logicaldisk -ComputerName $computer -filter "drivetype=3"
        
                        foreach ($disk in $disks) {

                            $hash = [ordered]@{
                                    'ComputerName'=$computerU;
                                    'Disk'=$disk.DeviceID;
                                    'FreeSpace(GB)'=$disk.freespace / 1gb -as [int];
                                    'Size(GB)'=$disk.size / 1gb -as [int];
                                    'PercentFree'=($disk.freespace / $disk.size).ToString("P",$nfi)
                            }

                $obj = New-Object -TypeName PSObject -Property $hash
                Write-Output $obj
                         }
                }
            }
     }

     END {
     Write-Verbose "Finished retrieving disk information."
     }
}

Function global:Get-MemoryUsage {
<#
.SYNOPSIS
Gets the current memory usage of the specified computers.
.DESCRIPTION
This command uses WMI. WMI must be enabled and you must run this with admin rights for any remote computer.
.PARAMETER ComputerName
One or more computer names to query.
.EXAMPLE
Get-MemoryUsage -ComputerName localhost
#>
    [CmdletBinding()]
    Param
    (    
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$ComputerName
    )

    Begin
    {
    Write-Verbose "Getting memory info..."
    }
    Process
    {
        foreach ($computer in $ComputerName){

            if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {

            gwmi win32_operatingsystem -ComputerName $computer -ErrorAction SilentlyContinue | select `
            @{n='Computer';e={$computer.toupper()}},
            @{n='FreeMemory(GB)';e={$_.freephysicalmemory / 1MB -as [int]}}, 
            @{n='UsedMemory(GB)';e={$_.totalvisiblememorysize / 1MB - $_.freephysicalmemory / 1MB -as [int]}},
            @{n='TotalMemory(GB)';e={$_.totalvisiblememorysize / 1MB -as [int]}},
            @{n='PctUsed';e={(($_.totalvisiblememorysize - $_.freephysicalmemory) / $_.totalvisiblememorysize).tostring("P")}}
                
            }

            else{
                Write-Warning "$($computer.toupper()) is either offline or an invalid computer name."
            }
        }
    }
    End
    {
    Write-Verbose "Finished getting memory info."
    }
}

Function global:Get-SystemInfo {
<#
.SYNOPSIS
Gets critical system info from one or more computers.
.DESCRIPTION
This command uses WMI, and can 
accept computer names, CNAME aliases,
and IP addresses. WMI must be enabled and you must run this
with admin rights for any remote computer.
.PARAMETER Computername
One or more names or IP addresses to query.
.EXAMPLE
Get-SystemInfo -computername localhost
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [string]$ErrorLog = 'c:\retry.txt',

        [switch]$LogErrors
    )
    PROCESS {
    if (Test-Path c:\errors.txt) {
    del c:\errors.txt
    }
        foreach ($computer in $computerName) {
            Write-Verbose "Getting WMI data from $computer"
            $os = Get-WmiObject -class Win32_OperatingSystem -computerName $computer
            $cs = Get-WmiObject -class Win32_ComputerSystem -computerName $computer
            $props = @{'ComputerName'=$computer;
                       'LastBootTime'=($os.ConvertToDateTime($os.LastBootupTime));                    
                       'OSVersion'=$os.version;
                       'Manufacturer'=$cs.manufacturer;
                       'Model'=$cs.model
                              }
            $obj = New-Object -TypeName PSObject -Property $props
            $obj.PSObject.TypeNames.Insert(0,'MOL.SystemInfo')
            Write-Output $obj
        }
    }
}

Function global:Get-UsedSpace {
<#
.SYNOPSIS
Gets the total used space on the disks of the specified computers.
.DESCRIPTION
This command uses WMI, and can accept computer names, CNAME aliases,and IP addresses. 
WMI must be enabled and you must run this with admin rights for any remote computer.
.PARAMETER ComputerName
One or more computer names to query.
.EXAMPLE
Get-UsedSpace -ComputerName localhost
#>

   [cmdletbinding()]

    param( 
    [String[]]$ComputerName = 'localhost'
    )
 
    Begin{
    Write-Verbose "Getting disk information..."
    }

    Process{
        
        foreach ($computer in $ComputerName) {
    
            Try {
                gwmi win32_logicaldisk -ComputerName $computer -ErrorAction Stop | out-null
            }
        
            Catch {
                Write-Warning "$($computer.ToUpper()) is either offline or an invalid computer name."          
            }
        }     

            gwmi win32_logicaldisk -ComputerName $computername -filter "drivetype=3" -ErrorAction SilentlyContinue | select DeviceID,VolumeName,@{n='UsedSpace(GB)';e={$_.size /1gb - $_.freespace /1gb -as [int]}} | sort 'usedspace(gb)' 
    }
    
    End { 
     Write-Verbose "Finished retrieving disk information."   
    }    
}

Function global:Get-GroupMembership {

    [CmdletBinding()]
    
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('Name','Username')]
        [String[]]$Identity
    )

    Begin
    {
    }
    Process
    {
            foreach ($I in $Identity) {

                Write-Verbose "Checking if $I exists..."

                # Check if the user(s) exist
                if ($User = Get-ADUser -Filter {(name -eq $I) -or (samaccountname -eq $I)}) {
               
                $Groups = Get-ADPrincipalGroupMembership -Identity $User | Get-ADGroup -properties GroupCategory | select Name,GroupCategory | sort name | ft -AutoSize
                
                # Display group membership for each user             
                $Groups
                }

               # Warn the user if the entered username is invalid
               else {
               Write-Warning "$I is not a valid user."
               }  
            }
    }
}

Function global:Get-UserInfo {
<#
.SYNOPSIS
   Gets Active Directory information of the specified user(s).
.DESCRIPTION
   Queries Active Directory for selected properties of the specified user(s).
.PARAMETER Identity
   One or more users to query.
.EXAMPLE
   Get-UserInfo -Identity test.user
#>

    [CmdletBinding()]
    
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('Name','Username')]
        [String[]]$Identity
    )

    Begin
    {
    }
    Process
    {
            foreach ($I in $Identity) {

                Write-Verbose "Checking if $I exists..."

                # Check if the user exists
                if (Get-ADUser -Filter {(Name -eq $I) -or (SamAccountName -eq $I)}) {

                $Name = Get-ADUser -properties msDS-UserPasswordExpiryTimeComputed,GivenName,Name,PasswordNeverExpires,homeMDB,PrimaryGroup,LastLogonDate,LockedOut,AccountExpirationDate,Description,ScriptPath,PasswordLastSet,WhenCreated `
                -Filter {(Name -eq $I) -or (SamAccountName -eq $I)}

                # Get the username of each user
                $Username = $Name | Select-Object -ExpandProperty SamAccountName

                # Get group membership for each user
                $Groups = Get-ADPrincipalGroupMembership -Identity $Username | Sort Name | select -ExpandProperty Name
                
                    foreach ($N in $Name) {                       

                        # Get mailbox stats for the user                     
                        if ($Mailbox = Get-Mailbox -Filter "SamAccountName -eq '$Username'") {
                            $MailboxStats = $Mailbox | Get-MailboxStatistics
                            $MailboxSize = (($MailboxStats.TotalItemSize.ToString()).Split('(')[0]).trim()

                                # If the mailbox is set to use the database defaults, display those. Otherwise, display the quota on the mailbox itself.
                                if ($Mailbox.UseDataBaseQuotaDefaults) {
                                    $Quota = ($MailboxStats.DatabaseProhibitSendQuota.ToString()).Split('(')[0]
                                }

                                else {
                                    $Quota = ($Mailbox.ProhibitSendQuota.ToString()).Split('(')[0]
                                    }

                            $MailboxSizeLimit = $MailboxSize + "/" + $Quota
                            }

                        else {
                            $MailboxSizeLimit = $Null
                            }                          

                        # Check if the password is set to expire
                        if ($N.PasswordNeverExpires) {
                            $expires = 'Never'
                        }

                        else {
                            $expires = ([datetime]::FromFileTime($N."msDS-UserPasswordExpiryTimeComputed")).ToShortDateString()
                        }

                        # Check if passwors is set to expire
                        if ($N.PasswordLastSet -eq $null) {
                        $LastSet = 'Never'
                        }

                        else {
                        $LastSet = $N.PasswordLastSet.ToShortDateString()
                        }
                                                                                       
                        # Check if the account is set to expire
                        if ($N.AccountExpirationDate -eq $null) {
                            $accountexpires = 'Never'
                        }

                        else {
                            $accountexpires = $N.AccountExpirationDate
                        }

                        # Check if the user has a home mailbox database
                        if ($N.homeMDB -eq $null) {}

                        else {
                            $mdb = $Mailbox.Database
                        }

                        # Get the main computer used the user if possible
                        if ($computer = Get-ADComputer -Properties Description,Name -Filter "Description -like '*$($N.Name)* Workstation'" -SearchBase "ou=national ave.,dc=mastersoncompany,dc=com" -SearchScope Subtree `
                        | Select -Expand Name) {}                       
                        
                        else {
                        $computer = 'None/Multiple'
                        }

                            Write-Verbose "Adding properties to hash table..."

                            # Create the properties we want to see
                            $props = [ordered]@{
                            'Name' = $N.Name
                            'Username' = $N.SamAccountName
                            'Title' = $N.Description
                            'Enabled' = $N.enabled
                            'LockedOut' = $N.LockedOut                                        
                            'PasswordExpiryDate' = $expires
                            'PasswordLastSet' = $LastSet
                            'LogonScript' = $N.ScriptPath
                            'LastLogon' = $N.LastLogonDate.ToShortDateString()
                            'CreatedOn' = $N.WhenCreated.ToShortDateString()
                            'AccountExpiration' = $accountexpires
                            'MailboxDatabase' = $mdb
                            'MailboxSize/Limit' = $MailboxSizeLimit
                            'PrimaryComputer' = $computer
                            'PrimaryGroup' = $N.PrimaryGroup.Split(',=')[1]
                            'Groups' = $Groups
                            }
                    }
                    # Create a new PSObject and store the above properties in it
                    $obj = New-Object -TypeName PSObject -Property $props
                                   
                }
                # Warn the user if they entered in an invalid username
                else {
                Write-Warning "$I is not a valid user."
                }
                 
                # Display the object created above
                $obj
            }
    
    }
    End
    {
    Write-Verbose "Finished retrieving user information."
    }

}

Function global:Get-Computer {
[CmdletBinding()]   
    Param
    (
     [Parameter(Mandatory=$false)]
     [String]$ComputerName = '*'
    )

Get-ADComputer -Filter ("Name -like '$ComputerName'") -Properties description,name,operatingsystem | Select-Object Name,Description,OperatingSystem | Sort-Object name

}

Function global:Get-NavUsers {

    Invoke-Command -ComputerName NAVSQL1 -ScriptBlock {
        (Invoke-Sqlcmd -ServerInstance NAVSQL1 -Database MastersonLIVE -Query "SELECT [Session ID],[User ID],[Client Type] FROM [dbo].[Active Session] ORDER BY [Client Type] DESC")} | 
            Select @{n='SessionID';e={$_.'Session ID'}},@{n='User';e={$_.'User ID'.Replace('MASTERSON\',"")}},
            @{
            n='ClientType';
            e={Switch ($_.'Client Type') 
                     {
                         0 {"Windows Client"}
                         1 {"SharePoint Client"}
                         2 {"Web Services"}
                         3 {"Client Service"}
                         4 {"NAV Application Server"}
                         5 {"Background"}
                         6 {"Management Client"}
                         7 {"Web Client"}
                         8 {"Unknown"}
                         9 {"Tablet"}
                        10 {"Handheld/Phone"}
                        11 {"Desktop"}
                      }
               }

              }   
}

Function global:Get-VicinityUsers {

    Invoke-Command -ComputerName NAVSQL1 -ScriptBlock {Invoke-Sqlcmd -ServerInstance NAVSQL1 -Database Vicinity -Query "SELECT [ComputerName],[UserID],[LoginDate] FROM [dbo].[Login] ORDER BY [UserID]"} |
    
    Select @{n='User';e={($_.UserID.ToString()).ToUpper()}},@{n='Computer';e={$_.ComputerName}},LoginDate -ExcludeProperty PSComputerName,RunspaceId
                        
}

Function global:Kill-NavUsers {
    
    [Cmdletbinding()]

    Param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias('Session ID')]
    [int]$Session
    )

    Invoke-Command -ComputerName NAVSQL1  -ArgumentList $Session -ScriptBlock {

            param($Session)
            Invoke-Sqlcmd -ServerInstance NAVSQL1 -Database MastersonLIVE -Query "DELETE [dbo].[Active Session] WHERE [Session ID] = '$Session'"
    }
              
}

Function global:New-MainsaverUser {

[Cmdletbinding()]

    Param (
    [Parameter(Mandatory=$true)]
    [string]$Login,
    [Parameter(Mandatory=$true)]
    [string]$Password
    )

   $Server = 'NAVSQL1'
   $Database = 'MSDB1'
   

   $Query = "CREATE LOGIN $Login WITH PASSWORD = '$Password',
        CHECK_POLICY = OFF,
        DEFAULT_DATABASE = master
        GO

        USE MSDB1;
        CREATE USER $Login FOR LOGIN $Login;
        EXEC sp_addrolemember 'msvr_clerk', $Login
        GO
        
        USE MSDB1_Test;
        CREATE USER $Login FOR LOGIN $Login;
        EXEC sp_addrolemember 'msvr_clerk', $Login
        GO"

        Invoke-Sqlcmd -ServerInstance $Server -Database $Database -Query $Query
        
                                        
    } 

Function global:Get-Joke {

$ProgressPreference = 'SilentlyContinue'

$URI = 'http://www.laughfactory.com/jokes/joke-of-the-day'
$Content = Invoke-WebRequest $URI

($content.ParsedHtml.getElementsByTagName("p") | where {($_.id -like 'joke_*')}).innertext | get-random
$ProgressPreference = 'Continue'

}

Function global:Get-CPU {
<#
.SYNOPSIS
Gets the current CPU usage of the specified computers.
.DESCRIPTION
This command uses a performance counter to get the average processor load of all CPUs.
.PARAMETER ComputerName
One or more computer names to query.
.EXAMPLE
Get-CPU -ComputerName localhost
#>
    [CmdletBinding()]
    Param
    (    
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$ComputerName
    )

    Begin
    {
    Write-Verbose "Getting CPU info..."
    }
    Process
    {

    #Create an initial array
    $FinalObject = @()

        foreach ($computer in $ComputerName){

            #Check if the entered computers are valid/online
            if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {

            #Get each computer's CPU info
            $CPU = (Get-Counter -ComputerName $computer -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 5 | 
            Select-Object -ExpandProperty countersamples | select -ExpandProperty cookedvalue | Measure-Object -Average).Average

            $CPU2 = "$([math]::Round($CPU))" + "%" 
            
            #Add properties from each computer to the array above
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -Type NoteProperty -Name 'Computer' -Value $computer.toupper()
            $obj | Add-Member -Type NoteProperty -Name 'CPU' -Value $CPU2
            
            $FinalObject += $obj  
                
            }

            else {
                Write-Warning "$($computer.toupper()) is either offline or an invalid computer name."
            }
        }

        $FinalObject
    }
    
    End
    {
    Write-Verbose "Finished getting CPU info."
    }
}

Function global:Load-Module {

Import-Module customfunctions -Force -Global

}

Function global:Get-MailboxDatabaseStatistics {

<#
.SYNOPSIS
Gets basic information from the specified mailbox database.
.DESCRIPTION
This command queries the specified mailbox database and returns some information about it.
.PARAMETER Database
One or more mailbox database names to query.
.EXAMPLE
Get-MailboxDatabaseStatistics -Database MBD2
#>

[CmdletBinding()]
    Param
    ()

Begin {}

Process {

# Get the names of all Exchange servers
$Servers = Get-ExchangeServer | select -ExpandProperty Name

 
   foreach ($S in $Servers) {

    if ($MBD = Get-MailboxDatabase -Server $S -ErrorAction SilentlyContinue) {

        foreach ($DB in $MBD) {
        
        Write-Verbose "Querying mailbox database $($DB.Name)..."
       
        $DB | Select Name, 
        @{Name=”Size”;Expression={(Get-MailboxDatabase -Identity $_.Identity -Status -WarningAction silentlycontinue | Select DatabaseSize).databasesize.tostring().split('(')[0]}},
        @{Name="LargestMailbox";expression={((Get-MailboxStatistics -Database $_.Identity | sort TotalItemSize)[-1]).DisplayName}},
        @{Name="LargestMailboxSize";expression={(((Get-MailboxStatistics -Database $_.Identity | sort TotalItemSize)[-1]).TotalItemSize.value).tostring().split("(")[0]}},
        @{Name=”TotalUserMailboxes”;expression={(Get-Mailbox -Database $_.Identity | Measure-Object).Count}}   
        
        Write-Verbose "Finished querying mailbox database $($DB.Name)."
        }

    }

    else {
    Write-Warning "$D is not a valid mailbox database."
    }
}
}

End {}

}

Function global:Prompt {
    Write-Host ("PS " + $(get-location) +">") -NoNewline -BackgroundColor Black -ForegroundColor White
    return " "
}

Function global:Shutdown-Host {

<#
.SYNOPSIS
Gracefully shuts down the specified physical host(s). 
.DESCRIPTION
This command utilizes PowerCLI to shut down each guest VM, put the host in maintenance mode, and then shut it down.
.PARAMETER Hosts
One or more physical hosts to shut down. Use regex to match multiple hosts.
.EXAMPLE
Shutdown-Hosts -HostName PS3,PS2
#>

[CmdletBinding()]
    Param
    (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$HostName
    )

Begin {

# Create an array to store the specified hosts
$VMHosts = @()
}

Process {

# Get each host and store it in the array created above
ForEach ($H in $HostName) {

    $VMHosts += Get-VMHost | Where-Object Name -Match $H    
}

# Loop through the hosts and get the VMs on each
ForEach ($VMHost in $VMHosts) {

Write-Host "Getting virtual machines on $($VMHost.Name)..."
$VirtualMachines = $VMHost | Get-VM

    # Loop through each VM and shut it down if possible
    ForEach ($VM IN $VirtualMachines) {

            # Check power state
            Write-Host "Checking power state on $($VM.Name)..."
            if ($VM.PowerState -eq 'PoweredOn') {
              
             # Check if VMWare Tools is installed and running
             Write-Host "Checking VMWare tools status on $($VM.Name)..."
             $ToolsVersionStatus = (Get-VMGuest -VM $VM).ExtensionData.ToolsVersionStatus
             $ToolsRunningStatus = (Get-VMGuest -VM $VM).ExtensionData.ToolsStatus

                if ($ToolsVersionStatus -eq 'guestToolsCurrent' -and $ToolsRunningStatus -eq 'toolsOk') {

                    Write-Host "Shutting Down $($VM.Name)..."
                    $VM | Shutdown-VMGuest -Confirm:$false | Out-Null

                        # Wait until the VM is powered off
                        do {
                            Write-Host "Waiting for $($VM.Name) to shut down..."
                            Start-Sleep -Seconds 7
                            $NewVM = Get-VM -Name ($VM.Name)
                            $Status = $NewVM.PowerState
                        }

                        until ($Status -eq 'PoweredOff')
                        Write-Host "$($VM.Name) has shut down." -ForegroundColor Green
                }

                else {
                      Write-Host "VMWare Tools is either not running or unmanaged. Will forcefully shut down $($VM.Name)." -ForegroundColor Yellow
                      Stop-VM -VM $VM -Confirm:$false -Kill | Out-Null

                        # Wait until the VM is powered off
                        do {
                            Write-Host "Waiting for $($VM.Name) to shut down..."
                            Start-Sleep -Seconds 3
                            $NewVM = Get-VM -Name ($VM.Name)
                            $Status = $NewVM.PowerState
                        }

                        until ($Status -eq 'PoweredOff')
                        Write-Host "$($VM.Name) has shut down." -ForegroundColor Green
                }
             }

             else {
                Write-Host "Skipping $($VM.Name), already shut down." -ForegroundColor Yellow
             }
    }

    # Put host in maintenance mode
    try {   
        Set-VMHost -VMHost $VMHost -State Maintenance -Confirm:$false -ErrorAction Stop | Out-Null
        
        do {
            Write-Host "Waiting for $($VMHost.Name) to enter maintenance mode..."
            Start-Sleep -Seconds 5
            $NewVMHost = Get-VMHost -Name ($VMHost.Name)
            $HostStatus = $NewVMHost.ConnectionState
            }

        until ($HostStatus -eq 'Maintenance')
        Write-Host "$($VMHost.Name) has entered maintenance mode." -ForegroundColor Green

                # Shutdown the host after it enters maintenance mode                                 
                try {
                    Write-Host "Shutting down $($VMHost.Name)..."
                    Stop-VMHost -VMHost $VMHost -Confirm:$false -ErrorAction Stop | Out-Null

                    do {
                        Write-Host "Waiting for $($VMHost.Name) to shut down..."
                        Start-Sleep -Seconds 5
                        $HostMaint = Get-VMHost -Name $VMHost.Name
                        $HostMaintStatus = $HostMaint.PowerState
                        }

                    until ($HostMaintStatus = 'PoweredOff')
                    Write-Host "$($VMHost.Name) has shut down." -ForegroundColor Cyan
                }

                catch {
                Write-Host "$($VMHost.Name) cannot be shutdown." -ForegroundColor Red
                }   
    }

    catch {
        Write-Host "Cannot put $($VMHost.Name) in maintenance mode. Please ensure all VMs on it are shut down." -ForegroundColor Red
}
}

End {

# Display status of all hosts
ForEach ($Computer in $HostName) {
    Get-VMHost | Where-Object Name -Match $Computer | Select-Object Name,PowerState
}

}
}
}

Function global:Get-BackupSize {

[CmdletBinding()]
    Param
    (    
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string[]]$Server
    )

$finalobj = @()

foreach ($S in $Server) {

    #### Find full backup size ####

    if (test-path "\\veeam\d$\Backups\$S") {

    $directory = "\\veeam\d$\Backups\$S"

    $totalsize = dir $directory -Recurse -Include '*.vbk','*.vib' | Measure-Object -Property length -sum

    $fulls = dir $directory -Recurse -Include '*.vbk' | Measure-Object -Property length -sum -Average

    $oldestfull = dir $directory -Recurse -include '*.vbk' | sort lastwritetime | select -First 1 | select -expand lastwritetime

    $sizeGB = $fulls.Sum / 1gb

    $average = $fulls.Average / 1gb

    #### Find incremental backup size ####

    $incrementals = dir $directory -Recurse -Include '*.vib' | Measure-Object -Property length -sum -Average

    $lastbackup = dir $directory -Recurse -include '*.vbk','*.vib' | sort lastwritetime | select -last 1 | select -expand lastwritetime

    $incsizeGB = $incrementals.Sum / 1gb

    $incaverage = $incrementals.Average / 1gb

    $props = [ordered]@{
    'Name' = $S.toupper()
    'FullBackups' = $fulls.Count
    'IncBackups' = $incrementals.Count
    'TotalFullSize(GB)' = [math]::Round($sizeGB,2)
    'AvgFullBackup(GB)' = [math]::Round($average,2)    
    'TotalIncSize(GB)' = [math]::Round($incsizeGB,2)
    'AvgIncSize(GB)' = [math]::Round($incaverage,2)
    'TotalSize(GB)' = [math]::Round($totalsize.Sum / 1GB,2)
    'OldestFullBackup' = $oldestfull
    'LatestBackup' = $lastbackup
   
    }

    $obj = New-Object -TypeName PSObject -Property $props

    $finalobj += $obj
    }

    else {
    Write-Warning "Server name '$s' is invalid."
    }

}

$finalobj
}



