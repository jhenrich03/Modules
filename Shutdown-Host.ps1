##################################################
# Script variables & connection to VCenter Server
##################################################

# Disconnect from any session that may be running
try {
    Disconnect-VIServer -Server * -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
catch {}

# Enter the name of your VCenter server. This will get shutdown last.
$VCenter = 'vcenter6'

# Connect to VCenter Server
$Username = ### Enter username here ###
$encrypted = Get-Content C:\Scripts\encrypted_password1.txt | ConvertTo-SecureString
$credentials = New-Object system.management.automation.pscredential($Username,$encrypted)

Write-Host "`nConnecting to $($VCenter.ToUpper())..."
$VC = Connect-VIServer $VCenter -Credential $credentials

if ($VC.IsConnected) {

Write-Host "Success!" -ForegroundColor Green

# Enter a comma separated list of hosts you need to shut down
$HostName = 'ps[1-6]'

# Get the VM and host that Vcenter is running on
$VCVM = Get-VM $VCenter
$VCenterHost = $VCVM | Get-VMHost

# Create an array to store the specified hosts to shut down
$VMHosts = @()

######################
# Beginning of script
######################

# Get each host and store it in the array created above
ForEach ($H in $HostName) {

    $VMHosts += Get-VMHost | Where-Object Name -Match $H  
}

# Loop through the hosts and get the VMs on each
ForEach ($VMHost in $VMHosts) {

    # Skip over the host running VCenter
    if ($VMHost.Name -ne $VCenterHost.Name) {

        Write-Host "`nGetting virtual machines on $($VMHost.Name)..."
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

                    Write-Host "Shutting down $($VM.Name)..."
                    $VM | Shutdown-VMGuest -Confirm:$false | Out-Null

                        # Wait until the VM is powered off
                        do {
                            Write-Host "Waiting for $($VM.Name) to shut down..."
                            Start-Sleep -Seconds 10
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

##########################################################
# Put host in maintenance mode and shutdown if successful
##########################################################

    try {
        Write-Host "Putting $($VMHost.Name) in maintenance mode..."   
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
                    Write-Host "$($VMHost.Name) has shut down." -ForegroundColor Green                   
                }

                catch {
                Write-Host "$($VMHost.Name) cannot be shutdown." -ForegroundColor Red            
                }   
    }

    catch {
        Write-Host "Cannot put $($VMHost.Name) in maintenance mode. Please ensure all VMs on it are shut down."  -ForegroundColor Red
    }
    }
}

# Disconnect from VCenter VM
Disconnect-VIServer -Server $VCenter -Force -Confirm:$false | Out-Null
}

else {
      Write-Host "Cannot connect to $($VCenter.Name). Check that the VM is online and the credentials are correct."  -ForegroundColor Red
      exit
}

############################################################################################
# We will now shut down the VMs running on the VCenter server and the host itself if needed 
############################################################################################

if ($VMHosts -contains $VCenterHost) {

    Write-Host "`nWe will now shutdown the VCenter server: $($VCenterHost.Name)"
    
        # Connect to physical host running VCenter
        $vcenterUsername = 'root'
        $vcenterencrypted = Get-Content C:\Scripts\vcenterpassword.txt | ConvertTo-SecureString
        $vcentercredentials = New-Object system.management.automation.pscredential($vcenterUsername,$vcenterencrypted)

        Write-Host "Connecting to $($VCenterHost.Name)..."
        $VC = Connect-VIServer $VCenterHost -Credential $vcentercredentials

            if ($VC.IsConnected) {

                Write-Host "Success!" -ForegroundColor Green

                $VCVM = Get-VM $VCenter
                $VCenterHost = $VCVM | Get-VMHost

                # Shutdown all VMs on the host
                Write-Host "`nGetting virtual machines on $($VCenterHost.Name)..."
                $VcenterVMs = $VCenterHost | Get-VM

                    foreach ($VM in $VcenterVMs) {

                        # Check power state
                        Write-Host "Checking power state on $($VM.Name)..."
                        if ($VM.PowerState -eq 'PoweredOn') {
              
                        # Check if VMWare Tools is installed and running
                        Write-Host "Checking VMWare tools status on $($VM.Name)..."            
                        $ToolsRunningStatus = (Get-VMGuest -VM $VM).ExtensionData.ToolsStatus
                        $ToolsVersionStatus = (Get-VMGuest -VM $VM).ExtensionData.ToolsVersionStatus

                            if ($ToolsRunningStatus -eq 'toolsOk' -and $ToolsVersionStatus -eq 'guestToolsCurrent') {

                                Write-Host "Shutting down $($VM.Name)..."
                                $VM | Shutdown-VMGuest -Confirm:$false | Out-Null

                                    # Wait until the VM is powered off
                                    do {
                                    Write-Host "Waiting for $($VM.Name) to shut down..."
                                    Start-Sleep -Seconds 10
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

##################################################################
# Put VCenter host in maintenance mode and shutdown if successful
##################################################################

    try { 
        Write-Host "Putting $($VCenterHost.Name) in maintenance mode..."
        Set-VMHost -VMHost $VCenterHost -State Maintenance -Confirm:$false -ErrorAction Stop | Out-Null
        
        do {
            Write-Host "Waiting for $($VCenterHost.Name) to enter maintenance mode..."
            Start-Sleep -Seconds 5
            $NewVMHost = Get-VMHost -Name ($VCenterHost.Name)
            $HostStatus = $NewVMHost.ConnectionState
            }

        until ($HostStatus -eq 'Maintenance')
        Write-Host "$($VCenterHost.Name) has entered maintenance mode." -ForegroundColor Green

                # Shutdown the host after it enters maintenance mode                                 
                try {
                    Write-Host "Shutting down $($VCenterHost.Name)..."
                    Stop-VMHost -VMHost $VCenterHost -Confirm:$false -ErrorAction Stop | Out-Null                 
                    Write-Host "$($VCenterHost.Name) has shut down." -ForegroundColor Green                    
                }

                catch {
                Write-Host "$($VCenterHost.Name) cannot be shutdown."  -ForegroundColor Red
                }   
    }

    catch {
           Write-Host "Cannot put $($VCenterHost.Name) in maintenance mode. Please ensure all VMs on it are shut down."  -ForegroundColor Red
    }
}

else {
      Write-Host "Cannot connect to $($VCenterHost.Name). Check that the host is online and the credentials are correct." -ForegroundColor Red
      exit
}
}

try {
    Disconnect-VIServer -Server * -Force -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
catch {}

Write-Host "`nScript finished."

# End the transcript
Stop-Transcript | Out-Null