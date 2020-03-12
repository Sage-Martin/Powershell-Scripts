#############################
#### Sage's Master Setup
#############################
$Global:version = "2.1"

#############################
#### Misc Functions
#############################

# Checks to see if a string is only an int
Function Is-Numeric ($x) {
    return $x -match '^[0-9]+$'
}

# Converts a string into an int
Function Convert-To-Numeric ($x) {
    [string]$x
    [int]$new = [int]::Parse($x)
    Write-Host $new 
    return $new
}

# Just does a simple print test on the screen
Function Print-Test {
    Clear-Host
    Write-Host "===================="
    Write-Host "Print Test"
}

# Tests the X500 Path maker
Function String-Thing {
    $str = X500-Path $(Read-Host "Path") $true
    Write-Host $str
}

# Creates an X500 path based on a simple syntax
# ex: domain.local/kansas/employees/operations/
# output: ou=operations,ou=employees,ou=kansas,dc=domain,dc=local
# ex: domain.local/kansas/employees/operations/Sage Martin
# output: cn=Sage Martin,ou=operations,ou=employees,ou=kansas,dc=domain,dc=local
Function X500-Path {
    Param (
        [Parameter(Mandatory=$true)] [string]$path,
        [Parameter(Mandatory=$false)] [boolean]$isOU = $false
    )
    #Write-Host $isOU
    if($path.Contains("/")){
        $splits = $path.Split("/")
        $fin = ""
        for($i=$splits.Length - 1;$i -ge 0;$i--) {
            if($splits[$i].Length -ne 0) {
                if($fin.Length -gt 0) {
                    $fin += ","
                }
                if($splits[$i].Contains(".")) {
                    $domainParts = $splits[$i].Split(".")
                    for($o=0;$o -lt $domainParts.Length;$o++) {
                        if($o -gt 0) {
                            $fin += ","
                        }
                        $fin += "dc=" + $domainParts[$o]
                    }
                } else {
                    if($i -eq $splits.Length - 1 -and -not $isOU) {
                        $fin += "cn="
                    } else {
                        $fin += "ou="
                    }
                    $fin += $splits[$i]
                }
            }
        }
        return $fin
    }
    return $path
}

#############################
#### Initial Setup Stuff
#############################

Function Create-VM {
    # Uncomment line below if erroring on line 0
    #Set-ExecutionPolicy Unrestricted

    # New Hyper-V VM Creation script
    # This will create either a server 2016, or windows 10 VM

    # User input for VM name
    $vmname = Read-Host "What is the name of this VM?"

    # Create Private 1 switch if it does not exist yet
    $switch = Get-VMSwitch

    If($switch.Name -notcontains "Private 1")
    {
        New-VMSwitch -Name "Private 1" -SwitchType Private
    }

    # Set up params for New-VM CMDLET
    # Using @{ } to create a collection of params/values
    $NewVMParam = @{
        Name = $vmname

        MemoryStartupBytes = 1GB

        Path = "C:\Hyper-V\VMS"

        SwitchName = "Private 1"

        NewVHDPath = "C:\Hyper-V\VMS\$vmname.vhdx"

        NewVHDSizeBytes = 20GB

        #common parameters (can be used on a majority of CMDLETs)
        ErrorAction = "Stop"

        Verbose = $true
    }

    # Plug the parameters into New-VM and store the VM for later use
    $VM = New-VM @NewVMParam

    #Setup params for the Set-VM CMDLET
    #This piece adds the additional details from the wizard
    $SetVMParam = @{
        ProcessorCount = 1

        DynamicMemory = $true

        MemoryMinimumBytes = 512MB

        MemoryMaximumBytes = 2GB

        ErrorAction = "Stop"

        Verbose = $true
    }

    $VM = $VM | Set-VM @SetVMParam -Passthru

    # ask user if they need an additional hard drive
    $addhdd = Read-Host "Do you need an additional 10GB hard drive? Y/N"
    If($addhdd -eq "y")
    {
        $NewVHDParam = @{
            Path = "C:\Hyper-V\VMS\$vmname-hdd2.vhdx"

            Dynamic = $true

            SizeBytes = 10GB

            ErrorAction = "Stop"

            Verbose = $true
        }

        New-VHD @NewVHDParam

        $AddVMHDDParam = @{
            Path = "C:\Hyper-V\VMS\$vmname-hdd2.vhdx"

            ControllerType = "SCSI"

            ControllerLocation = 1
        }

        $VM | Add-VMHardDiskDrive @AddVMHDDParam


    }

    # Branch to decide which OS to install
    # ISO path may need to be updated for different machines
    $os = Read-Host "Which OS would you like to load (2016/w10)?"
    if($os -eq "2016")
    {
        $VMDVDParam = @{
            VMName = $vmname

            Path = "C:\Hyper-V\ISOS\Windows_Server_2016_x64_30350.ISO"

            ErrorAction = "Stop"

            Verbose = $true
        }

        Set-VMDvdDrive @VMDVDParam
    }
    elseif($os -eq "w10")
    {
        $VMDVDParam = @{
            VMName = $vmname

            Path = "C:\Hyper-V\ISOS\en_windows_10_enterprise_x64_dvd_6851151.iso"

            ErrorAction = "Stop"

            Verbose = $true
        }

        Set-VMDvdDrive @VMDVDParam
    }

    $VM | Start-VM -Verbose
}

# Simple initial config
Function Inital-Config {
    # Script for initial configuration
    # The script will implement the following
    # Rename computer, IP config, Firewall, Lcoal users & groups

    # Variables for user input.
    $hostname = Read-Host "What is this computer's name?"
    $ip = Read-Host "Enter the IP Address"
    $cdir = Read-Host "Enter the CIDR notation subnet mask"
    $dns = Read-Host "Enter the DNS Server's IP Address"

    ## Rename the computer
    Rename-Computer -NewName $hostname

    ## Set new IP Address
    New-NetIPAddress -IPAddress $ip -InterfaceAlias Ethernet -AddressFamily IPv4 -PrefixLength $cdir

    ## Set DNS Server info
    Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $dns

    # Disable IPv6
    Disable-NetAdapterBinding -InterfaceAlias Ethernet -ComponentID ms_tcpip6

    ## Enable Ping in Firewall
    Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True -Direction Inbound
    Enable-NetFirewallRule -DisplayName "Virtual Machine Monitoring (Echo Request - ICMPv4-In)"

    ## Set Timezone
    Set-TimeZone -Name "Central Standard Time"

    # Restart
    Write-Host "Restarting Machine"
    Start-Sleep 3
    Restart-Computer -Force
}

# Join a client to a domain
Function Join-Domain {
    $domainName = Read-Host "Domain Name"
    $credential = Read-Host "Credential"
    add-computer –domainname $domainName -Credential $credential -restart –force
}

#############################
#### DHCP Install Stuff
#############################

# Install DHCP on a new server
Function DHCP-Install {
    ## Installing DHCP w/ Tools ##
    Install-WindowsFeature DHCP -IncludeAllSubFeature -IncludeManagementTools
}

# Create a new DHCP scope
Function DHCP-Scope {
    # TODO: IP Checks
    $scopeName = Read-Host "Scope Name"
    $startRange = Read-Host "Start Range"
    $endRange = Read-Host "End Range"
    $subnetMask = Read-Host "Subnet Mask"
    # Create a new DHCP score for the 192.168.0.1 /24 scheme
    Add-DhcpServerv4Scope -Name $scopeName -StartRange $startRange -EndRange $endRange `
    -SubnetMask $subnetMask

    # TODO: Ask for this
    DHCP-Exclusion
}

# Add an exclusion to a domain
Function DHCP-Exclusion {
    # TODO: IP Checks
    $scopeID = Read-Host "Scope ID"
    $startRange = Read-Host "Start Range"
    $endRange = Read-Host "End Range"
    Add-DhcpServerv4ExclusionRange -ScopeId $scopeID -StartRange $startRange `
    -EndRange $endRange
}

# Authorize a DHCP scope for a domain
Function DHCP-Authorize {
    Add-DhcpServerInDC -DnsName $(Read-Host "Server Name")
}

# Link a scope to a failover
Function DHCP-Failover {
    $dhcp1 = Read-Host "Main DHCP"
    $dhcp2 = Read-Host "Partner Server"
    $scopeID = Read-Host "Scope ID"
    Add-DhcpServerv4Failover -ComputerName $dhcp1 -Name "SFO-SIN-Failover" -PartnerServer $dhcp2 -ScopeID $scopeID -SharedSecret "what"
}

#############################
#### Active Directory Stuff
#############################

# Does an Initial install of a domain
Function ADDS-Install {
    Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
    $domainName = Read-Host "Domain Name"
    $netBiosName = ($domainName.Split(".")[0].ToUpper())
    #
    # Windows PowerShell script for AD DS Deployment
    #

    Import-Module ADDSDeployment
    Install-ADDSForest `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "WinThreshold" `
    -DomainName $domainName `
    -DomainNetbiosName $netBiosName `
    -ForestMode "WinThreshold" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$false `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Force:$true
}

# Does a Initial install of a secondary domain
Function ADDS-Secondary {
    Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools
    $domainName = Read-Host "Domain Name"
    Import-Module ADDSDeployment
    Install-ADDSDomainController `
        -NoGlobalCatalog:$false `
        -CreateDnsDelegation:$false `
        -Credential (Get-Credential) `
        -CriticalReplicationOnly:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainName $domainName `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$false `
        -SiteName "Default-First-Site-Name" `
        -SysvolPath "C:\Windows\SYSVOL" `
        -Force:$true

}

# Prompts to create a new OU
Function ADDS-NewOU {
    $ouName = Read-Host "OU Name"
    $ouPath = X500-Path $(Read-Host "OU Path") $true
    New-ADOrganizationalUnit -Name $ouName -Path $ouPath
}

# Prompts to create a simple group
Function ADDS-NewGroup {
    $groupName = Read-Host "Group Name"
    $displayName = Read-Host "Display Name"
    $groupPath = X500-Path $(Read-Host "Path")
    New-ADGroup -Name $groupName -SamAccountName $groupName -GroupCategory Security `
    -GroupScope Global -DisplayName $displayName`
    -Path $groupPath
}

# Prompts to create a simple user
Function ADDS-NewUser {
    $aduFirst = Read-Host "First Name"
    $aduLast = Read-Host "Last Name"
    $password = Read-Host "Password" -AsSecureString
    $aduPath = X500-Path $(Read-Host "Path")
    $aduPrinciple = Read-Host "Email"
    $aduFull = $aduFirst + " " + $aduLast
    $aduSAM = $aduFirst.ToLower().Substring(0,1) + $aduLast.ToLower()
    #Write-Host $aduFull
    New-ADUser -Name $aduFull -GivenName $aduFirst `
        -Surname $aduLast `
        -SamAccountName $aduSAM `
        -AccountPassword $password `
        -ChangePasswordAtLogon $false `
        -Path $aduPath `
        -UserPrincipalName $aduPrinciple `
        -Enabled $true
}

# Add a user to a group
# This actually just uses the Add-ADGroupMember which can accept multiple names
Function ADDS-UserToGroup {
    $adu = X500-Path $(Read-Host "User Path")
    $adg = X500-Path $(Read-Host "Group Path")
    Add-ADGroupMember -Identity $adg -Members $adu

}

# Simple Import of Groups
# Headers: Name, GroupCategory, GroupScope, Description, Path
Function ADDS-ImportGroups {
    Import-Csv -Path (Read-Host "CSV PATH") | `
    ForEach-Object {
        New-ADGroup -Name $_.Name `
            -GroupCategory $_.GroupCategory `
            -GroupScope $_.GroupScope `
            -Description $_.Description `
            -Path $_.Path
    }
}

# Simple import CSV of Users
# Headers: First, Last, User, Email, Password, Path, Group 
Function ADDS-ImportUsers {
    Import-Csv -Path (Read-Host "CSV PATH") | `
    ForEach-Object {
        New-ADUser -Name $($_.First + " " + $_.Last) `
            -GivenName $_.First `
            -Surname $_.Last `
            -SamAccountName $_.User `
            -AccountPassword $(ConvertTo-SecureString $_.Password -AsPlainText -Force) `
            -ChangePasswordAtLogon $false `
            -Path $_.Path `
            -UserPrincipalName $($_.User + $_.Email) `
            -Enabled $true 
        Add-ADGroupMember -Members $("cn=" + $_.First + " " + $_.Last + "," + $_.Path) -Identity $_.Group
    }
}

# Import a CSV File that contains a User and the new group
# Very basic, needs a headers of User and Group
Function ADDS-ImportUsersToGroups {
    Import-Csv -Path (Read-Host "CSV PATH") | `
    ForEach-Object {
        Add-ADGroupMember -Members $_.User -Identity $_.Group
    }
}

Function Menu-Page {
    Param (
        [Parameter(Mandatory=$true)] [int]$page = 0,
        [Parameter(Mandatory=$false)] [boolean]$quick = $false
    )
    if($page -lt 0) {
        $page = 0
    }

    # Pages can have page names
    $pageSelect = @{1 = "Intial Stuff"; 2 = "DHCP"; 3 = "ADDS Part 1"; 4 = "ADDS Part 2"}
    # Pages only have 6 things
    $options = @("0","Initial Config","Create VM", "Join Domain", "", "", "Test Paths", `
                 "Install DHCP", "DHCP Scope", "DHCP Authorize", "DHCP Exclude", "DHCP Failover", "", `
                 "ADDS Install", , "ADDS Secondary Install", "ADDS New OU", "ADDS New User", "ADDS User into Group", "ADDS Import Groups",`
                 "ADDS Import Users","ADDS U2G")
    $menu = 0
    $killthis = $false
    if(-not $quick) {
        Clear-Host
        $pagetext ="======= Page $page ======="
        Write-Host "==== Master Setup ===="
        Write-Host $pagetext
        if($page -gt 0 -and $pageSelect[$page] -ne $null) {
            $pagetext = "==== " + $pageSelect[$page] + " ===="
            Write-Host $pagetext
        }
        # If it's page 0 Show a few Pages of options
        if($page -eq 0) {
            for($i=1;$i -lt 7;$i++) {
                $pSel = $i
                #Write-Host $opt
                if($pageSelect.ContainsKey($pSel) -and $pageSelect[$pSel].Length -ne 0) {                
                    $text = "$i" + ": " + $pageSelect[$pSel]
                    Write-Host $text
                }     
            }
        # Otherwise Display the actual page options
        } else {
            for($i=1;$i -lt 7;$i++) {
                $opt = (($page - 1) * 6) + ($i)
                #Write-Host $opt
                if($options.Length -ge $opt -and $options[$opt].Length -ne 0) {                
                    $text = "$i" + ": " + $options[$opt]
                    Write-Host $text
                }     
            }
        }
        # Options 7-0 are reserved for the menu
        Write-Host "7: Main Menu"
        if($page -gt 1) {
            Write-Host "8: Page Back"
            Write-Host "9: Page Next"
        } else {
            Write-Host "8: Print Test"
            Write-Host "9: Page Next"
        }
        Write-Host "0: Exit"
    } else {

    }
    $menu = 0
    $menu = Read-Host ">"
    # Make sure that you enter in a number
    if(Is-Numeric($menu)) {
        # These are for the menu/special options
        if($page -eq 0) {
            if([int]$menu -eq 0) {
                $menu = 0
            } elseif([int]$menu -eq 7) {
                $menu = "menu"
            } elseif([int]$menu -eq 8) {
                $menu = "print"
            } elseif([int]$menu -eq 9) {
                $menu = "next"
            } else {
                Menu-Page $menu
                $menu = 0
            }
        } elseif($page -gt 1) {
            if([int]$menu -eq 0) {
                $menu = 0
            } elseif([int]$menu -eq 7) {
                $menu = "menu"
            } elseif([int]$menu -eq 8) {
                $menu = "back"
            } elseif ([int]$menu -eq 9) {
                $menu = "next"
            } else {
                $menu = [int]$menu + (($page - 1) * 6)
            }
        } else {
            if([int]$menu -eq 0) {
                $menu = 0
            } elseif([int]$menu -eq 7) {
                $menu = "menu"
            } elseif([int]$menu -eq 8) {
                $menu = "print"
            } elseif([int]$menu -eq 9) {
                $menu = "next"
            } else {
                $menu = [int]$menu + (($page - 1) * 6)
            }
        }
        
    } else {
        Write-Host "Not a number"
    }
    
    while($menu -ne "0" -or $menu -ne 0) 
    {
        #Write-Host $menu
        switch ($menu) {
            # Initial Stuff
            1 { 
                Inital-Config
                break
            }
            2 { 
                Create-VM
                break 
            }
            3 {
                Join-Domain
                break
            }
            4 {        
                break
            }
            5 { 
                break 
            }
            6 {
                String-Thing
                break
            }

            ## DHCP
            7 {
                DHCP-Install
                break
            }
            8 {
                DHCP-Scope
                break
            }
            9 {
                DHCP-Authorize
                break
            }
            10 {
                DHCP-Exclusion
                break
            }
            
            11 {
                DHCP-Failover
                break
            }

            ## ADDS Page 1
            13 {
                ADDS-Install
                break
            }
            14 {
                ADDS-Secondary
                break
            }
            15 {
                ADDS-NewOU
                break
            }
            16 {
                ADDS-NewUser
                break
            }
            17 {
                ADDS-UserToGroup
                break
            }
            18 {
                ADDS-ImportGroups
                break
            }
            ## ADDS Page 2
            19 {
                ADDS-ImportUsers
                break
            }
            20 {
                ADDS-ImportUsersToGroups
                break
            }
            
            ## Default options
            "menu" { 
                Menu-Page 0
                $killthis = $true
                break 
            }
            "back" {
                $page = $page - 1
                Menu-Page $page
                $killthis = $true
                break
            }
            "next" {
                $page = $page + 1
                Menu-Page $page
                $killthis = $true
                break
            }
            "print" { 
                Print-Test
                break 
            }
            0 { break }
            default { 
                #Clear-Host
                Write-Host "===================="
                Write-Host "Unknown Option"
                break 
            }

        }
        if(-not $killthis) {
            Write-Host "==== 7 for menu ===="
            Menu-Page $page $true
        }
        break
    }
    

}

Menu-Page 0