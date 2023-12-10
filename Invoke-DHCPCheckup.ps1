Import-Module DHCPServer
Import-Module ActiveDirectory
Import-Module DnsServer

function GetActiveActiveDhcpServers
{
    $DhcpServers = Get-DhcpServerInDC 

    $activeServers = @()

    if (!$DhcpServers)
    {
        Write-Host "[*] Error - No DHCP servers found in the domain"
        throw
    }

    foreach ($server in $DhcpServers)
    {
        # Check if the server is responding
        $error.Clear()
        try
        {
            $res = Get-DhcpServerSetting -ComputerName $server.DnsName -ErrorAction SilentlyContinue
        }
        catch
        {
            
        }

        if (!$error[0])
        {
            $activeServers += $server
        }
        else
        {
            Write-Host "[*] DHCP server $($server.DnsName.ToUpper()) is not responding!"
        }
    }

    return $activeServers.DnsName
}

function GetStrongUsers
{
    $strongGroupsSIDs = (
     "*-516", # Domain Controllers
     "*-512", # Domain Admins 
     "*-519", # Enterprise Admins 
     "*-544", # Administrators
     "*-1101" # DnsAdmins
     )
    $strongGroupsMembers = @()

    foreach ($groupSID in $strongGroupsSIDs)
    {
        $strongGroupsMembers += Get-ADGroup -Filter * | Where-Object -Property SID -like $groupSID | Get-ADGroupMember | Select-Object name
    }

    $strongGroupsMembers = $strongGroupsMembers | select name -unique 

    return $strongGroupsMembers.name

}

function Check-DnsCredentialSettings
{
    param(
    [parameter(Mandatory=$True)][String[]]$ActiveDhcpServers,
    [parameter(Mandatory=$True)][String[]]$strongGroupsMembers
    )

    # Check DNS Credentials Configuration
    $DhcpCredentials = @()

    foreach ($server in $ActiveDhcpServers)
    {

        $serverDisplayName = $server.ToUpper()
        $serverCN = $server.Split(".")[0].ToUpper()

        $serverDnsCredential = Get-DhcpServerDnsCredential -ComputerName $server

        if ($serverDnsCredential.UserName -ne "")
        {
            Write-Host "[*] $($serverDisplayName) - The credential used to create and own DNS records by the server is: '$($serverDnsCredential.UserName)'"
            $DhcpCredentials += ,($serverDnsCredential.UserName, $serverDisplayName)

            # Check if the DNS credential is strong
            if ($serverDnsCredential.UserName -in $strongGroupsMembers)
            {
                Write-Host "[*] $($serverDisplayName) - The credential '$($serverDnsCredential.UserName)' is a Member of a strong group. This means that a malicious DHCP client could spoof any DNS record in the zone."
            
            }
        }

        # If no DNS credential is configured, the machine account would be used
        else
        {
            Write-Host "[*] $($serverDisplayName) - DNS credential is not configured. The machine account '$($serverCN)$' would be used to create and own DNS records."
            $DhcpCredentials += ,(($serverCN + "$"), $serverDisplayName)
        
            # Check if the DNS credential is strong
            if ($serverCN -in $strongGroupsMembers)
            {
                Write-Host "[*] $($serverDisplayName) - The credential '$($serverCN)$' is a Member of a strong group. This means that a malicious DHCP client could spoof any DNS record in the zone."

            }
        }

        Write-Host ""
        
    }

    return $DhcpCredentials
}

function Check-DhcpNameProtectionSettings
{
    param(
    [parameter(Mandatory=$True)][String[]]$ActiveDhcpServers
    )

    foreach ($server in $ActiveDhcpServers)
    {
        $printed = $False
        $serverDisplayName = $server.ToUpper()

        # IPv4 scopes settings

        $serverV4DnsSettings = Get-DhcpServerv4DnsSetting -ComputerName $server

        if ($serverV4DnsSettings.NameProtection -eq $False)
        {
            Write-Host "[*] $($serverDisplayName) - Name protection disabled on the server level for IPv4. This means that new scopes would be created without name protection."
            $printed = $True
        }

        $serverV4Scopes = Get-DhcpServerv4Scope -ComputerName $server

        foreach ($scopeID in $serverV4Scopes)
        {
            $scopeV4DnsSettings = Get-DhcpServerv4DnsSetting -ComputerName $server -ScopeId $scopeID.ScopeId.IPAddressToString
            if ($scopeV4DnsSettings.NameProtection -eq $False)
            {
                Write-Host "[*] $($serverDisplayName) - Name protection disabled for the IPv4 scope: $($scopeID.Name) - $($scopeID.ScopeId.IPAddressToString)"
                $printed = $True
            }
        }


        # IPv6 scopes settings

        $serverV6DnsSettings = Get-DhcpServerv6DnsSetting -ComputerName $server

        if ($serverV6DnsSettings.NameProtection -eq $False)
        {
            Write-Host "[*] $($serverDisplayName) - Name protection disabled on the server level for IPv6. This means that new scopes would be created without name protection."
            $printed = $True
        }

        $serverV6Scopes = Get-DhcpServerv6Scope -ComputerName $server

        foreach ($scopeID in $serverV6Scopes)
        {
            $scopeV6DnsSettings = Get-DhcpServerv6DnsSetting -ComputerName $server -prefix $scopeID.prefix.IPAddressToString
            if ($scopeV6DnsSettings.NameProtection -eq $False)
            {
                Write-Host "[*] $($serverDisplayName) - Name protection disabled for the IPv6 scope: $($scopeID.Name) - $($scopeID.prefix.IPAddressToString)"
                $printed = $True
            }
        }

        if ($printed)
        {
            Write-Host ""
        }
    }
}

function Check-DnsUpdateProxyMembership
{
    $allDhcpServers = Get-DhcpServerInDC

    # Check for members of DNSUpdateproxy

    $updateProxymembers = Get-ADGroupMember "DNSUpdateProxy"

    foreach ($member in $updateProxymembers)
    {

        if (($member.name + "." + $domainName) -in $allDhcpServers.DnsName)
        {
            Write-Host "[*] $($member.name) is a DHCP server and a member of DNSUpdateProxy. DNS records created by this server are vulnerable to spoofing.`n"
        }
        else
        {
            Write-Host "[*] $($member.name) is not a DHCP server and a member of DNSUpdateProxy, it should be removed from the group.`n"
        }
    }
}

function Find-VulnerableDnsRecords
{
    param(
    [parameter(Mandatory=$True)][String[]]$DhcpCredentials
    )
    # Scan the permissions of all the DNS records in the zone to find vulnerable ones

    $authenticatedUsersRecords = @()
    $vulnerableRecords = @()
    $printed = $False


    $DnsRecords = Get-DnsServerResourceRecord -ZoneName $domainName

    foreach ($record in $DnsRecords)
    {
        
        $recordDisplayName = $record.HostName.ToUpper()
        $recordAcl = get-acl -path "AD:$($record.DistinguishedName)"
        

        # Check if the "Authenticated Users" group has write permissions over the record
        $authenticatedUsersWrite = $recordAcl.Access | Where-Object {($_.ActiveDirectoryRights -eq "GenericWrite") -and ($_.IdentityReference -eq "NT AUTHORITY\Authenticated Users")}

        if ($authenticatedUsersWrite)
        {
            $authenticatedUsersRecords += $recordDisplayName
        }


        # Check if any of the DHCP servers owns the record

        # DhcpCredentials were extracted at the previous "DNS Credentials" section
        foreach ($cred in $DhcpCredentials)
        {
           
            $DhcpServerCredential = $cred[0]
            $DhcpServerName = $cred[1]

            if ($recordAcl.Owner.Split('\\')[1] -eq $DhcpServerCredential)
            {
                if (!($recordDisplayName -in $vulnerableRecords))
                {
                    Write-Host "[*] The record '$($recordDisplayName)' is owned by the DHCP server $($DhcpServerName) with the credential '$($DhcpServerCredential)'. It is vulnerable to spoofing by malicious DHCP clients."
                    $vulnerableRecords += $recordDisplayName
                    $printed = $True
                }
            }
        }
    }

    if ($printed)
    {
        Write-Host ""
    }

    if ($authenticatedUsersRecords)
    {
        Write-Host "[*] Found DNS Records Writeable By Authenticated Users. Any user in the domain could spoof these records:" 

        foreach ($record in $authenticatedUsersRecords)
        {
            Write-Host "`t* $($record)"
        }
    }
}

function Invoke-DHCPCheckup
{
<#
    .SYNOPSIS
    This function performs a security checkup on all DHCP servers in the domain, finding common misconfigurations that could cause security risks.

    Author: Ori David (@oridavid123)
    
    .DESCRIPTION
    This function checks for the following misconfigurations:
    - DHCP DNS Credential security risks
    - DHCP name protection settings
    - DNSUpdateProxy group members
    - DNS records with weak permissions


    .PARAMETER DomainName
    The name of the Active Directory domain that we are scanning

    .EXAMPLE
    Invoke-DHCPCheckup -domainName akamai.test

    .LINK
    https://akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp


    #>
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$True)][String]$domainName,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )

    if($invalid_parameter)
    {
        Write-Host "[*] Error - $($invalid_parameter) is not a valid parameter"
        throw
    }


    Write-Host @"
  _____                 _               _____  _    _  _____ _____   _____ _               _                
 |_   _|               | |             |  __ \| |  | |/ ____|  __ \ / ____| |             | |               
   | |  _ ____   _____ | | _____ ______| |  | | |__| | |    | |__) | |    | |__   ___  ___| | ___   _ _ __  
   | | | '_ \ \ / / _ \| |/ / _ \______| |  | |  __  | |    |  ___/| |    | '_ \ / _ \/ __| |/ / | | | '_ \ 
  _| |_| | | \ V / (_) |   <  __/      | |__| | |  | | |____| |    | |____| | | |  __/ (__|   <| |_| | |_) |
 |_____|_| |_|\_/ \___/|_|\_\___|      |_____/|_|  |_|\_____|_|     \_____|_| |_|\___|\___|_|\_\\__,_| .__/ 
                                                                                                     | |    
Microsoft DHCP Server Risk Assessment                                                                |_|       
By Ori David of Akamai SIG

"@
    
    Write-Host "`n-----------------------------------------`nFinding Active DHCP Servers`n-----------------------------------------`n"
    
    
    # Get a list of active DHCP servers in the domain
    $ActiveDhcpServers = GetActiveActiveDhcpServers

    if ($ActiveDhcpServers.Count -ge 1)
    {
        Write-Host "[*] Found $($ActiveDhcpServers.Count) active DHCP servers:"
        foreach ($server in $ActiveDhcpServers)
        {
            Write-Host "`t* $($server.toUpper())"
        }
    }
    else
    {
        Write-Host "[*] No active DHCP servers found. Verify that the running user has permissions to access the DHCP servers."
        throw
    }




    # Get a list of strong group members
    $strongGroupMembers = GetStrongUsers


    Write-Host "`n-----------------------------------------`nChecking DNS Credentials Settings`n-----------------------------------------`n"
    
    $DhcpCredentials = Check-DnsCredentialSettings -ActiveDhcpServers $ActiveDhcpServers -strongGroupsMembers $strongGroupMembers


    Write-Host "`n-----------------------------------------`nChecking DHCP Name Protection Settings`n-----------------------------------------`n"

    Check-DhcpNameProtectionSettings -ActiveDhcpServers $ActiveDhcpServers


    Write-Host "`n-----------------------------------------`nChecking DNSUpdateProxy Group Membership`n-----------------------------------------`n"

    Check-DnsUpdateProxyMembership


    Write-Host "`n-----------------------------------------`nSearching For Vulnerable DNS Records`n-----------------------------------------`n"
   
    Find-VulnerableDnsRecords -DhcpCredentials $DhcpCredentials

}
