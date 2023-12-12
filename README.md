# Invoke-DHCPCheckup.ps1

Invoke-DHCPCheckup is a tool meant to identify risky DHCP and DNS configurations in Active Directory environments.
For additional information please refer to our blogpost:
https://akamai.com/blog/security-research/spoofing-dns-by-abusing-dhcp



The tool identifies the following misconfigurations:

### DNS Credential
- DNS Credential is not configured
- The configured DNS credential is of a strong user

### Name Protection
- Name protection is not enabled on a scope
- Name protection is not enabled by default on new scopes

### DNSUpdateProxy
- Display group members 
- Specify whether the members are DHCP servers

### Weak record ACLs
- List records owned by DHCP servers (Managed Records)
- List records that could be overwritten by authenticated users


## Usage
Invoke-DHCPCheckup relies on the DHCP server management API and requires to run as a user that is part of the "DHCP Administrators" and "DNSAdmins" groups.

It also requires the following Powershell modules: 
- ActiveDirectory
- DHCPServer
- DNSServer

To run use the following commands:
```
PS C:\Users\Administrator> Import-Module C:\Users\Administrator\Desktop\DHCP-Checkup.ps1
PS C:\Users\Administrator> Invoke-DHCPCheckup -domainName <domain_name> -dnsServerName <adidns_server_fqdn>
```

For domains that use languages other than english as their default language, adjust the names of the strong groups at line 45 if necessary.

-------
Copyright 2023 Akamai Technologies Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.



