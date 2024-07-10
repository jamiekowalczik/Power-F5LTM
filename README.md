## Power-F5LTM
Powershell module for F5 BIG-IP LTM
## Powershell module to provide CRUD functionality for F5 BIG-IP LTM certificates, client-ssl profiles and 
## some other stuff..
### Import Module and Connect to F5 BIG-IP LTM
```
PS > Import-Module Power-F5LTM
PS > Connect-F5 -Hostname bigip.local -Username ausername
Password: ************************************
PS >
```
### Upload files
```
PS > Add-F5File -SourceFile "C:\Users\username\certbot\LE_PROD\1821180437\testserver3.local\cert.key" -DestinationFileName "testserver3.local.key"

PS > Add-F5File -SourceFile "C:\Users\username\certbot\LE_PROD\1821180437\testserver3.local\cert.cer" -DestinationFileName "testserver3.local.cer"
```
### Create Private and Public Key pair from uploaded files
```
PS > Add-F5PrivateKey -SourceFile "/var/config/rest/bulk/testserver3.local.key" -DestinationName "/Customer1/testserver3.local.20241001"

PS > Add-F5PublicKey -SourceFile "/var/config/rest/bulk/testserver3.local.cer" -DestinationName "/Customer1/testserver3.local.20241001"
```
### Create new client-ssl profile
```
PS > New-F5ClientSSLProfile -ProfileName "/Customer1/testserver3.local" -PublicKey "/Customer1/testserver3.local.20241001" -PrivateKey "/Customer1/testserver3.local.20241001" -Chain "R11.crt" 
```
### Update client-ssl profile
```
PS > Update-F5ClientSSLProfile -ProfileName "/Customer1/testserver3.local" -PublicKey "/Customer1/testserver3.local.20250601" -PrivateKey "/Customer1/testserver3.local.20250601" -Chain "R11.crt"
```
### Commands
```
PS > Get-Command -Module Power-F5LTM

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Add-F5File                                         1.0.0.0    power-f5ltm
Function        Add-F5PrivateKey                                   1.0.0.0    power-f5ltm
Function        Add-F5PublicKey                                    1.0.0.0    power-f5ltm
Function        Connect-F5                                         1.0.0.0    power-f5ltm
Function        Get-F5ExpiringOrExpiredCertificates                1.0.0.0    power-f5ltm
Function        Invoke-F5BashCmd                                   1.0.0.0    power-f5ltm
Function        New-F5ClientSSLProfile                             1.0.0.0    power-f5ltm
Function        Send-F5RestRequest                                 1.0.0.0    power-f5ltm
Function        Update-F5ClientSSLProfile                          1.0.0.0    power-f5ltm
```
