Function Connect-F5 {
    <#
    .SYNOPSIS
    Establishes a connection to an F5 BIG-IP and saves the connection information
         to a global variable to be used by subsequent Rest commands.
    NOTE: 20m validity period by default - I am not handling the extension of that
    nor reissuance at this time.

    .DESCRIPTION
    Attempt to esablish a connection to an F5 BIG-IP and if the connection succeeds
         then it is saved to a global variable to be used for subsequent Rest commands.

    .EXAMPLE
    PS C:\>  Connect-F5 -Hostname bigip.local -Username ausername -Password apassword

    #>
   Param(
      [Parameter(Mandatory=$true)][String]$Hostname,
      [Parameter(Mandatory=$true)][String]$Username,
      [Parameter(Mandatory=$false)][String]$Password,
      [Parameter(Mandatory=$false)][Bool]$Troubleshoot = $false,
      [Parameter(Mandatory=$false)][Bool]$SkipCertificateCheck = $false
   )

   begin {}

   Process {
      If($Password -eq ""){
         $Password = Read-Host 'Password' -MaskInput
      }

      $TokenBody = @{
         username = $Username
         password = $Password
         loginProviderName = "tmos"
      } | ConvertTo-JSON

      Try {
         $ProgressPreference = 'SilentlyContinue'
         If($SkipCertificateCheck){ $queryParams += @{SkipCertificateCheck = $true} } Else { $queryParams += @{SkipCertificateCheck = $false } }

         $Results = (Invoke-WebRequest "https://$($Hostname)/mgmt/shared/authn/login" -Method POST -ContentType 'application/json' -Body $TokenBody @queryParams -UseBasicParsing | ConvertFrom-JSON)
         If($Troubleshoot){ $Results }
         $token = $($Results.token.token)

      } catch {
         If($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Error "`nThe F5 BIG-IP connection failed - Unauthorized`n"
            Break
         } else {
            Write-Error "Error connecting to F5 BIG-IP"
            Write-Error "`n($_.Exception.Message)`n"
            Break
         }
      }

      $Headers = @{}
      $Headers.Add("X-F5-Auth-Token", $token)
      $Headers.Add("Content-Type", "application/json")

      $global:F5Connection = new-object PSObject -Property @{
         'Headers' = $Headers
         'Token' = ($Results.token)
         'F5APIHostname' = $Hostname
         'F5APIUsername' = $Username
         'F5ApiPassword' = $Password
         'F5ApiTroubleshoot' = $Troubleshoot
         'F5SkipCertificateCheck' = $Troubleshoot
      }
      If($Troubleshoot){ $global:F5Connection }
   }

   end {}
}

Function Send-F5RestRequest {
    <#
    .SYNOPSIS
    Invoke a request to the F5 LTM API.

    .DESCRIPTION
    Invoke a request to the F5 LTM API.

    .EXAMPLE
    PS C:\> Send-F5RestRequest -Method GET -URI "/mgmt/tm/sys/version"

    .EXAMPLE
    PS C:\> (Send-F5RestRequest -Method GET -URI "/mgmt/tm/sys/version").Content | ConvertFrom-JSON

    #>
   Param(
      [Parameter(Mandatory=$false)][String]$Method = "Get",
      [Parameter(Mandatory=$true)][String]$Uri,
      [Parameter(Mandatory=$false)][HashTable]$Headers,
      [Parameter(Mandatory=$false)][String]$Body
   )

   ## Check Token
   If(($global:F5Connection.Token.startTime).AddMinutes(18) -lt (get-Date)){
      Connect-F5 -Hostname $global:F5Connection.F5APIHostname -Username $global:F5Connection.F5APIUsername -Password $global:F5Connection.F5APIPassword -Troubleshoot $global:F5Connection.F5ApiTroubleshoot -SkipCertificateCheck $global:F5Connection.F5SkipCertificateCheck
   }

   Try {
      If($Headers -eq $null) { $Headers = $global:F5Connection.Headers }
      If($global:F5Connection.F5SkipCertificateCheck){ $queryParams += @{SkipCertificateCheck = $true} } Else { $queryParams += @{SkipCertificateCheck = $false } }
      If($Body -ne ""){ $queryParams += @{Body = $Body}}

      $ProgressPreference = 'SilentlyContinue'
      $Results = Invoke-WebRequest "https://$($global:F5Connection.F5APIHostname)$($Uri)" -Method $Method -Headers $Headers -SkipHeaderValidation @queryParams -UseBasicParsing
      If($Troubleshoot){ $Results }
      Return $Results

   } catch {
      If($_.Exception.Response.StatusCode -eq "Unauthorized") {
         Write-Host -ForegroundColor Red "`nThe F5 BIG-IP connection failed - Unauthorized`n"
         Break
      } else {
         Write-Error "Error connecting to F5 BIG-IP"
         Write-Error "`n$($_)`n"
         Break
      }
   }
}

Function Get-F5ExpiringOrExpiredCertificates {
    <#
    .SYNOPSIS
    Get an object containing all certificates nearing expiration along with the SSL profiles
    they exist in and any virtuals where the SSL profile is utilized.

    .DESCRIPTION
    Get an object containing all certificates nearing expiration along with the SSL profiles
    they exist in and any virtuals where the SSL profile is utilized.

    .EXAMPLE
    PS C:\> Get-F5ExpiringOrExpiredCertificates -ExpiresIn 30

    .EXAMPLE
    PS C:\> (Get-F5ExpiringOrExpiredCertificates -ExpiresIn 30) | Where { $_.Profile -ne $null -And $_.Virtuals -ne $null } | Select Certificate,Profile,Expiration,Subject,@{name='virtuals';expr={$_.Virtuals | Out-String}}

    #>
   param(
      [Parameter(Mandatory=$false)][Int]$ExpiresIn = 30,
      [Parameter(Mandatory=$false)][Bool]$GetVirtuals = $true
   )

   $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
   $allExpiringOrExpiredPublicKeys = ((Send-F5RestRequest -Uri "/mgmt/tm/sys/file/ssl-cert").Content | ConvertFrom-JSON).items | Select Name,partition,subject,subjectAlternativeName,@{name='expirationDate';expression={$origin.addseconds($_.expirationDate)}} | Where { $_.expirationDate -lt (Get-date).AddDays($ExpiresIn) }
   $allClientSSLProfiles = ((Send-F5RestRequest -Uri "/mgmt/tm/ltm/profile/client-ssl").Content | ConvertFrom-JSON).items | Select name,partition,cert,chain,key
   If($GetVirtuals){
      $allVirtuals = ((Send-F5RestRequest -Uri "/mgmt/tm/ltm/virtual").Content | ConvertFrom-JSON).items | Select name,partition,description,@{name='profiles';expression={((Send-F5RestRequest -Uri "$($_.profilesReference.link.Replace('https://localhost',''))").Content | ConvertFrom-JSON).items | Select Name}}
   }
   $ExpiringCerts = @()
   ForEach($aExpiringOrExpiredPublicKey in $allExpiringOrExpiredPublicKeys){
      $numProfiles = 0
      ForEach($aClientSSLProfile in $allClientSSLProfiles){
         If($aClientSSLProfile.cert -eq "/$($aExpiringOrExpiredPublicKey.partition)/$($aExpiringOrExpiredPublicKey.name)"){
            $numProfiles+=1
            $numVirtuals = 0
            If($GetVirtuals){
               $Virtuals = @()
               ForEach($aVirtual in $allVirtuals){
                  ForEach($aVirtualProfile in $aVirtual.profiles){
                     If("/$($aVirtual.partition)/$($aVirtualProfile.name)" -eq "/$($aClientSSLProfile.partition)/$($aClientSSLProfile.name)"){
                        $numVirtuals+=1
                        $Virtuals += New-Object -TypeName PSObject -Property @{name="/$($aVirtual.partition)/$($aVirtual.name)"; Description=$aVirtual.description}
                     }
                  }
               }
            }
            If($numVirtuals -ne 0){
               $ExpiringCerts += New-Object -TypeName PSObject -Property @{Certificate="/$($aExpiringOrExpiredPublicKey.partition)/$($aExpiringOrExpiredPublicKey.name)"; Partition=$aExpiringOrExpiredPublicKey.partition; Profile="/$($aClientSSLProfile.partition)/$($aClientSSLProfile.name)"; Expiration=$aExpiringOrExpiredPublicKey.expirationDate; Subject=$aExpiringOrExpiredPublicKey.subject; SubjectAltName=$aExpiringOrExpiredPublicKey.subjectAlternativeName; Virtuals=$($Virtuals)}
            }Else{
               $ExpiringCerts += New-Object -TypeName PSObject -Property @{Certificate="/$($aExpiringOrExpiredPublicKey.partition)/$($aExpiringOrExpiredPublicKey.name)"; Partition=$aExpiringOrExpiredPublicKey.partition; Profile="/$($aClientSSLProfile.partition)/$($aClientSSLProfile.name)"; Expiration=$aExpiringOrExpiredPublicKey.expirationDate; Subject=$aExpiringOrExpiredPublicKey.subject; SubjectAltName=$aExpiringOrExpiredPublicKey.subjectAlternativeName; Virtuals=$null}
            }
         }
      }
      If($numProfiles -eq 0){ $ExpiringCerts += New-Object -TypeName PSObject -Property @{Certificate="/$($aExpiringOrExpiredPublicKey.partition)/$($aExpiringOrExpiredPublicKey.name)"; Partition=$aExpiringOrExpiredPublicKey.partition; Profile=$null; Expiration=$aExpiringOrExpiredPublicKey.expirationDate; Subject=$aExpiringOrExpiredPublicKey.subject; SubjectAltName=$aExpiringOrExpiredPublicKey.subjectAlternativeName} }
   }

   Return $ExpiringCerts
}

Function Get-F5Certificates {
   <#
    .SYNOPSIS
    Get all certificates

    .DESCRIPTION
    Get all certificates

    .EXAMPLE
    PS C:\> Get-F5Certificates

   #>
   Try {
      $Headers = $global:F5Connection.Headers

      $Results = ((Send-F5RestRequest -Method Get -Uri "/mgmt/tm/sys/file/ssl-cert" -Headers $Headers)) | ConvertFrom-JSON
      Return $Results.items
   } Catch {
      Write-Error "`n($_.Exception.Message)`n"
   }
}

Function Add-F5File {
   <#
    .SYNOPSIS
    Upload file to /var/config/rest/bulk

    .DESCRIPTION
    Upload file to /var/config/rest/bulk

    .EXAMPLE
    PS C:\> Add-F5File -SourceFile "C:\Users\username\certbot\LE_PROD\1821180437\testserver3.local\cert.key" -DestinationFileName "testserver3.local.key"

   #>
   Param(
      [Parameter(Mandatory=$true)][String]$SourceFile,
      [Parameter(Mandatory=$true)][String]$DestinationFileName
   )

   Try {
      $File = [IO.File]::ReadAllBytes($SourceFile)
      $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
      $encodedfile = $enc.GetString($File)
      $range = "0-" + ($encodedfile.Length - 1) + "/" + $encodedfile.Length  # you need to calculate the size of this file to use in the REST Header

      $Headers = $global:F5Connection.Headers
      $Headers.Remove("Content-Range")
      $Headers.Add("Content-Range", $range)

      $Results = ((Send-F5RestRequest -Method POST -Uri "/mgmt/shared/file-transfer/bulk/uploads/$($DestinationFileName)" -Body $encodedfile -Headers $Headers).content) | ConvertFrom-JSON
      Return $Results
   } Catch {
      Write-Error "`n($_.Exception.Message)`n"
   }
}

Function Import-F5PrivateKey {
   <#
    .SYNOPSIS
    Create Private Key using file which exists on the filesystem.

    .DESCRIPTION
    Create Private Key using file which exists on the filesystem.

    .EXAMPLE
    PS C:\> Import-F5PrivateKey -SourceFile "/var/config/rest/bulk/testserver3.local.key" -DestinationName "/Customer1/testserver3.local.20241001"

   #>
   Param(
      [Parameter(Mandatory=$true)][String]$SourceFile,
      [Parameter(Mandatory=$true)][String]$DestinationName
   )

   $payload = @{
      'command' = 'install'
      'name' = $DestinationName
      'from-local-file' = $SourceFile
   } | ConvertTo-JSON

   $Headers = $global:F5Connection.Headers

   $Results = ((Send-F5RestRequest -Method POST -Uri "/mgmt/tm/sys/crypto/key" -Body $payload -Headers $Headers)) | ConvertFrom-JSON
   Return $Results
}

Function Import-F5PublicKey {
    <#
    .SYNOPSIS
    Create public Key using file which exists on the filesystem.

    .DESCRIPTION
    Create public Key using file which exists on the filesystem.

    .EXAMPLE
    PS C:\> Import-F5PublicKey -SourceFile "/var/config/rest/bulk/testserver3.local.cer" -DestinationName "/Customer1/testserver3.local.20241001"

    #>
    Param(
      [Parameter(Mandatory=$true)][String]$SourceFile,
      [Parameter(Mandatory=$true)][String]$DestinationName
   )

   If($SourceFile -Like "https://*"){ Write-Host "url attempt"; Break }
   $payload = @{
      'command' = 'install'
      'name' = $DestinationName
      'from-local-file' = $SourceFile
   } | ConvertTo-JSON

   $Headers = $global:F5Connection.Headers

   $Results = ((Send-F5RestRequest -Method POST -Uri "/mgmt/tm/sys/crypto/cert" -Body $payload -Headers $Headers)) | ConvertFrom-JSON
   Return $Results
}

Function Get-F5ClientSSLProfile {
    <#
    .SYNOPSIS
    Get Client SSL Profile.

    .DESCRIPTION
    Get Client SSL Profile.

    .EXAMPLE
    PS C:\> Get-F5ClientSSLProfile -ProfileName "~Customer1~testserver3.local"

    #>
   Param(
      [Parameter(Mandatory=$false)][String]$ProfileName
   )

    $payload = @{
       'name' = $ProfileName
       'defaultsFrom' = $DefaultsFrom
       'cert' = $PublicKey
       'key' = $PrivateKey
       'chain' = $Chain

   } | ConvertTo-JSON

   $Headers = $global:F5Connection.Headers

   $Results = ((Send-F5RestRequest -Method Get -Uri "/mgmt/tm/ltm/profile/client-ssl" -Headers $Headers)) | ConvertFrom-JSON
   Return $Results.items
}

Function New-F5ClientSSLProfile {
    <#
    .SYNOPSIS
    Create Client SSL Profile.

    .DESCRIPTION
    Create Client SSL Profile.

    .EXAMPLE
    PS C:\> New-F5ClientSSLProfile -ProfileName "~Customer1~testserver3.local" -PublicKey "/Customer1/testserver3.local.20241001" -PrivateKey "/Customer1/testserver3.local.20241001" -Chain "R11.crt"

    #>
   Param(
      [Parameter(Mandatory=$true)][String]$ProfileName,
      [Parameter(Mandatory=$false)][String]$DefaultsFrom = "clientssl",
      [Parameter(Mandatory=$true)][String]$PublicKey,
      [Parameter(Mandatory=$true)][String]$PrivateKey,
      [Parameter(Mandatory=$true)][String]$Chain
   )

    $payload = @{
       'name' = $ProfileName
       'defaultsFrom' = $DefaultsFrom
       'cert' = $PublicKey
       'key' = $PrivateKey
       'chain' = $Chain

   } | ConvertTo-JSON

   $Headers = $global:F5Connection.Headers

   $Results = ((Send-F5RestRequest -Method POST -Uri "/mgmt/tm/ltm/profile/client-ssl/" -Body $payload -Headers $Headers)) | ConvertFrom-JSON
   Return $Results
}

Function Update-F5ClientSSLProfile {
    <#
    .SYNOPSIS
    Update Client SSL Profile.

    .DESCRIPTION
    Update Client SSL Profile.

    .EXAMPLE
    PS C:\> Update-F5ClientSSLProfile -ProfileName "~Customer1~testserver3.local" -PublicKey "/Customer1/testserver3.local.20250601" -PrivateKey "/Customer1/testserver3.local.20250601" -Chain "R11.crt"

    .EXAMPLE
    PS C:\> Update-F5ClientSSLProfile -ProfileName "~Customer1~testserver3.local" -PublicKey "/Customer1/testserver3.local.20250601"

    #>
    Param(
      [Parameter(Mandatory=$true)][String]$ProfileName,
      [Parameter(Mandatory=$false)][String]$PublicKey,
      [Parameter(Mandatory=$false)][String]$PrivateKey,
      [Parameter(Mandatory=$false)][String]$Chain
   )

   $ProfileName = $ProfileName.Replace("/","~")

   $Keys = (Send-F5RestRequest -Uri "/mgmt/tm/ltm/profile/client-ssl/$($ProfileName)" -Headers $Headers) | ConvertFrom-JSON
   If($PublicKey -eq "") { $PublicKey = $Keys.cert }
   If($PrivateKey -eq "") { $PrivateKey = $Keys.key }
   If($Chain -eq "") { $Chain = $Keys.chain }

   $payload = @{
         'key' = $PrivateKey
         'cert' = $PublicKey
         'chain' = $chain
   } | ConvertTo-JSON

   $Headers = $global:F5Connection.Headers

   $Results = (Send-F5RestRequest -Method PATCH -Uri "/mgmt/tm/ltm/profile/client-ssl/$($ProfileName)" -Body $payload -Headers $Headers) | ConvertFrom-JSON
   Return $Results
}

Function Invoke-F5BashCmd {
    <#
    .SYNOPSIS
    Run a bash command.

    .DESCRIPTION
    Run a bash command.

    .EXAMPLE
    PS C:\> Invoke-F5BashCmd -Command "cat /config/filestore/files_d/Customer1_d/certificate_d/\:Customer1\:testserver3.local.20250601*"

    #>
    Param(
      [Parameter(Mandatory=$true)][String]$Command
   )

   $payload = @{
         'command' = 'run'
         'utilCmdArgs' = "-c '$($Command)'"
   } | ConvertTo-JSON

   $Headers = $global:F5Connection.Headers

   $Results = (Send-F5RestRequest -Method POST -Uri "/mgmt/tm/util/bash" -Body $payload -Headers $Headers) | ConvertFrom-JSON
   Return $Results.commandResult
}

Function Get-Pools {
   <#
   .SYNOPSIS
   Get all pools.

   .DESCRIPTION
   Get all pools.

   .EXAMPLE
   PS C:\> Get-Pools

   #>
   Param(
      [Parameter(Mandatory=$false)][String]$Filter
   )

   $Headers = $global:F5Connection.Headers

   $Results = (Send-F5RestRequest -Uri "/mgmt/tm/ltm/pool?$($Filter)" -Body $payload -Headers $Headers) | ConvertFrom-JSON
   Return $Results.items
}

Function Get-Virtuals {
   <#
   .SYNOPSIS
   Get all virtuals.

   .DESCRIPTION
   Get all virtuals.

   .EXAMPLE
   PS C:\> Get-Virtuals

   #>
   Param(
      [Parameter(Mandatory=$false)][String]$Filter
   )

   $Headers = $global:F5Connection.Headers

   $Results = (Send-F5RestRequest -Uri "/mgmt/tm/ltm/virtual?$($Filter)" -Body $payload -Headers $Headers) | ConvertFrom-JSON
   Return $Results.items
}

Function Get-Nodes {
   <#
   .SYNOPSIS
   Get all nodes.

   .DESCRIPTION
   Get all nodes.

   .EXAMPLE
   PS C:\> Get-Nodes

   #>

   $Headers = $global:F5Connection.Headers

   $Results = (Send-F5RestRequest -Uri "/mgmt/tm/ltm/node" -Body $payload -Headers $Headers) | ConvertFrom-JSON
   Return $Results.items
}
