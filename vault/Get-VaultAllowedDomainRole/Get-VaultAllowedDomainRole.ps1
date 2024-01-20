<#
.Synopsis
   Identifies Role & PKI Secrets Engine in Vault
.DESCRIPTION
   RESTful-based. Retrieves Token via LDAP auth. Identifies Role & PKI Secrets Engine in Vault
.EXAMPLE
   .\Get-VaultAllowedDomainRole.ps1 -INGRESS_HOST 'api.localcompany.local' -VAULT_ADDR 'https://pki.myvaultserver.com:8200'
#>

[CmdletBinding()]
[Alias()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$VAULT_ADDR
    
    [Parameter(Mandatory=$true)]
    [string]$INGRESS_HOST
       
    )


$ErrorActionPreference='STOP'

#Enable TLS1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


$CREDs=Get-Credential -Message "Enter your LDAP Credentials"
$USERNAME=($CREDs.UserName).Split("\")[-1]
$PASSWORD=$($creds.GetNetworkCredential().password)

#Obtain Vault token with ldap login
$LDAP_LOGIN_ENDPOINT='/v1/auth/ldap/login/'
$URL=$VAULT_ADDR+$LDAP_LOGIN_ENDPOINT+$USERNAME
$HEADER=@{
    'accept'= '*/*'
    'Content-Type'='application/json'
}
$BODY=@{"password"=$PASSWORD}
$RESPONSE=Invoke-RestMethod -Method Post -UseBasicParsing -Uri $URL -Body $BODY
$TOKEN=$RESPONSE.auth.client_token


#Get a list of secret engines

$SECRET_ENGINES_ENDPOINT='/v1/sys/mounts'
$URL=$VAULT_ADDR+$SECRET_ENGINES_ENDPOINT
$HEADER=@{
        'accept'= '*/*'
        'X-Vault-Token'=$TOKEN
    }
$RESPONSE=Invoke-RestMethod -Method GET -UseBasicParsing -Uri $URL -Headers $HEADER
$SECRET_ENGINES = $RESPONSE.psobject.Properties.name

$SECRET_ENGINES_ENDPOINT='/v1/sys/mounts'
$URL=$VAULT_ADDR+$SECRET_ENGINES_ENDPOINT
$HEADER=@{
    'accept'= '*/*'
    'X-Vault-Token'=$TOKEN
}
$RESPONSE=Invoke-RestMethod -Method GET -UseBasicParsing -Uri $URL -Headers $HEADER


$COLLECTION_ENGINE=@()
    
foreach($ENGINE in $SECRET_ENGINES){
    $ENGINE_OBJ=$RESPONSE.($ENGINE)
    if($ENGINE_OBJ.accessor.length -lt 1){continue}
    $ENGINE_NAME=$ENGINE.TrimEnd("/")
    $OBJ=[pscustomobject]@{
        NAME=$ENGINE_NAME
        ACCESSOR=$ENGINE_OBJ.accessor
        Description=$ENGINE_OBJ.Description
        Type=$ENGINE_OBJ.type
    }
    $COLLECTION_ENGINE += $OBJ
}


#Get a list of roles from a PKI Secrets Engine
$PKI_ENGINES=$COLLECTION_ENGINE|?{$_.type -eq "pki"}


$COLLECTION_ROLES=@()
$HEADER=@{
        'accept'= '*/*'
        'X-Vault-Token'=$TOKEN
    }


foreach($ENGINE in $PKI_ENGINES){
   
    $ENGINE_ROLE_ENDPOINT="/v1/$($ENGINE.name)/roles?list=true"
    $URL=$VAULT_ADDR+$ENGINE_ROLE_ENDPOINT
    try{
        $RESPONSE=Invoke-RestMethod -Method GET -UseBasicParsing -Uri $URL -Headers $HEADER
        $ROLES=$RESPONSE.data.keys
    }catch{
        continue
    }
    

    foreach($ROLE in $ROLES){
        $ROLE_ENDPOINT="v1/$($ENGINE.name)/roles/$ROLE"
        $URL=$VAULT_ADDR+"/"+$ROLE_ENDPOINT
        try{
            $RESPONSE=Invoke-RestMethod -Method GET -UseBasicParsing -Uri $URL -Headers $HEADER
            $ALLOWED_DOMAINS=$RESPONSE.data.allowed_domains
        }catch{$ALLOWED_DOMAINS='ERROR'}
        
        $OBJ=[pscustomobject]@{
            ROLE=$ROLE
            ENGINE=$($ENGINE.name)
            Allowed_Domains=$ALLOWED_DOMAINS
        }
        $COLLECTION_ROLES += $OBJ
    }
}

$QUERY=$COLLECTION_ROLES|?{$INGRESS_HOST -in $_.Allowed_Domains}

if($QUERY.count -eq 0){
	write-host "No roles found matching Ingress name"
}

return $QUERY
