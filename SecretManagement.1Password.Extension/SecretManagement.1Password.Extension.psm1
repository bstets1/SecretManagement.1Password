using namespace Microsoft.PowerShell.SecretManagement

function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName,

        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $vaultName).VaultParameters
    )

    $VaultParameters = $AdditionalParameters
    $accountName = $VaultParameters.AccountName
    $emailAddress = $VaultParameters.EmailAddress
    $secretKey = $VaultParameters.SecretKey
    Write-Verbose "SecretManagement: Testing Vault ${VaultName} for Account ${accountName}"

    if (-not $VaultName) { throw '1Password: You must specify a Vault Name to test' }
    if (-not $VaultParameters.AccountName) { throw '1Password: You must specify a 1Password Account to test' }
    if (-not $VaultParameters.EmailAddress) { throw '1Password: You must specify an Email for your 1Password Account to test' }
    if (-not $VaultParameters.SecretKey) { throw '1Password: You must specify an SecretKey for your 1Password Account to test' }

    Write-Verbose "Test listing vaults"
    $vaults = & op vault list 2>$null | ConvertFrom-Json

    if ($null -eq $vaults) {
        if ( $null -eq [System.Environment]::GetEnvironmentVariable("OP_SESSION_$accountName") ) {
            Write-Verbose "Attempt login with shorthand and grab session token"
            $token = & op account add $accountName --raw

            if ( $null -eq $token ) {
                Write-Verbose "Attempt login with all parameters"
                $token = & op account add $accountName $emailAddress $secretKey --raw
            }
        }
        else {
            Write-Verbose "Attempt login with shorthand and grab session token"
            & op account add $accountName
        }

        Write-Verbose "Cache session token to [OP_SESSION_$accountName] - $token"
        [System.Environment]::SetEnvironmentVariable("OP_SESSION_$accountName", $token)

        Write-Verbose "Test listing vaults final"
        $vaults = & op vault list 2>$null | ConvertFrom-Json
    }

    $Vaults.name -contains $VaultName
}

function Get-SecretInfo {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName, Mandatory)]
        [string]$VaultName,
        [Parameter()]
        [string]$Filter,
        [Parameter()]
        [hashtable] $AdditionalParameters
    )

    $items = & op item list --categories Login,Password --vault $VaultName --format=json | ConvertFrom-Json

    $keyList = [Collections.ArrayList]::new()

    foreach ($item in $items) {
        if ( $keyList.Contains(($item.title).ToLower()) ) {
            Write-Verbose "Get-SecretInfo: An item with the same key has already been added. Key: [$($item.title)]"
        }
        else {
            $type = switch ($item.category) {
                'LOGIN' { [SecretType]::PSCredential }
                'PASSWORD' { [SecretType]::SecureString }
                Default { [SecretType]::Unknown }
            }

            Write-Verbose $item.title
            [SecretInformation]::new(
                $item.title,
                $type,
                $VaultName
            )
            $keyList.Add(($item.title).ToLower())
        }
    }
}

function Get-Secret {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Name,
        [Parameter()]
        [string]$Filter,
        [Parameter()]
        [string]$VaultName,
        [Parameter()]
        [hashtable] $AdditionalParameters
    )
    
    $username = & op item get $Name --fields username --vault $VaultName --format=json | ConvertFrom-Json
    $password = & op item get $Name --fields password --vault $VaultName --format=json | ConvertFrom-Json
    
    [securestring]$secureStringPassword = ConvertTo-SecureString $password.value -AsPlainText -Force
    
    $output = [PSCredential]::new(
        $username.value,
        $secureStringPassword
    )
    

    $output
}

function Set-Secret {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Name,
        [Parameter()]
        [object]$Secret,
        [Parameter()]
        [string]$VaultName,
        [Parameter()]
        [hashtable] $AdditionalParameters
    )

    $item = & op item get $Name --fields title --vault $VaultName 2>$null
    $verb = if ($null -eq $item) { 'create' } else { 'edit' }
    Write-Verbose $verb
    $data = @{}
    $commandArgs = [Collections.ArrayList]::new()

    Write-Verbose "Secret type [$($Secret.GetType().Name)]"
    switch ($Secret.GetType()) {
        { $_.IsValueType } {
            $category = "Password"
            Write-Verbose "Processing [string] as $category"
            $commandArgs.Add($verb) | Out-Null
            $commandArgs.Add('item') | Out-Null

            if ('create' -eq $verb ) {
                Write-Verbose "Creating $Name"
                $data = op item template get $category | ConvertFrom-Json -AsHashtable
                $data.password = $Secret
                $endcodedData = $data | ConvertTo-Json | op encode

                $commandArgs.Add($category) | Out-Null
                $commandArgs.Add($endcodedData) | Out-Null
                $commandArgs.Add("Title=$Name") | Out-Null
            }
            else {
                Write-Verbose "Updating $item"
                $commandArgs.Add($item) | Out-Null
                $commandArgs.Add("password=$Secret") | Out-Null
            }
            break
        }
        { $_.Name -eq 'securestring' } {
            $category = "Password"
            Write-Verbose "Processing [securestring] as $category"
            $commandArgs.Add($verb) | Out-Null
            $commandArgs.Add('item') | Out-Null

            if ('create' -eq $verb ) {
                Write-Verbose "Creating $Name"
                $data = op item template get $category | ConvertFrom-Json -AsHashtable
                $data.password = ConvertFrom-SecureString -SecureString $Secret -AsPlainText
                $endcodedData = $data | ConvertTo-Json | op encode

                $commandArgs.Add($category) | Out-Null
                $commandArgs.Add($endcodedData) | Out-Null
                $commandArgs.Add("Title=$Name") | Out-Null
            }
            else {
                Write-Verbose "Updating $item"
                $commandArgs.Add($item) | Out-Null
                $commandArgs.Add("password=$(ConvertFrom-SecureString -SecureString $Secret -AsPlainText)") | Out-Null
            }
            break
        }
        { $_.Name -eq 'PSCredential' } {
            $category = "Login"
            Write-Verbose "Processing [PSCredential] as $category"
            $commandArgs.Add($verb) | Out-Null
            $commandArgs.Add('item') | Out-Null

            if ('create' -eq $verb ) {
                Write-Verbose "Creating $Name"
                $data = op item template get $category | ConvertFrom-Json -AsHashtable
                $data.fields | ForEach-Object {
                    if ($_.name -eq 'username') { $_.value = $Secret.UserName }
                    if ($_.name -eq 'password') { $_.value = $Secret.GetNetworkCredential().Password }
                }
                $endcodedData = $data | ConvertTo-Json | op encode

                $commandArgs.Add($category) | Out-Null
                $commandArgs.Add($endcodedData) | Out-Null
                $commandArgs.Add("Title=$Name") | Out-Null
            }
            else {
                Write-Verbose "Updating $item"
                $commandArgs.Add($item) | Out-Null
                $commandArgs.Add("username=$($Secret.UserName)") | Out-Null
                $commandArgs.Add("password=$(ConvertFrom-SecureString -SecureString $Secret -AsPlainText)") | Out-Null
            }
            break
        }
        Default {}
    }

    $commandArgs.Add('--vault') | Out-Null
    $commandArgs.Add($VaultName) | Out-Null

    $sanitizedArgs = $commandArgs | ForEach-Object {
        if ($_ -like 'password=*') {
            'password=*****'
        }
        else {

            $_
        }
    }
    Write-Verbose ($sanitizedArgs -join ' ')
    & op @commandArgs

    return $?
}

function Remove-Secret {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Name,
        [Parameter()]
        [string]$VaultName,
        [Parameter()]
        [hashtable] $AdditionalParameters
    )


    $verb = 'delete'
    $commandArgs = [Collections.ArrayList]::new()
    $commandArgs.Add($verb) | Out-Null
    $commandArgs.Add("item") | Out-Null
    $commandArgs.Add($Name) | Out-Null
    $commandArgs.Add('--vault') | Out-Null
    $commandArgs.Add($VaultName) | Out-Null

    Write-Verbose ($commandArgs -join ' ')
    & op @commandArgs

    return $LASTEXITCODE -eq 0
}
