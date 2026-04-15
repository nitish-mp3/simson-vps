# Simson VPS Admin CLI Helper
# Makes it easy to manage accounts, nodes, and SIP endpoints without raw curl commands.
# Usage: .\admin-cli.ps1 -Command create-sip-endpoint -Params @{...}

param(
    [Parameter(Mandatory=$true)]
    [string]$Command,
    
    [hashtable]$Params = @{},
    
    [string]$VpsUrl = "https://simson-vps.niti.life",
    [string]$AdminToken = $env:SIMSON_ADMIN_TOKEN
)

if (-not $AdminToken) {
    Write-Error "SIMSON_ADMIN_TOKEN environment variable not set. Exiting."
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $AdminToken"
    "Content-Type" = "application/json"
}

function Invoke-AdminCall {
    param([string]$Method, [string]$Path, [object]$Body)
    $url = "$VpsUrl$Path"
    $splat = @{
        Uri     = $url
        Method  = $Method
        Headers = $headers
    }
    if ($Body) {
        $splat["Body"] = ($Body | ConvertTo-Json -Depth 10)
    }
    try {
        $response = Invoke-RestMethod @splat
        return $response
    } catch {
        Write-Error "Request failed: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            Write-Error "Response: $($_.Exception.Response | ConvertFrom-Json)"
        }
        exit 1
    }
}

switch ($Command) {
    "create-sip-endpoint" {
        $accountId = $Params.AccountId
        $extension = $Params.Extension
        $username = $Params.Username
        $password = $Params.Password
        $description = $Params.Description
        $routeTo = $Params.RouteTo
        $enabled = if ($Params.Enabled -eq $false) { $false } else { $true }
        
        if (-not $accountId -or -not $extension -or -not $username -or -not $password) {
            Write-Error "Required: -Params @{AccountId='...'; Extension='1001'; Username='desk1'; Password='pass'; Description='optional'; RouteTo='optional'; Enabled=\$true}"
            exit 1
        }
        
        $body = @{
            extension = $extension
            username = $username
            password = $password
            description = $description
            route_to = $routeTo
            enabled = $enabled
        }
        
        Write-Host "Creating SIP endpoint: ext=$extension user=$username"
        $result = Invoke-AdminCall POST "/admin/accounts/$accountId/sip-endpoints" $body
        Write-Host "✓ Created:" ($result | ConvertTo-Json) -ForegroundColor Green
    }
    
    "list-sip-endpoints" {
        $accountId = $Params.AccountId
        if (-not $accountId) {
            Write-Error "Required: -Params @{AccountId='...'}"
            exit 1
        }
        
        Write-Host "Listing SIP endpoints for account: $accountId"
        $result = Invoke-AdminCall GET "/admin/accounts/$accountId/sip-endpoints"
        $result | ForEach-Object {
            Write-Host "  [$($_.extension)] $($_.username) - $($_.description)" $(if (-not $_.enabled) { "(DISABLED)" })
        }
    }
    
    "delete-sip-endpoint" {
        $endpointId = $Params.EndpointId
        if (-not $endpointId) {
            Write-Error "Required: -Params @{EndpointId='...'}"
            exit 1
        }
        
        Write-Host "Deleting SIP endpoint: $endpointId"
        Invoke-AdminCall DELETE "/admin/sip-endpoints/$endpointId"
        Write-Host "✓ Deleted" -ForegroundColor Green
    }
    
    "reload-sip" {
        Write-Host "Reloading Asterisk PJSIP module..."
        $result = Invoke-AdminCall POST "/admin/asterisk/reload-sip"
        Write-Host "✓ Reload result: $result" -ForegroundColor Green
    }
    
    "list-accounts" {
        Write-Host "Listing all accounts..."
        $result = Invoke-AdminCall GET "/admin/accounts"
        $result | ForEach-Object {
            Write-Host "  [$($_.id)] $($_.name) - Nodes: $($_.max_nodes) / Calls: $($_.max_calls) - $($_.license_status)"
        }
    }
    
    "health" {
        $result = Invoke-AdminCall GET "/admin/health"
        Write-Host "VPS Health:" ($result | ConvertTo-Json) -ForegroundColor Green
    }
    
    default {
        Write-Error @"
Unknown command: $Command

Available commands:
  create-sip-endpoint    Create a new SIP phone account
  list-sip-endpoints     List SIP endpoints for an account
  delete-sip-endpoint    Delete a SIP endpoint
  reload-sip             Reload Asterisk config
  list-accounts          List all accounts
  health                 Check VPS health

Examples:
  .\admin-cli.ps1 create-sip-endpoint -Params @{
      AccountId = 'myaccount'
      Extension = '1001'
      Username = 'desk1'
      Password = 'MySecretPass123'
      Description = 'Front desk phone'
      RouteTo = ''
  }
  
  .\admin-cli.ps1 list-sip-endpoints -Params @{AccountId='myaccount'}
  .\admin-cli.ps1 reload-sip
  .\admin-cli.ps1 health
"@
        exit 1
    }
}
