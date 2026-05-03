# firewall.ps1 
# 17/04/2026 - 17:10
# Yuri

function check_firewall {

    <#
    Analisa regras do Firewall do Windows em busca de riscos "Any-to-Any" e 
	identifica regras de entrada permissivas e exporta todas as regras para JSON.
    #>

    $exportPath = ".\FirewallRules_$(Get-Date -Format 'yyyyMMdd').json"
    $reportDate = Get-Date -Format "F"

    Write-Host "--- Iniciada auditoria do firewall: $reportDate ---" -ForegroundColor Cyan

    try {
        # 1. Obter regras válidas
        $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -ErrorAction Stop |
                 Where-Object Action -eq Allow
    }
    catch {
        Write-Error "Erro ao obter regras do firewall: $($_.Exception.Message)"
        return
    }

    # 2. Identificar regras de risco (Any-to-Any)
    $riskyRules = foreach ($rule in $rules) {
        try {
            $addr = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
            $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop

            if (
                $addr.RemoteAddress -eq "Any" -and
                $addr.LocalAddress -eq "Any" -and
                $port.LocalPort -eq "Any" -and
                $port.Protocol -eq "Any"
            ) {
                $rule
            }
        }
        catch {
            Write-Warning "Erro ao processar regra '$($rule.Name)': $($_.Exception.Message)"
        }
    }

    # 3. Exibir riscos
    if ($riskyRules -and $riskyRules.Count -gt 0) {
        Write-Host "`n[!] AVISO: Regras potencialmente perigosas encontradas:" -ForegroundColor Red
        $riskyRules | Select-Object Name, DisplayName, DisplayGroup, Description |
            Format-Table -AutoSize
    }
    else {
        Write-Host "`n[+] Nenhuma regra Any-to-Any encontrada." -ForegroundColor Green
    }

    # 4. Exportação (JSON)
    $exportData = foreach ($rule in $rules) {
        try {
            $addr = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
            $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop

            [PSCustomObject]@{
                Name          = $rule.Name
                DisplayName   = $rule.DisplayName
                DisplayGroup  = $rule.DisplayGroup
                Direction     = $rule.Direction
                Action        = $rule.Action
                Enabled       = $rule.Enabled
                Profile       = $rule.Profile
                EndLocal      = $addr.LocalAddress
                EndRemoto     = $addr.RemoteAddress
                Protocolo     = $port.Protocol
                PortaLocal    = $port.LocalPort
                PortaRemota   = $port.RemotePort
            }
        }
        catch {
            Write-Warning "Erro ao exportar regra '$($rule.Name)'"
        }
    }

    try {
        $exportData | ConvertTo-Json -Depth 5 | Out-File $exportPath -Encoding UTF8
        Write-Host "`n[+] Regras exportadas para: $exportPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Erro ao salvar arquivo JSON: $($_.Exception.Message)"
    }

    Write-Host "--- Fim da auditoria: $(Get-Date -Format 'F') ---`n" -ForegroundColor Cyan

    Start-Sleep 2
}

# Main

check_firewall