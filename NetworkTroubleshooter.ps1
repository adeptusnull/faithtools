#Requires -RunAsAdministrator
[CmdletBinding()]
param()

function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}

function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-Logging {
    $script:logDir = "C:\troubleshooting-with-faith"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logFile = Join-Path $logDir "NetworkTrouble_$timestamp.log"
    
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }
    Start-Transcript -Path $logFile
    Write-Host "Logging started at $logFile"
}

function Get-NetworkAdapterInfo {
    Write-SectionHeader "Network Adapter Information"
    
    Write-Host "`nActive Network Adapters:" -ForegroundColor Yellow
    Get-NetAdapter | Where-Object Status -eq "Up" | Format-Table -AutoSize
    
    Write-Host "`nDetailed IP Configuration:" -ForegroundColor Yellow
    Get-NetIPConfiguration -Detailed | Format-List
    
    Write-Host "`nAdapter Statistics:" -ForegroundColor Yellow
    Get-NetAdapterStatistics | Format-Table -AutoSize
    
    Write-Host "`nAdvanced Properties:" -ForegroundColor Yellow
    Get-NetAdapterAdvancedProperty | Format-Table -AutoSize
}

function Test-LocalConnectivity {
    Write-SectionHeader "Local Connectivity Tests"
    
    Write-Host "`nTesting Loopback:" -ForegroundColor Yellow
    Test-NetConnection -ComputerName localhost
    Test-NetConnection -ComputerName 127.0.0.1
    
    $gateway = (Get-NetIPConfiguration).IPv4DefaultGateway.NextHop
    if ($gateway) {
        Write-Host "`nTesting Gateway ($gateway):" -ForegroundColor Yellow
        Test-NetConnection -ComputerName $gateway
    } else {
        Write-Warning "No gateway found!"
    }
}

function Test-DNSConfiguration {
    Write-SectionHeader "DNS Tests"
    
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | 
        Select-Object -ExpandProperty ServerAddresses
    
    if ($dnsServers) {
        Write-Host "`nTesting DNS Servers:" -ForegroundColor Yellow
        foreach ($dns in $dnsServers) {
            Write-Host "`nTesting DNS Server: $dns" -ForegroundColor Yellow
            Test-NetConnection -ComputerName $dns -Port 53
        }
        
        Write-Host "`nTesting DNS Resolution:" -ForegroundColor Yellow
        try {
            Resolve-DnsName google.com -Type A -ErrorAction Stop
        } catch {
            Write-Warning "DNS resolution failed: $_"
        }
    } else {
        Write-Warning "No DNS servers configured!"
    }
}

function Test-ActiveDirectoryConnectivity {
    Write-SectionHeader "Active Directory Tests"
    
    $dcInfo = nltest /dsgetdc: 2>&1
    if ($LASTEXITCODE -eq 0) {
        $dc = ($dcInfo -match "DC: \\\\(.+)") | ForEach-Object { $Matches[1] }
        Write-Host "`nTesting connection to Domain Controller: $dc" -ForegroundColor Yellow
        Test-NetConnection -ComputerName $dc -Port 389
    } else {
        Write-Warning "Not connected to a domain or domain controller not accessible"
    }
}

function Test-InternetConnectivity {
    Write-SectionHeader "Internet Connectivity Tests"
    
    $targets = @(
        @{Name = "Google HTTPS"; Host = "google.com"; Port = 443},
        @{Name = "Google DNS"; Host = "8.8.8.8"; Port = 53}
    )
    
    foreach ($target in $targets) {
        Write-Host "`nTesting connection to $($target.Name):" -ForegroundColor Yellow
        Test-NetConnection -ComputerName $target.Host -Port $target.Port
    }
    
    Write-Host "`nPerforming traceroute to google.com:" -ForegroundColor Yellow
    Test-NetConnection -ComputerName google.com -TraceRoute
}

function Get-NetworkPerformance {
    Write-SectionHeader "Network Performance"
    
    Write-Host "`nChecking for dropped packets:" -ForegroundColor Yellow
    $droppedPackets = Get-NetAdapterStatistics | 
        Where-Object { $_.ReceivedPacketsDropped -gt 0 -or $_.OutboundPacketsDropped -gt 0 }
    if ($droppedPackets) {
        $droppedPackets | Format-Table -AutoSize
    } else {
        Write-Host "No dropped packets found." -ForegroundColor Green
    }
    
    Write-Host "`nChecking interface errors:" -ForegroundColor Yellow
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, @{
        Name="Errors"
        Expression={(Get-NetAdapterStatistics -Name $_.Name).ReceivedErrors}
    } | Format-Table -AutoSize
}

function Invoke-CommonFixes {
    Write-SectionHeader "Running Common Fixes"
    
    Write-Host "`nFlushing DNS cache..." -ForegroundColor Yellow
    ipconfig /flushdns
    
    Write-Host "`nResetting Winsock..." -ForegroundColor Yellow
    netsh winsock reset
    
    Write-Host "`nResetting TCP/IP stack..." -ForegroundColor Yellow
    netsh int ip reset
    
    Write-Host "`nChecking Network Profile..." -ForegroundColor Yellow
    Get-NetConnectionProfile | Format-Table -AutoSize
}

# Main execution
try {
    if (-not (Test-AdminRights)) {
        throw "This script requires administrator privileges. Please run as administrator."
    }
    
    Initialize-Logging
    
    Get-NetworkAdapterInfo
    Test-LocalConnectivity
    Test-DNSConfiguration
    Test-ActiveDirectoryConnectivity
    Test-InternetConnectivity
    Get-NetworkPerformance
    
    $response = Read-Host "`nWould you like to run common fixes? (y/n)"
    if ($response -eq 'y') {
        Invoke-CommonFixes
        Write-Warning "System restart may be required for changes to take effect"
    }
    
} catch {
    Write-Error "An error occurred: $_"
} finally {
    Write-Host "`nTroubleshooting complete. Check the log file for details: $logFile"
    Stop-Transcript
}
