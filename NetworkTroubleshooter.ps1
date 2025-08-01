<#
.SYNOPSIS
    Network Troubleshooting Tool for Windows Systems

.DESCRIPTION
    This PowerShell script performs comprehensive network diagnostics and troubleshooting.
    It systematically tests various network components including adapters, connectivity,
    DNS configuration, Active Directory connections, and internet access. The script
    provides detailed logging and offers common network fixes.

.NOTES
    Name: NetworkTroubleshooter.ps1
    Author: faithtools
    Requires: PowerShell 5.0+, Administrator privileges
    
.FUNCTIONALITY
    - Network adapter information and statistics
    - Local connectivity testing (loopback, gateway)
    - DNS server testing and resolution validation
    - Active Directory connectivity verification
    - Internet connectivity and traceroute analysis
    - Network performance monitoring (packet drops, errors)
    - Common network fixes (DNS flush, Winsock reset, TCP/IP reset)
    - Comprehensive logging with transcript

.EXAMPLE
    .\NetworkTroubleshooter.ps1
    Runs the complete network diagnostic suite and prompts for applying fixes.
#>

#Requires -RunAsAdministrator
[CmdletBinding()]
param()

<#
.SYNOPSIS
    Writes a formatted section header for console output

.DESCRIPTION
    Creates a visually distinct section header with cyan color formatting
    to organize the troubleshooting output into clear sections.

.PARAMETER Title
    The title text to display in the header
#>
function Write-SectionHeader {
    param([string]$Title)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}

<#
.SYNOPSIS
    Tests if the current PowerShell session has administrator privileges

.DESCRIPTION
    Checks the current user's security principal to determine if they have
    administrator rights. This is critical since many network troubleshooting
    commands require elevated privileges.

.OUTPUTS
    Boolean - Returns $true if running as administrator, $false otherwise
#>
function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Initializes logging functionality for the troubleshooting session

.DESCRIPTION
    Creates a log directory and starts PowerShell transcript logging to capture
    all console output. The log file includes a timestamp for unique identification.
    Logs are stored in C:\troubleshooting-with-faith for easy access.
#>
function Initialize-Logging {
    # Set up logging directory and file paths
    $script:logDir = "C:\troubleshooting-with-faith"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logFile = Join-Path $logDir "NetworkTrouble_$timestamp.log"
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }
    
    # Start transcript to capture all output
    Start-Transcript -Path $logFile
    Write-Host "Logging started at $logFile"
}

<#
.SYNOPSIS
    Gathers comprehensive network adapter information

.DESCRIPTION
    Collects and displays detailed information about network adapters including:
    - Active network adapters and their status
    - Detailed IP configuration for each adapter
    - Network adapter statistics (packets sent/received, errors)
    - Advanced adapter properties and settings
    
    This information helps identify adapter-level issues and configuration problems.
#>
function Get-NetworkAdapterInfo {
    Write-SectionHeader "Network Adapter Information"
    
    # Display all active (up) network adapters
    Write-Host "`nActive Network Adapters:" -ForegroundColor Yellow
    Get-NetAdapter | Where-Object Status -eq "Up" | Format-Table -AutoSize
    
    # Show detailed IP configuration including addresses, gateways, DNS servers
    Write-Host "`nDetailed IP Configuration:" -ForegroundColor Yellow
    Get-NetIPConfiguration -Detailed | Format-List
    
    # Display packet statistics to identify potential performance issues
    Write-Host "`nAdapter Statistics:" -ForegroundColor Yellow
    Get-NetAdapterStatistics | Format-Table -AutoSize
    
    # Show advanced properties like speed, duplex, flow control settings
    Write-Host "`nAdvanced Properties:" -ForegroundColor Yellow
    Get-NetAdapterAdvancedProperty | Format-Table -AutoSize
}

<#
.SYNOPSIS
    Tests local network connectivity including loopback and gateway

.DESCRIPTION
    Performs fundamental connectivity tests to verify:
    - Loopback functionality (localhost and 127.0.0.1) to test TCP/IP stack
    - Gateway connectivity to verify local network access
    
    These tests help identify if problems are local to the machine or extend
    to the broader network infrastructure.
#>
function Test-LocalConnectivity {
    Write-SectionHeader "Local Connectivity Tests"
    
    # Test loopback interface to verify TCP/IP stack is functioning
    Write-Host "`nTesting Loopback:" -ForegroundColor Yellow
    Test-NetConnection -ComputerName localhost
    Test-NetConnection -ComputerName 127.0.0.1
    
    # Test connectivity to default gateway (router/switch)
    $gateway = (Get-NetIPConfiguration).IPv4DefaultGateway.NextHop
    if ($gateway) {
        Write-Host "`nTesting Gateway ($gateway):" -ForegroundColor Yellow
        Test-NetConnection -ComputerName $gateway
    } else {
        Write-Warning "No gateway found!"
    }
}

<#
.SYNOPSIS
    Tests DNS configuration and resolution functionality

.DESCRIPTION
    Performs comprehensive DNS testing including:
    - Connectivity to configured DNS servers on port 53
    - DNS resolution testing using a known domain (google.com)
    - Validation of DNS server configuration
    
    DNS issues are a common cause of network problems, so this function
    helps identify if DNS servers are reachable and functioning properly.
#>
function Test-DNSConfiguration {
    Write-SectionHeader "DNS Tests"
    
    # Get all configured IPv4 DNS server addresses
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | 
        Select-Object -ExpandProperty ServerAddresses
    
    if ($dnsServers) {
        # Test connectivity to each configured DNS server on port 53
        Write-Host "`nTesting DNS Servers:" -ForegroundColor Yellow
        foreach ($dns in $dnsServers) {
            Write-Host "`nTesting DNS Server: $dns" -ForegroundColor Yellow
            Test-NetConnection -ComputerName $dns -Port 53
        }
        
        # Test actual DNS resolution functionality
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

<#
.SYNOPSIS
    Tests Active Directory and domain controller connectivity

.DESCRIPTION
    Verifies connectivity to Active Directory infrastructure by:
    - Using nltest to discover the domain controller
    - Testing LDAP connectivity to the domain controller on port 389
    
    This is essential for domain-joined machines to ensure proper authentication
    and domain services functionality. Skips testing if not domain-joined.
#>
function Test-ActiveDirectoryConnectivity {
    Write-SectionHeader "Active Directory Tests"
    
    # Use nltest to discover the domain controller for this machine
    $dcInfo = nltest /dsgetdc: 2>&1
    if ($LASTEXITCODE -eq 0) {
        # Extract domain controller name from nltest output
        $dc = ($dcInfo -match "DC: \\\\(.+)") | ForEach-Object { $Matches[1] }
        Write-Host "`nTesting connection to Domain Controller: $dc" -ForegroundColor Yellow
        # Test LDAP connectivity (port 389) to the domain controller
        Test-NetConnection -ComputerName $dc -Port 389
    } else {
        Write-Warning "Not connected to a domain or domain controller not accessible"
    }
}

<#
.SYNOPSIS
    Tests internet connectivity and external network access

.DESCRIPTION
    Performs comprehensive internet connectivity testing including:
    - HTTPS connectivity to Google (port 443) for web access verification
    - DNS connectivity to Google's public DNS (8.8.8.8 port 53)
    - Traceroute to google.com to identify routing path and potential bottlenecks
    
    These tests help determine if the machine can reach external resources
    and identify where connectivity issues might occur in the routing path.
#>
function Test-InternetConnectivity {
    Write-SectionHeader "Internet Connectivity Tests"
    
    # Define test targets with different protocols and purposes
    $targets = @(
        @{Name = "Google HTTPS"; Host = "google.com"; Port = 443},  # Web access test
        @{Name = "Google DNS"; Host = "8.8.8.8"; Port = 53}        # External DNS test
    )
    
    # Test each target for connectivity
    foreach ($target in $targets) {
        Write-Host "`nTesting connection to $($target.Name):" -ForegroundColor Yellow
        Test-NetConnection -ComputerName $target.Host -Port $target.Port
    }
    
    # Perform traceroute to identify routing path and potential issues
    Write-Host "`nPerforming traceroute to google.com:" -ForegroundColor Yellow
    Test-NetConnection -ComputerName google.com -TraceRoute
}

<#
.SYNOPSIS
    Analyzes network performance and identifies potential issues

.DESCRIPTION
    Examines network performance metrics including:
    - Dropped packets on network adapters (both inbound and outbound)
    - Interface errors that could indicate hardware or driver issues
    - Link speeds and adapter status information
    
    Performance issues like dropped packets or errors can indicate
    hardware problems, driver issues, or network congestion.
#>
function Get-NetworkPerformance {
    Write-SectionHeader "Network Performance"
    
    # Check for dropped packets which indicate potential performance issues
    Write-Host "`nChecking for dropped packets:" -ForegroundColor Yellow
    $droppedPackets = Get-NetAdapterStatistics | 
        Where-Object { $_.ReceivedPacketsDropped -gt 0 -or $_.OutboundPacketsDropped -gt 0 }
    if ($droppedPackets) {
        $droppedPackets | Format-Table -AutoSize
    } else {
        Write-Host "No dropped packets found." -ForegroundColor Green
    }
    
    # Check for interface errors that could indicate hardware/driver problems
    Write-Host "`nChecking interface errors:" -ForegroundColor Yellow
    Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, @{
        Name="Errors"
        Expression={(Get-NetAdapterStatistics -Name $_.Name).ReceivedErrors}
    } | Format-Table -AutoSize
}

<#
.SYNOPSIS
    Applies common network fixes and resets

.DESCRIPTION
    Performs standard network troubleshooting fixes including:
    - DNS cache flush to resolve DNS-related issues
    - Winsock reset to fix socket-level problems
    - TCP/IP stack reset to resolve protocol issues
    - Network profile check to verify connection settings
    
    These fixes resolve many common network problems but may require
    a system restart to take full effect. Should only be run after
    diagnostic tests identify potential issues.
#>
function Invoke-CommonFixes {
    Write-SectionHeader "Running Common Fixes"
    
    # Clear DNS resolver cache to fix DNS resolution issues
    Write-Host "`nFlushing DNS cache..." -ForegroundColor Yellow
    ipconfig /flushdns
    
    # Reset Winsock catalog to default state (fixes socket issues)
    Write-Host "`nResetting Winsock..." -ForegroundColor Yellow
    netsh winsock reset
    
    # Reset TCP/IP stack to default configuration
    Write-Host "`nResetting TCP/IP stack..." -ForegroundColor Yellow
    netsh int ip reset
    
    # Display current network profile settings for verification
    Write-Host "`nChecking Network Profile..." -ForegroundColor Yellow
    Get-NetConnectionProfile | Format-Table -AutoSize
}

# ============================================================================
# MAIN EXECUTION BLOCK
# ============================================================================
# This is the main script execution flow that orchestrates all network tests
# and provides user interaction for applying fixes.

try {
    # Verify administrator privileges before proceeding
    # Many network commands require elevated permissions
    if (-not (Test-AdminRights)) {
        throw "This script requires administrator privileges. Please run as administrator."
    }
    
    # Start logging to capture all output for later analysis
    Initialize-Logging
    
    # Execute comprehensive network diagnostic tests in logical order:
    # 1. Hardware/adapter level information
    Get-NetworkAdapterInfo
    
    # 2. Basic connectivity (local network)
    Test-LocalConnectivity
    
    # 3. DNS functionality (critical for name resolution)
    Test-DNSConfiguration
    
    # 4. Domain/AD connectivity (if domain-joined)
    Test-ActiveDirectoryConnectivity
    
    # 5. External/internet connectivity
    Test-InternetConnectivity
    
    # 6. Performance analysis
    Get-NetworkPerformance
    
    # Offer to apply common fixes based on diagnostic results
    # User choice prevents automatic changes that might affect connectivity
    $response = Read-Host "`nWould you like to run common fixes? (y/n)"
    if ($response -eq 'y') {
        Invoke-CommonFixes
        Write-Warning "System restart may be required for changes to take effect"
    }
    
} catch {
    # Handle any unexpected errors during execution
    Write-Error "An error occurred: $_"
} finally {
    # Always stop transcript logging and inform user of log location
    # This ensures logs are saved even if script encounters errors
    Write-Host "`nTroubleshooting complete. Check the log file for details: $logFile"
    Stop-Transcript
}
