
<#
.SYNOPSIS
    Comprehensive network troubleshooting script for Windows systems.

.DESCRIPTION
    This script collects network adapter information, tests local and internet connectivity, checks DNS and Active Directory, and offers common network fixes. It logs all output to a timestamped file for later review. Requires administrative privileges.

.NOTES
    Author: [Your Name]
    Date: 2025-08-01
    Version: 1.0
    Requires: PowerShell 5.0+, Administrator rights

.EXAMPLE
    Run as administrator:
        powershell.exe -File .\NetworkTroubleshooter.ps1
#>

#Requires -RunAsAdministrator

# Enables advanced function features and parameter binding
[CmdletBinding()]
param()


# Writes a colored section header to the console for readability

function Write-SectionHeader {
    <#
    .SYNOPSIS
        Writes a colored section header to the console.
    .PARAMETER Title
        The title text to display as a section header.
    #>
    param([string]$Title)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}


# Checks if the script is running with administrator rights

function Test-AdminRights {
    <#
    .SYNOPSIS
        Checks if the script is running with administrator rights.
    .OUTPUTS
        [bool] True if running as administrator, otherwise False.
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


# Initializes logging by creating a log directory and starting transcript logging

function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes logging to a timestamped file.
    .DESCRIPTION
        Creates a log directory if needed and starts transcript logging for all script output.
    #>
    $script:logDir = "C:\troubleshooting-with-faith"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:logFile = Join-Path $logDir "NetworkTrouble_$timestamp.log"
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    }
    # Start logging all output to a file
    Start-Transcript -Path $logFile
    Write-Host "Logging started at $logFile"
}


# Displays information about network adapters, IP configuration, statistics, and advanced properties

function Get-NetworkAdapterInfo {
    <#
    .SYNOPSIS
        Displays information about network adapters and their configuration.
    .DESCRIPTION
        Shows active adapters, IP configuration, statistics, and advanced properties.
    #>
    Write-SectionHeader "Network Adapter Information"
    # ...existing code...
    Write-Host "`nAdvanced Properties:" -ForegroundColor Yellow
    Get-NetAdapterAdvancedProperty | Format-Table -AutoSize
}


# Tests local network connectivity: loopback and gateway

function Test-LocalConnectivity {
    <#
    .SYNOPSIS
        Tests local network connectivity (loopback and gateway).
    .DESCRIPTION
        Verifies loopback and gateway connectivity using Test-NetConnection.
    #>
    Write-SectionHeader "Local Connectivity Tests"
    # ...existing code...
}


# Tests DNS server connectivity and DNS resolution

function Test-DNSConfiguration {
    <#
    .SYNOPSIS
        Tests DNS server connectivity and DNS resolution.
    .DESCRIPTION
        Checks each configured DNS server and attempts to resolve a known domain.
    #>
    Write-SectionHeader "DNS Tests"
    # ...existing code...
}


# Tests connectivity to Active Directory Domain Controller (if joined to a domain)

function Test-ActiveDirectoryConnectivity {
    <#
    .SYNOPSIS
        Tests connectivity to Active Directory Domain Controller.
    .DESCRIPTION
        Checks if the system is joined to a domain and tests LDAP port connectivity.
    #>
    Write-SectionHeader "Active Directory Tests"
    # ...existing code...
}


# Tests internet connectivity to common external hosts and performs a traceroute

function Test-InternetConnectivity {
    <#
    .SYNOPSIS
        Tests internet connectivity to external hosts and performs a traceroute.
    .DESCRIPTION
        Checks connectivity to Google and Google DNS, and runs a traceroute.
    #>
    Write-SectionHeader "Internet Connectivity Tests"
    # ...existing code...
}


# Checks for network performance issues such as dropped packets and interface errors

function Get-NetworkPerformance {
    <#
    .SYNOPSIS
        Checks for network performance issues such as dropped packets and errors.
    .DESCRIPTION
        Reports dropped packets and interface errors for all network adapters.
    #>
    Write-SectionHeader "Network Performance"
    # ...existing code...
}


# Runs common network troubleshooting fixes (flush DNS, reset Winsock, reset TCP/IP)

function Invoke-CommonFixes {
    <#
    .SYNOPSIS
        Runs common network troubleshooting fixes.
    .DESCRIPTION
        Flushes DNS, resets Winsock and TCP/IP, and displays the current network profile.
    #>
    Write-SectionHeader "Running Common Fixes"
    # ...existing code...
}


# =====================
# Main script execution
# =====================
try {
    # Ensure script is run as administrator
    if (-not (Test-AdminRights)) {
        throw "This script requires administrator privileges. Please run as administrator."
    }
    
    # Start logging
    Initialize-Logging
    
    # Run all troubleshooting steps
    Get-NetworkAdapterInfo
    Test-LocalConnectivity
    Test-DNSConfiguration
    Test-ActiveDirectoryConnectivity
    Test-InternetConnectivity
    Get-NetworkPerformance
    
    # Prompt user to run common fixes
    $response = Read-Host "`nWould you like to run common fixes? (y/n)"
    if ($response -eq 'y') {
        Invoke-CommonFixes
        Write-Warning "System restart may be required for changes to take effect"
    }
    
} catch {
    # Handle any errors
    Write-Error "An error occurred: $_"
} finally {
    # End logging and notify user
    Write-Host "`nTroubleshooting complete. Check the log file for details: $logFile"
    Stop-Transcript
}
