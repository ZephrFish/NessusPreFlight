<#

.Synopsis
  Nessus Preflight(NPF) Check for local and remote systems, Yes it is very hacky code but it works ok :)

  Reg Keys modified:
  HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy
  HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint
  HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint

  Current Functions:
  Invoke-NPF -localonly
  Invoke-NPF -localclean
  Invoke-NPF -checklocalreg
  Invoke-NPF -remote -target '10.10.20.1'
  Invoke-NPF -remoteclean -target '10.10.20.1'


  Author: Andy Gill (@ZephrFish)
  Version: 0.100 Alpha
  Required Dependencies: None
  Optional Dependencies: None   

  New & Fixes in this release:
    Fixed: Tidied up function names 
    Fixed: Remote fucntions no longer duplicate target parameter
    New: Remotely set registry values via WMI
    New: Remotely cleanup registry keys, delete domain and standard keys, modify the LocalAccountTokenFilterPolicy to set to  0 via Invoke-WMIMethod
    New: Run in remote or localonly mode based on flags, added in -localclean & -remoteclean

  
  Work in Progress:
    CIDR Parsing > New-IPv4RangeFromCIDR -Network 10.10.10.1/24
  
			

.DESCRIPTION
	Carries out a series of checks on the local or a remote system to ensure nessus will work for credentialed patch scans, current setup is for localonly
.EXAMPLE
	Invoke-NPF -localonly
	Only check for the registry keys and set them if not already.
.EXAMPLE
	Invoke-NPF -localclean
    Revert the keys back to standard once complete, run on a local system
.EXAMPLE
	Invoke-NPF -checklocalreg
    Run just the checks don't change anything, if not set the function will recommend running -localonly
.EXAMPLE
	Invoke-NPF -remote -target '10.10.20.1'
    Run the script against a remote system, note this will prompt for your credentials, please enter then DOMAIN\Username
.EXAMPLE
	Invoke-NPF -remoteclean -target '10.10.20.1'
    Revert the keys back to standard once complete, run on a remote system

#>

# Define Registry paths
$localATFPPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
$gpoDomPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint'
$gpoStandPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint'


# Set counters to zero for checking loops
$regcleancount = 0
$localcheckcount = 0

# Check if the current user is running as admin if not prompt them to rerun script as admin
function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "[!] Looks like you are not running as Admin please rerun powershell as admin!";
    exit 1;
}

$ErrorActionPreference = "Stop";

###########################################################
# CIDR Testing                                            #
# Insert code for parsing CIDR ranges                     #
###########################################################
function New-IPv4RangeFromCIDR {
    param(
       [Parameter(Mandatory=$true,
       ValueFromPipelineByPropertyName=$true,
       Position=0)]
       $Network
    )

# Extract the portions of the CIDR that will be needed
$StrNetworkAddress = ($Network.split('/'))[0]
[int]$NetworkLength = ($Network.split('/'))[1]
$NetworkIP = ([System.Net.IPAddress]$StrNetworkAddress).GetAddressBytes()
$IPLength = 32-$NetworkLength
[Array]::Reverse($NetworkIP)
$NumberOfIPs = ([System.Math]::Pow(2, $IPLength)) -1
$NetworkIP = ([System.Net.IPAddress]($NetworkIP -join '.')).Address
$StartIP = $NetworkIP +1
$EndIP = $NetworkIP + $NumberOfIPs

# We make sure they are of type Double before conversion
If ($EndIP -isnot [double])
{
    $EndIP = $EndIP -as [double]
}
If ($StartIP -isnot [double])
{
    $StartIP = $StartIP -as [double]
}
# We turn the start IP and end IP in to strings so they can be used.
$StartIP = ([System.Net.IPAddress]$StartIP).IPAddressToString
$EndIP = ([System.Net.IPAddress]$EndIP).IPAddressToString
New-IPv4Range $StartIP $EndIP
}

function New-IPv4Range
{
    param(
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
        $StartIP,

        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
        $EndIP      
        )

    # created by Dr. Tobias Weltner, MVP PowerShell
    $ip1 = ([System.Net.IPAddress]$StartIP).GetAddressBytes()
    [Array]::Reverse($ip1)
    $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address

    $ip2 = ([System.Net.IPAddress]$EndIP).GetAddressBytes()
    [Array]::Reverse($ip2)
    $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

    for ($x=$ip1; $x -le $ip2; $x++) {
        $ip = ([System.Net.IPAddress]$x).GetAddressBytes()
        [Array]::Reverse($ip)
        $ip -join '.'
        }
}
############################################################
############################################################

# Create main function
function Invoke-NPF
{
    [CmdletBinding()]
param( 
    [Parameter(
        HelpMessage='Only check for the registry keys and set them if not already.'
        )]
    [switch]$localonly,
    
    [Parameter(
        HelpMessage='Revert the keys back to standard once complete'
        )]
    [switch]$localclean,
    
    [Parameter(
        HelpMessage='Run just the checks dont change anything, if not set the function will recommend running -localonly'
        )]
    [switch]$checklocalreg,
    
    [Parameter(
        HelpMessage='Check a remote system or range of systems for registry keys to be set and if not set enable them'
        )]
    [switch]$remote,

    [Parameter (
        HelpMessage='Revert the keys back to standard once complete, run on a remote system'
    )]
    [switch]$remoteclean,

    [Parameter(
        HelpMessage='Target remote host, can be IP address or hostname'
    )]
    [string]$target,

    [Parameter(
        HelpMessage='Debug mode, run anything in this function for testing purposes'
        )]
    [switch]$debugmode
)

    # Setup All our functions
    function Invoke-LocalMode {
        If ((Get-ItemPropertyValue -Path $localATFPPath -Name "LocalAccountTokenFilterPolicy") -eq '0') {
            Write-Verbose '[!] The Registry key does not exist, setting it view reg add'
            REG add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
           
            Write-Host "[!] Enabled DomainProfile [Step 1 = Complete]" -ForegroundColor Green
        } elseif ((Get-ItemPropertyValue -Path $localATFPPath -Name "LocalAccountTokenFilterPolicy") -eq '1') {
            Write-Host '[!] LocalAccountTokenFilterPolicy Enabled, next checking Domain and Standard Profiles' -ForegroundColor Green
           
        }
       
        # Check the domain profile regkey and set if not enabled
        If (-not (Test-Path -Path $gpoDomPath)) {
            Write-Host "[+] Looks like DomainProfile is not enabled, Creating a new registry key for this GPO" -ForegroundColor Yellow
            REG add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" /v Enabled /t REG_DWORD /d 1 /f
            REG add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint" /v RemoteAddresses /t REG_SZ /d "*" /f
            Write-Host "[!] Enabled DomainProfile [Step 2a = Complete]" -ForegroundColor Green
        } elseif ((Get-ItemPropertyValue -Path $gpoDomPath -Name "Enabled") -eq '0') {
            Set-ItemProperty -Path $gpoDomPath -Name 'Enabled' -Value '1'
            Write-Host "[!] Enabled DomainProfile [Step 2a = Complete]" -ForegroundColor Green
           
        } else {
            Write-Host "[!] All good [Step 2a = Complete]" -ForegroundColor Green
              
        }
    
        # Check the standard profile regkey and set if not enabled
        If (-not (Test-Path -Path $gpoStandPath)) {
            Write-Host "[+] Looks like StandardProfile is not enabled, Creating a new registry key for this GPO" -ForegroundColor Yellow
            REG add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" /v Enabled /t REG_DWORD /d 1 /f
            REG add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint" /v RemoteAddresses /t REG_SZ /d "*" /f
           
        } elseif ((Get-ItemPropertyValue -Path $gpoStandPath -Name "Enabled") -eq '0') {
            Set-ItemProperty -Path $gpoStandPath -Name 'Enabled' -Value '1'
            Write-Host "[!] Enabled StandardProfile [Step 2b = Complete]" -ForegroundColor Green
           
        } else {
            Write-Host "[!] All good [Step 2b = Complete]" -ForegroundColor Green
            
        }
        
        # Check the status of the counter for local checks
        if ($localcheckcount-ge '3') {
            Write-Host ""
            Write-Host "[!] All three values set, good to go for Nessus" -ForegroundColor Green -NoNewline
            Write-Host ""
        }
        
        # Finally restart the server service
        Write-Host "[!] Restarting the server service!" -ForegroundColor Yellow -NoNewline
        restart-service server
        Write-Output ""
    
    }
    
    # Create function for cleaning up the actions of NPF to revert an environment 
    function Invoke-CleanReg {
        # Check for LocalAccountTokenFilterPolicy Registry key value
        if ((Get-ItemPropertyValue -Path $localATFPPath -Name "LocalAccountTokenFilterPolicy") -eq '1') {
            Write-Host '[+] The value of LocalAccountTokenFilterPolicy is 1, cleaning up the registry setting this back to 0' -ForegroundColor Yellow 
            Set-ItemProperty -Path $localATFPPath -Name "LocalAccountTokenFilterPolicy" -Value '0'
            $regcleancount++
        }
        
        # Check for Domain Profile FileAndPrint Registry key value for local group policy
        if ((Get-ItemPropertyValue -Path $gpoDomPath -Name "Enabled") -eq '1') {
            Write-Host '[+] The value of DomainProfile\Services\FileAndPrint is 1, cleaning up the registry setting this back to 0' -ForegroundColor Yellow 
            Set-ItemProperty -Path $gpoDomPath -Name "Enabled" -Value '0'
            $regcleancount++
        }
        
        # Check for Standard Profile FileAndPrint Registry key value for local group policy
        if ((Get-ItemPropertyValue -Path $gpoStandPath -Name "Enabled") -eq '1') {
            Write-Host '[+] The value of StandardProfile\Services\FileAndPrint is 1, cleaning up the registry setting this back to 0' -ForegroundColor Yellow 
            Set-ItemProperty -Path $gpoStandPath -Name "Enabled" -Value '0'
            $regcleancount++
        }
        
        # If we get all zeros back cleanup has been successful
        
            Write-Host "[!] Looks like either the keys don't exist or they've already been cleaned" -ForegroundColor Yellow
            Write-Host "[*] If you see three zeros below the system is already clean" -ForegroundColor Green
            Get-ItemPropertyValue -Path $localATFPPath -Name "LocalAccountTokenFilterPolicy"
            Get-ItemPropertyValue -Path $gpoDomPath -Name "Enabled"
            Get-ItemPropertyValue -Path $gpoStandPath -Name "Enabled"
        
        
    }

        function Invoke-LocalChecks {
            Get-ItemProperty -Path $localATFPPath -Name "LocalAccountTokenFilterPolicy"
            Get-ItemProperty -Path $gpoDomPath -Name "Enabled"
            Get-ItemProperty -Path $gpoDomPath -Name "RemoteAddresses"
            Get-ItemProperty -Path $gpoStandPath -Name "Enabled"
            Get-ItemProperty -Path $gpoStandPath -Name "RemoteAddresses"
            Write-Host "[+] You should see three registry keys printed out with all 1s, if not you will need to run the standard script with -localonly" -ForegroundColor Yellow
        }
    
        
        function Invoke-Remote {
 
            param (
            [uint32]$hklm = 2147483650
            #[uint32]$hkcu = 2147483649,
            )
            
            # Top level keys
            $localATFPPathNKV = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
            $gpoDomPathNKV = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint"
            $gpoStandPathNKV = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint"
            
            # The value we're setting
            $localATFPPathNN = "LocalAccountTokenFilterPolicy"
            $gpoPathNN = "FileAndPrint"
            
            # String value :)
            # $newvalue = "1"
            $GPONV = "Enabled"
            
            # Get credentials
            $creds = Get-Credential

            # First we want to check we can reach the remote system
            # need to add in ping command in here to test connection to remote system
            
            #Get-WmiObject -Namespace "root\cimv2" -Class Win32_ComputerSystem -Credential $cred -ComputerName $target
            
            # Create top level key
            # HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System
            $localATFPResult = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name CreateKey  $hklm, $localATFPPathNKV -ComputerName $target -Credential $creds
            If ($localATFPResult.Returnvalue -eq 0) {
                Write-Host  "New LocalAccountTokenFilterPolicy Key Created"
            }
            
            # Set DWORD value (Set to 1 in output below)
            $localATFPValueResult = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name SetDWORDvalue -ArgumentList @( $hklm, $localATFPPathNKV, $localATFPPathNN, 1) -ComputerName $target -Credential $creds
            If ($localATFPValueResult.Returnvalue -eq 0) {
                Write-Host "LocalAccountTokenFilterPolicy DWORD Value created" -ForegroundColor Green
            }
            
            ######################################## Domain Profile ######################################################################
            # Create top level key
            # SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint
            $DomProfileResult = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name CreateKey  $hklm, $gpoDomPathNKV -ComputerName $target -Credential $creds
            If ($DomProfileResult.Returnvalue -eq 0) {
                Write-Host  "New DomainProfile Key Created"
            }
            # Create String value for Domain Profile
            $DomProfileKeyResult = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name SetStringvalue $hklm, $gpoDomPathNKV, $NPONV, $gpoPathNN -ComputerName $target -Credential $creds
            If ($DomProfileKeyResult.Returnvalue -eq 0) {
                Write-Host  "DomainProfile Reg Key Value Enabled" -ForegroundColor Green
            }
            
            
            ######################################## Standard Profile ######################################################################
            # Create top level key
            # SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint
            $StandardProfileResult = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name CreateKey  $hklm, $gpoStandPathNKV -ComputerName $target -Credential $creds
            If ($StandardProfileResult.Returnvalue -eq 0) {
                Write-Host  "New StandardProfile Key Created"
            }
            
            # Create String value for Standard Profile
            $StandardProfileValueResult = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name SetStringvalue $hklm, $gpoStandPathNKV, $GPONV, $gpoPathNN -ComputerName $target -Credential $creds
            If ($StandardProfileValueResult.Returnvalue -eq 0) {
                Write-Host "StandardProfile Reg Key Value Enabled" -ForegroundColor Green
            }
            
            
            }
    
            # Remote funciton for cleaning up a remote system, supply with a target IP address and the function will clean the host up by deleting the keys
            function Invoke-RemoteCleanup {
                param (
                    [uint32]$hklm = 2147483650,
                    [uint32]$hkcu = 2147483649
            )
            # Top level keys
            $localATFPPathNKV = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
            $gpoDomPathNKV = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint"
            $gpoStandPathNKV = "SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Services\FileAndPrint"
            
            # The value we're setting
            $localATFPPathNN = "LocalAccountTokenFilterPolicy"
            $creds = Get-Credential
            
            # Set cleanup commands
            $GPODomClean = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name DeleteKey  $hklm, $gpoDomPathNKV -ComputerName $target -Credential $creds
            $GPOStanClean = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name DeleteKey  $hklm, $gpoStandPathNKV -ComputerName $target -Credential $creds
            $localATFPValueResult = Invoke-WmiMethod -Namespace root\cimv2 -Class StdRegProv -Name SetDWORDvalue -ArgumentList @( $hklm, $localATFPPathNKV, $localATFPPathNN, 0) -ComputerName $target -Credential $creds
            
            # Get Results
            If ($localATFPValueResult.Returnvalue -eq 0) {
                Write-Host "[1] LocalAccountTokenFilterPolicy DWORD Value set to 0" -ForegroundColor Green
            }
            
            # Create String value for Domain Profile
            If ($GPODomClean.Returnvalue -eq 0) {
                Write-Host  "[2] DomainProfile Reg Key Value Deleted!" -ForegroundColor Green
            }
            
            If ($GPOStanClean.Returnvalue -eq 0) {
                Write-Host  "[3] StandardProfile Reg Key Value Deleted!"
            }
            
            if ($localATFPValueResult.Returnvalue -eq 0 -and $GPODomClean.Returnvalue -eq 0 -and $GPOStanClean.Returnvalue -eq 0) {
                Write-Host  "[!] Remote Cleanup Complete" -ForegroundColor Green
            
            }

            
            
            }
            

    # Warn the user about GPO
    
    Write-Host ""
    Write-Host "[+] Nessus Pre-Flight Checks Started" -ForeGroundColor Green 
    Write-Host '[!] Note: If the machine is on a domain, gpupdate /force will overwrite any settings set by this script so you may need to rerun if new GPO are pushed out' -ForeGroundColor Red -NoNewLine
    Write-Host ""
    

    #################################### MAIN FUNCTION  #################################### 
    # Checks if any of the flags have bene set, otherwise will prompt the user to select a flag and show help text
    if ($localonly)  {

        Invoke-LocalMode   
            
    } elseif ($localclean) {
    
        Invoke-CleanReg 
    
    } elseif ($checklocalreg) {
    
        Invoke-LocalChecks

    } elseif ($remote) {

        Invoke-Remote
    
    } elseif ($remoteclean) {

        Invoke-RemoteCleanup
    
    } elseif ($debugmode) {
        # Drop anything in here you want to quickly test
        Write-Host ""
        Write-Host "[+] Debug Mode Enabled" -ForeGroundColor Blue
        Write-Host "[#] Debug Mode [#]" -ForegroundColor DarkGreen
        Write-Host ""
        
    
    } else {
        Write-Output ""
        Write-Host '[!] Looks like you have not picked an option, please select either local, check, cleanup or remote. Printing help messages' -ForegroundColor Red 
        Get-Help Invoke-NPF 
    }
    

  }


