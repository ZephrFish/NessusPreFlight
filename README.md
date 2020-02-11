# Nessus PreFlight Quick-Start
Import the module:
`. .\NessusPreFlight.ps1`

	Carries out a series of checks on the local or a remote system to ensure nessus will work for credentialed patch scans, current setup is for localonly

- `Invoke-NPF -localonly`
	Only check for the registry keys and set them if not already.

- `Invoke-NPF -cleanup`
    Revert the keys back to standard once complete

- `Invoke-NPF -checklocalreg`
    Run just the checks don't change anything, if not set the function will recommend running -localonly
.
- `Invoke-NPF -remote -target '10.10.20.1'`
    Run the script against a remote system, note this will prompt for your credentials, please enter then DOMAIN\Username
    
