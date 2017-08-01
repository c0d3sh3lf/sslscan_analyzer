# sslscan_analyzer
Analyzes the SSL Scan output

## Options:
 - -h, --help            show this help message and exit
 - -H HOST, --host=HOST  IP address or Domain name to scan
 - -p PORT, --port=PORT  Port number to be scanned. Default is 443.
 - -v, --verbose         Verbose output
 - -o OUTPUT, --output=OUTPUT Output file

## Dependencies:
- [sslscan](https://github.com/rbsec/sslscan/releases?after=1.11.1-rbsec)


## Change Log:
   ### v1.1.3 - 01-Aug-17
   - Added Verbosity to the output
   - Added output file option (output as text)
   ### v1.1.2 - 31-Jul-17
   - Minor Bug Fixes and Enhancements
   ### v1.1.1 - 31-Jul-17
   - Minor Bug Fixes and Enhancements
   ### v1.1.0 - 31-Jul-17
   - Added automatic sslscan process run, and provide the output to analyse
   - Added options to input hostname and port
    
Report any bugs to [bugs.github@invadersam.com](bugs.github@invadersam.com)
