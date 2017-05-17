# goMS17-010
`goMS17-010` detects if host(s) is vulnerable to SMB exploit([MS17-010](https://technet.microsoft.com/en-us/library/security/ms17-010.aspx)), which is used by NSA hacking tools leaked by Shadow Brokers. If it's vulnerable, then checks if the target machine is running the Double Pulsar SMB backdoor. Inspired by [this Metasploit module](https://www.rapid7.com/db/modules/auxiliary/scanner/smb/smb_ms17_010), but doen't depend on MSF or any framework, just run `ms17-010.go` or `ms17-010.py` with option(s)  
`-i` detect single host  
`-n` scan a whole network in CIDR Notation, for example, 192.168.1.1/24
`-t` timeout on connection, in seconds
