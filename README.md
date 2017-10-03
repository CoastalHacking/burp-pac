# Burp Proxy Auto-Config Extension

[![Build Status](https://travis-ci.org/CoastalHacking/burp-pac.svg?branch=develop)](https://travis-ci.org/CoastalHacking/burp-pac) [![Code Coverage](https://img.shields.io/codecov/c/github/CoastalHacking/burp-pac/develop.svg)](https://codecov.io/github/CoastalHacking/burp-pac?branch=develop)

Are you using Burp inside a network that uses a [Proxy Auto-Config (PAC)][pac] script to dynamically determine which upstream proxies to use for some given host or hosts?

Are you lazy and just want an extension to figure this out auto-magically, without any user interaction?

Well then, the Burp Proxy Auto-Config (PAC) [extension][burpext] is for you! It automatically configures project-level upstream proxies for use by Burp based upon the desktop environment. It uses [proxy-vole][proxyVole], which has support for PAC scripts built-in, in addition to supporting Java properties and environmental variables.

## Q & A

Q: _I installed the extension but don't see anything to configure! How do I configure it?_

A: Currently, there's nothing to configure! Once enabled, it automatically adds upstream proxies. Don't
like that? Unload and/or remove the extension. Once unloaded, it should remove those upstream proxies
it added, and only those.

Q: _Will this extension screw up my other extensions?_

A: Hopefully not! If you suspect something, please file an [issue][pacissues].

Q: _How can I troubleshoot an upstream proxy issue that this extension might be causing?_

A: Once [Feature #2][feature_2] is implemented, there will be a UI to aid in troubleshooting.
Otherwise, manually inspecting the project-level upstream proxies should also help.

Q: _Does this extension mess with my Burp settings?_

A: Yes, by design it modifies the current project-level settings to add upstream proxies.
It also will automatically enable "Project options" &rarr; "Upstream Proxy Servers" &rarr;
"Override user options" due to limitations in the Burp Extender API. It [currently][bug_13]
does not reset this value.

## Comparison to Other Burp PAC Extensions

### ["Proxy PAC"][proxypac]  

Similarities:

* Both extensions use a library that evaluates the JavaScript PAC file within a Rhino ScriptEngine. However, this extension uses the newer version of proxy-vole. Proxy PAC uses an older unsupported version.  

Differences:

* The "Proxy PAC" extension is written in Python and executed via Jython. This extension is written in Java.
* "Proxy PAC" starts a local web proxy via another thread.
The user manually configures Burp to use this local web proxy.
The proxy then initiates a client connection to whatever upstream proxy server, adding additional network latency per-request. This extension does not start a local web server. Rather, it modifies Burp's project-level configuration to add a per-host server to it. This is all automatic. Burp then handles making the upstream request directly. 
* "Proxy PAC" does not seem to have any test case coverage, which makes modifications more challenging #yolo. This extension has some test case coverage.

## Security

This plugin assumes the following are trusted sources of proxy information:
* [Java proxy settings][proxyVoleJava] configured when Burp was launched
* [Desktop proxy settings][proxyVoleOS], including any configured proxy auto-configuration scripts
* [Certain][proxyVoleEnv] environmental variables

[bug_13]: https://github.com/CoastalHacking/burp-pac/issues/13
[feature_2]: https://github.com/CoastalHacking/burp-pac/issues/2
[pacissues]: https://github.com/CoastalHacking/burp-pac/issues
[pac]: https://en.wikipedia.org/wiki/Proxy_auto-config
[burpext]: https://portswigger.net/burp/extender/
[proxyVole]: https://github.com/MarkusBernhardt/proxy-vole
[proxyVoleJava]: https://github.com/MarkusBernhardt/proxy-vole/blob/master/src/main/java/com/github/markusbernhardt/proxy/search/java/JavaProxySearchStrategy.java#L13
[proxyVoleOS]: https://github.com/MarkusBernhardt/proxy-vole/blob/master/src/main/java/com/github/markusbernhardt/proxy/search/desktop/DesktopProxySearchStrategy.java
[proxyVoleEnv]: https://github.com/MarkusBernhardt/proxy-vole/blob/master/src/main/java/com/github/markusbernhardt/proxy/search/env/EnvProxySearchStrategy.java#L45
[proxypac]: https://github.com/vincd/burpproxypacextension
