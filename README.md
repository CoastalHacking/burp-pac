# Burp Proxy Auto-Config Extension

[![Build Status](https://travis-ci.org/CoastalHacking/burp-pac.svg?branch=master)](https://travis-ci.org/CoastalHacking/burp-pac) [![Code Coverage](https://img.shields.io/codecov/c/github/CoastalHacking/burp-pac/develop.svg)](https://codecov.io/github/CoastalHacking/burp-pac?branch=master)

Are you using Burp inside a network that uses a [Proxy Auto-Config (PAC)][pac] script to dynamically determine which upstream proxies to use for some given host or hosts?

Are you lazy and just want an extension to figure this out auto-magically, without any user interaction?

Well then, the Burp Proxy Auto-Config (PAC) [extension][burpext] is for you! It automatically configures project-level upstream proxies for use by Burp based upon the desktop environment. It uses [proxy-vole][proxyVole], which has support for PAC scripts built-in, in addition to supporting Java properties and environmental variables.

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

Caveat emptor: any identified PAC scripts are executed as-is. That is, they are not sandboxed within a security manager. 

[pac]: https://en.wikipedia.org/wiki/Proxy_auto-config
[burpext]: https://portswigger.net/burp/extender/
[proxyVole]: https://github.com/MarkusBernhardt/proxy-vole
[proxyVoleJava]: https://github.com/MarkusBernhardt/proxy-vole/blob/master/src/main/java/com/github/markusbernhardt/proxy/search/java/JavaProxySearchStrategy.java#L13
[proxyVoleOS]: https://github.com/MarkusBernhardt/proxy-vole/blob/master/src/main/java/com/github/markusbernhardt/proxy/search/desktop/DesktopProxySearchStrategy.java
[proxyVoleEnv]: https://github.com/MarkusBernhardt/proxy-vole/blob/master/src/main/java/com/github/markusbernhardt/proxy/search/env/EnvProxySearchStrategy.java#L45
[proxypac]: https://github.com/vincd/burpproxypacextension
