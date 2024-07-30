---
title: Part 4.2 - Hunting for Web Shells deployed on Servers.
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-24 12:00:00 -500
categories: [Detection Engineering, Bytes of Insights - YARA for Incident Response & Malware Hunting]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/yara_main.png
  
---

<!-- PROD -->
A web shell is a malicious file placed on a victim’s web server that allows the threat actor to remotely execute commands. Many of the compromises I have investigated involved web shells on internet-exposed web servers, such as Microsoft IIS servers, Citrix NetScaler servers, and others. The web shell functions as both a backdoor and a persistence mechanism for the threat actor.

![Desktop View](/images/yara/yara_webshell.drawio.png)

I used to run YARA rules as soon as I obtained the disk image of any compromised web server to check for the presence of known web shell signatures. In many cases, I was fortunate to find that the actor had dropped a web shell immediately after exploiting vulnerabilities on the target server. This approach makes it easier to search through `web server logs` for interesting indicators of compromise (IOCs) such as the threat actor's IP address, user agent, etc.

```bash
C:\inetpub\wwwroot\ # On Windwos IIS Server 
/var/www/html/ # on Linux Servers
```

I have linked here a collection of [YARA rules](https://github.com/Neo23x0/signature-base/blob/master/yara/cn_pentestset_webshells.yar) that contains a good number of web shell detections.

What if we could run YARA rules on a specified file location and automatically execute the rule as soon as a new file is created or modified? This use case can be achieved using the [OSQuery](https://www.osquery.io/) endpoint agent. The agent includes both a built-in YARA engine and file integrity checking features. You can write a YARA rule to trigger as soon as files are dropped into a specific location. I have covered this in more detail in the OSQuery Ecosystem section, so be sure to check that out.

<!--add video for weevely generate Password err.php -->






