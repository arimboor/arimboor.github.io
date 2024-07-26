---
title: Part 5 - Hunting for Web Shells deployed on Servers.
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-24 12:00:00 -500
categories: [Detection Engineering, Bytes of Insights - YARA for Incident Response]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/wallpaper_chik.jpg
  
---

<!-- PROD -->


![Desktop View](/images/yara/webshell.PNG)
_Full screen width and center alignment_


## CASE 1 : Hunt for webshells

<!-- PROD END-->

Types of web shell
Full and reversehell
Can read logs as ell 
Log4j 
Wscx logs

https://github.com/Neo23x0/signature-base/blob/master/yara/cn_pentestset_webshells.yar


A Web shell is a script placed on an openly accessible Web server, enabling an adversary to use the server as a gateway into a network. It can offer a set of functions for execution or provide a command-line interface on the system hosting the Web server.
It includes strings related to base64 decoding and conditions specifying the presence of certain decoded strings, along with other functions and a defined file size range.For instance, checking for the presence of base64 decoding, specific functions, and file size within a defined range.


weevely generate Password err.php
xample: Scanning default IIS web directories using the base ruleset > .\yara64.exe -r -C base.yara.bin C:\inetpub\wwwroot\
Example: Scanning default Apache web directories using the extended ruleset $ yara -r extended.yara.bin /var/www/html/

Small webshell vs big webshells
https://www.aon.com/cyber-solutions/aon_cyber_labs/detecting-effluence-an-unauthenticated-confluence-web-shell/
Web sheel drops in excnahe / citrix. aall over web 
