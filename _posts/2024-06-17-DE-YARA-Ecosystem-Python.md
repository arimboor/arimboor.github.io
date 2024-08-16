---
title: Part 5.4 - Yara Ecosysyem . Python
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-17 12:00:00 -500
categories: [Bytes of Insights - YARA for Incident Response & Malware Hunting, Threat hunting with YARA for Microsoft Windows Endpoints]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/wallpaper_chik.jpg
  lqip: data:image/webp;base64,UklGRpoAAABXRUJQVlA4WAoAAAAQAAAADwAABwAAQUxQSDIAAAARL0AmbZurmr57yyIiqE8oiG0bejIYEQTgqiDA9vqnsUSI6H+oAERp2HZ65qP/VIAWAFZQOCBCAAAA8AEAnQEqEAAIAAVAfCWkAALp8sF8rgRgAP7o9FDvMCkMde9PK7euH5M1m6VWoDXf2FkP3BqV0ZYbO6NA/VFIAAAA
  alt: Responsive rendering of Chirpy theme on multiple devices.
---

https://github.com/VirusTotal/yara-python

```bash
pip3 install yara-python
```

```python
import yara
rule = yara.compile(source='rule foo: bar {strings: $a = "lmn" condition: $a}')
matches = rule.match(data='abcdefgjiklmnoprstuvwxyz')
print(matches)
```