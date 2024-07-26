---
title: Part 7.5 - Yara Ecosysyem . Python
description: Examples of text, typography, math equations, diagrams, flowcharts, pictures, videos, and more.
date: 2024-04-28 12:00:00 -500
categories: [Detection Engineering, Analyzing Windows Files using YARA rules]
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