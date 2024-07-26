---
title: Part 5.4 - Hunting with YARA -Timestomping.
description: Examples of text, typography, math equations, diagrams, flowcharts, pictures, videos, and more.
date: 2024-04-25 12:00:00 -500
categories: [Detection Engineering, Analyzing Windows Files using YARA rules]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/wallpaper_chik.jpg
  
---

<!--PROD -->
## CASE 1 : Hunt for Timestomped  Executables


![Desktop View](/images/yara/gpt_x64.png){: width="468" height="468" }
_Full screen width and center alignment_


```bash
import "pe"
rule timestmping
  {
  condition:
    uint16(0) == 0x5A4D and
    (pe.machine ==  pe.MACHINE_AMD64 or pe.machine == pe.MACHINE_IA64) and 
    pe.timestamp < 1114435200 // April 25 2005
  }
```
<!--PROD End-->