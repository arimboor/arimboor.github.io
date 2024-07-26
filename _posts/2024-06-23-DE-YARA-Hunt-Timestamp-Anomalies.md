---
title: Part 6 - Hunting for files with Timestamp Anomalies.
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-23 12:00:00 -500
categories: [Detection Engineering, Bytes of Insights - YARA for Incident Response]
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