---
title: Part 4.3 - Hunting for files with Timestamp Anomalies.
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-23 12:00:00 -500
categories: [Detection Engineering - YARA and its Ecosystems, Part 2 - Threat hunting use cases for real world cases]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/yara_main.png
  
---

Sometimes, it takes common sense rather than just technical skills to uncover malware code. This example is based on the research published by Kaspersky Labs on TripleFantasy.The research team discovered the following sample, and upon analyzing the basic timestamp details, they noticed that the file was compiled on June 3, 2000, and is a 64-bit binary.

![Desktop View](/images/yara/timestomp.PNG)

I used ChatGPT to ask a question related to the Windows 64-bit operating system. 

![Desktop View](/images/yara/gpt_x64.png){: width="568" height="468" }

This clearly indicates when Microsoft first released the 64-bit operating system. This means the executable should be analyzed.

Here is the YARA rule to look for a Windows 64-bit executable with a specified timestamp:

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

<!-- 

https://www.youtube.com/watch?v=PEy-l6fduHo&ab_channel=JohnHammond
https://www.youtube.com/watch?v=4Qo8aKi9aKw&ab_channel=JaiMinton -> havoc C2
https://github.com/JPMinty/Detection_Engineering_Signatures/blob/main/yara/win_havoc_c2_demon_API_hashes.yar

https://aws.amazon.com/blogs/apn/best-practices-from-infopercept-on-malware-detection-with-yara-rules-and-shu%EF%AC%84e-soar/


get a diak image or mem with cobaltstike trhen try becon or C2 

https://github.com/Yara-Rules/rules/blob/master/email/Email_generic_phishing.yar

https://github.com/mandiant/speakeasy 

malware emulation 

https://github.com/Neo23x0/signature-base/blob/master/yara/apt_saudi_aramco_phish.yar

-->
