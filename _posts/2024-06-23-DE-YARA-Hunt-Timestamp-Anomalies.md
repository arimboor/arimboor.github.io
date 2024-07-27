---
title: Part 6 - Hunting for files with Timestamp Anomalies.
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-23 12:00:00 -500
categories: [Detection Engineering, Bytes of Insights - YARA for Incident Response & Malware Hunting]
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


https://www.youtube.com/watch?v=PEy-l6fduHo&ab_channel=JohnHammond
https://www.youtube.com/watch?v=4Qo8aKi9aKw&ab_channel=JaiMinton -> havoc C2
https://github.com/JPMinty/Detection_Engineering_Signatures/blob/main/yara/win_havoc_c2_demon_API_hashes.yar

https://aws.amazon.com/blogs/apn/best-practices-from-infopercept-on-malware-detection-with-yara-rules-and-shu%EF%AC%84e-soar/


get a diak image or mem with cobaltstike trhen try becon or C2 

https://github.com/Yara-Rules/rules/blob/master/email/Email_generic_phishing.yar

https://github.com/mandiant/speakeasy 

malware emulation 

https://github.com/Neo23x0/signature-base/blob/master/yara/apt_saudi_aramco_phish.yar


xx

## CASE 1 : Hunt for Packed Executables 

> example 1

```bash
import "pe"
rule basedOnString
{
    condition:
        for any i in (0 .. pe.number_of_sections): 
            (pe.sections[i].name == ".aspack")
}
```

> example 2

```bash
import "math"
rule basedOnEntropy {
  condition:
    math.entropy (0, filesize) > 7
}
```

> example 3

```bash
import "pe"
import "math"
rule basedOnEntropy
{
    condition:
    for any resource in pe.resources: ( 
    math.in_range(math.entropy(resource.offset, resource.length),7.8, 8.0))
}
```




## CASE 1 : Hunt for maldocs 

## CASE 1 : Hunt for Cobaltstike beacons 
