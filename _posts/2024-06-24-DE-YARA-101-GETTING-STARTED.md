---
title: Part 1 - Getting started with YARA. 
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-24 12:00:00 -500
categories: [Detection Engineering, Analyzing Windows Files using YARA rules]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/yara_main.png
---

I believe there's no need to introduce [**YARA**](https://github.com/VirusTotal/yara) to anyone working in the cybersecurity especially in the areas of detection engineering, but I'd still like to briefly cover some basics so that we're all on the same page.

The YARA engine is one of the most popular tools for pattern matching in files, and it's been around for more than 10 years.



### Why Pattern Matching? 

![Desktop View](/images/yara/yara-face0.jpg){:  width="672" height="289"  .w-50 .right} 
Traditional hash-based indicators, which rely on precise matches, frequently fall short against advanced attackers. A single modification to the code can render these indicators ineffective, evading signature-based detections. 

![Desktop View](/images/yara/yara-face.gif){: width="672" height="289" .w-50 .right}
A simple tweak will allow threat actor to get around hash-based detection. Hash-based detection is only effective for identifying known malware samples; it cannot detect a new variant of prevalent malware.

A pattern-based approach relies on different patterns in malicious files instead of signatures, making it useful for identifying variants of malware. The detection engineer can extract useful patterns from malware samples and write detection logic based on them. For example, they can focus on specific encryption logic used in the samples, the tunneling methods used in the code, etc.


### What are the key use cases ?


- `Threat Detection`{: .filepath}
- `Threat Attribution`{: .filepath}
- `Threat Research`{: .filepath}
- `Malware Classification`{: .filepath}

![light mode only](/images/yara/yara1-w.PNG){: .light .w-75  .rounded-10 w='2212' h='768' } 
![dark mode only](/images/yara/yara1.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }

![dark mode only](/images/yara/kenu.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }
![light mode only](/images/yara/kenu_white.PNG){: .light .w-75  .rounded-10 w='2212' h='768' }

Since the rules are written based on the patterns identified in malicious files, YARA can detect various campaigns with a single rule.

### Who is using YARA nowadays ?

YARA is an open-source project, so the engine is used in many commercial and open-source products. Full list can be found [**here**](https://github.com/VirusTotal/yara). In general, most endpoint detection tools and tech stacks for file analysis use the YARA engine in one way or another.


![light mode only](/images/yara/yara3_white.PNG){: .light .w-75  .rounded-10 w='2212' h='768' } 
![dark mode only](/images/yara/yara3.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }


### How is the logic written?

The YARA engine can search for specific keywords or hex patterns in files and is supported by a variety of built-in functions for file handling. The rules are written in a language that's easy to understand.

![light mode only](/images/yara/yara4-w.PNG){: .light .w-75  .rounded-10 w='2212' h='768' } 
![dark mode only](/images/yara/yara4.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }

>Everything is written as `KEY` and `VALUE` pairs in the rules
{: .prompt-tip }

All rules begin with the keyword "rule", and the logic of the rule is written inside {}. There are mainly three sections to the rule: 'meta', 'strings', and 'condition'. The 'meta' section is completely optional, but I highly recommend adding it when you write rules. Some items you can include are reference links to blogs, MD5/SHA256 values of the sampels, assembly code snippets, etc. 



To kick things off, here is a simple rule (I'll cover the details in the rule engineering section, but I just wanted to give you an overview of how the rule is structured.) 

```bash
rule simple_rule 

{
    meta: 
             author = "Jinto Antony" 
        strings: 
             $string = “malware_string" ascii wide nocase 
             $regex = /abcd[x-z]/ 
             $hex = { 63 62 61} 
        condition: 
             $hex at 0 and ( $re or $str ) 
} 
```
### Why don't researchers publish rules?

> Malware developers sometimes leverage publicly available YARA rules written by security researchers to understand how their malware code is being detected. Often, they change their campaign's code as a result. This is one reason why not all YARA rules are published on the internet by security researchers and companies.
{: .prompt-danger }



