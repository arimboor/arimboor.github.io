---
title: YARA and its enterprise ecosystems for Threat Hunting
description: Detection Engineering Using YARA.
date: 2024-04-27 12:00:00 -500
categories: [Detection Engineering, YARA for Threat Hunting]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/yara/post.jpg
---

I believe there's no need to introduce [**YARA**](https://github.com/VirusTotal/yara) to anyone working in the cybersecurity especially in the areas of detection engineering & Malware hunting, but I'd still like to briefly cover some basics to ensure we are all on the same page.

The YARA engine is one of the most popular tools for pattern matching in files, and it's been around for more than 10 years. Recently, the rule engine was rewritten in the Rust programming language and that is now called [**YARA-X**](https://github.com/VirusTotal/yara-x). In this series, I will be demonstrating how to use the Yara engine, which is primarily written in the C programming language.

### Why Pattern Matching? 

![Desktop View](/images/yara/yara-face0.jpg){:  width="672" height="289"  .w-50 .right} 
Traditional hash-based indicators, which rely on precise matches, frequently fall short against advanced attackers. A single modification to the code can render these indicators ineffective, evading signature-based detections. 

![Desktop View](/images/yara/yara-face.gif){: width="672" height="289" .w-50 .right}
Hash-based detection is only effective for identifying known malware samples; it cannot detect a new variant of prevalent malware. A simple tweak will allow threat actor to get around hash-based detection.

A pattern-based approach relies on different patterns in malicious files instead of signatures, making it useful for identifying variants of malware. We can extract useful patterns from malware samples and write detection logic based on them. For example, they can focus on specific encryption logic used in the samples, the tunneling methods used in the code, etc.

### What are the key use cases ?

- `Threat Detection`{: .filepath}
- `Threat Attribution`{: .filepath}
- `Threat Research`{: .filepath}
- `Malware Classification`{: .filepath}

![light mode only](/images/yara/yara1-w.PNG){: .light .w-75  .rounded-10 w='2212' h='768' } 
![dark mode only](/images/yara/yara1.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }

![dark mode only](/images/yara/kenu.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }
![light mode only](/images/yara/kenu_white.PNG){: .light .w-75  .rounded-10 w='2212' h='768' }

Since YARA rules are based on patterns identified in malicious files rather than on specific signatures, a well-written YARA rule can detect various campaigns with a single rule.

> Threat Actors sometimes leverage publicly available YARA rules written by security researchers to understand how their malware code is being detected. Often, they change their campaign's code as a result. This is one reason why not all YARA rules are published on the internet by security researchers and companies.
{: .prompt-danger }

### Who is using YARA nowadays ?

YARA is an open-source project, so the engine is used in many commercial and open-source products. Full list can be found [**here**](https://github.com/VirusTotal/yara). In general, most endpoint detection tools and tech stacks for file analysis use the YARA engine in one way or another.  A fun fact is that you might already be using the Yara engine without even realizing it. For example, macOS has Yara integrated for malware detection.

![light mode only](/images/yara/yara3_white.PNG){: .light  } 
![dark mode only](/images/yara/yara3.PNG){: .dark  }

### How is the logic written?

Every new technology comes with its own learning curve, and the challenge often lies in how easy or difficult it is to write the detection logic. Fortunately, with Yara, writing and understanding the detection logic is quite straightforward. The main learning curve involves gaining a good understanding of file-based artifacts. Once you grasp this concept, diving into YARA becomes much easier. The rules are written in a language that's easy to understand and can search for specific keywords or hex patterns in files., 

![light mode only](/images/yara/yara4-w.PNG){: .light .w-75  .rounded-10 w='2212' h='768' } 
![dark mode only](/images/yara/yara4.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }

>Everything is written as `KEY` and `VALUE` pairs in the rules
{: .prompt-tip }

I recommend exploring the comprehensive [**documentation**](https://yara.readthedocs.io/en/latest/) to gain an in-depth understanding of rule engineering. However, I’ll focus on the minimum necessary knowledge to help you get started with creating YARA rules.

All rules begin with the keyword "rule", and the logic of the rule is written inside {}. There are mainly three sections to the rule: 'meta', 'strings', and 'condition'. The 'meta' section is completely optional, but I highly recommend adding it when you write rules. Some items you can include are reference links to blogs, MD5/SHA256 values of the sampels, assembly code snippets, etc. The 'strings' section is where you specify the patterns you want to detect in malicious files, while the 'condition' section is where you write the actual logic. 

From my experience, a significant amount of time is spent identifying the malicious patterns in the file. Once that's done, writing the rule itself is relatively straightforward. Keep in mind that the rule logic depends entirely on your target objective. Are you aiming for specific malware detection, or are you conducting broader threat hunting to identify various threats from the same campaign or threat group?

To kick things off, here is a simple YARA rule (I'll cover the details in the rule engineering section, but I just wanted to give you an overview of how the rule is structured.) 

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
### Enterprise Ecosystem

It’s crucial to understand how YARA rules can be rolled out in a real enterprise environment. This is the core of the matter: if you don’t have an enterprise tech stack for detection and hunting using these rules, investing time in learning YARA might not be worthwhile.

Here I'll share some ecosystems where I have used YARA rules for threat hunting and incident response activities. I believe it's valuable to share these insights. While I’ll delve into how these ecosystems work with YARA in later sections, I wanted to give you a quick glimpse to spark some excitement as we get started.

![light mode only](/images/yara/yara_eco_white.PNG){: .light  } 
![dark mode only](/images/yara/yara_eco.PNG){: .dark  }

> Python Module : Developers can leverage YARA Python bindings for implementing various use cases
{: .prompt-info }