---
title: Part 2 - Extracting Artifacts from Windows PE files
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-27 12:00:00 -500
categories: [Detection Engineering, Bytes of Insights - YARA for Incident Response]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/yara_main.png
---

## What are interesting artifacts ?

To build a YARA rule to detect malicious code, we would first need to analyze and extract interesting artifacts from the file. The following are common interesting artifacts found in a file, such as a Windows PE Executable. Please note that there could be other interesting artifacts as well that can be found, but it will be difficult to include all of them in the blog.


![dark mode only](/images/yara/ioc.PNG){: .dark   }

> **`Unique Strings`** can be anything, including a `typo error` in the code, as malware authors are often found in non-English speaking countries.
{: .prompt-info }

## How to extract artifacts from files ?

There are quite a few tools out there that can help to analyze the interesting artifacts in a file. Some of my favorite tools are listed below; however, use the one you are comfortable with. 


![dark mode only](/images/yara/extract_tools.PNG){: .dark   }

Be careful when using automated rule creation tools such as YaraGen.py. This requires additional manual rule review before rolling out in a production environment.

### Option 1 : Using CyberChef

add few images/ gif / videos files as examples 

load exe -> extarct string -> run yara rule 

### Option 2 : Using Strings

add few images/ gif / videos files as examples 

###  Option 3 : Using FLOSS

add few images/ gif / videos files as examples 

###  Option 4 : Using Ghidra

add few images/ gif / videos files as examples 

###  Option 5 : Using YARA itself

add few images/ gif / videos files as examples 

## Code Block vs Data Block ?

When writing a rule, we can create a high-fidelity rule that focuses on a specific malware sample associated with a particular campaign. Even though the rule detects the malware, the flip side is that when threat actors reuse the same malware for another campaign and change certain parameters, the rule cannot detect the new variant.

In most cases, especially malware authors spend a significant amount of time developing the malware and often reuse certain underlying code bases such as **tunnel** techniques, **encryption** algorithms, antivirus **evasion** methods, data **exfiltration**, etc. Changing these code bases requires a significant amount of effort and time. 

In some cases, I have seen threat actors deploy multiple variants of the same malware in an ongoing campaign by changing the C2 URL.

In the analogy below, it's the same person but with small changes to the appearance. It looks different, but under the hood, it's all the same.

![light mode only](/images/yara/codevsdata.PNG){: .light  }
![dark mode only](/images/yara/codevsdata.PNG){: .dark   }

Another analogy is something like making a pizza. The dough, tomato sauce, and cheese are common in all pizzas (`the code block`), but based on the customer's needs, they can add chicken, meat, vegetables, etc (`the data block`).

Having a rule focused on these code blocks can be a very good approach and can detect not just one variant but also other variants from similar threat actors. This is the reason some YARA rules work effectively even after a few years.

> Code block-based YARA rules also helps to attribute the threat actor to an extent, but not always
{: .prompt-info }


<!-- PROD END-->



<!-- 


yaraQA : YARA rule Analyzer to improve rule quality and performance
YARA-CI helps you to keep your YARA rules in good shape. It can be integrated into any GitHub repository containing YARA rules, and it will run automated tests every time you make some change. The automated tests include:










-->

