---
title: Part 2 - Extracting Artifacts from Windows PE files
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-27 12:00:00 -500
categories: [Detection Engineering - YARA and its Ecosystems, Part 1 - Introduction to YARA and Writing detection rules]
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
![dark mode only](/images/yara/ioc.PNG){: .light }

> **`Unique Strings`** can be anything, including a `typo error` in the code, as malware authors are often found in non-English speaking countries.
{: .prompt-info }

Sometimes, the `PDB` (Program Database) file contains debugging information about a file. This information can be useful for threat attribution. Here are some examples of PDB strings found in real-life malware samples. 

```text
C:\Users\User\Desktop\Encrypt\Math_Cad\Release\Math_Cad.pdb
c:\users\user\documents\visual studio 2005\projects\adzxser\release\ADZXSER.pdb
C:\Users\muham\source\repos\loup\Debug\loup.pdb
C:\Users\user\Desktop\my_OK_2014\bit9\runsna\Release\runsna.pdb
D:\MyProjects\spreader\Release\ssExecutor_x86.pdb fullword ascii
C:\Projets\vbsedit_source\script2exe\Release\mywscript.pdb
C:\Users\john\Desktop\PotPlayer\Release\PotPlayer.pdb
C:\Work64\ADM\XFS\Release\XFS.pdb
C:\Documents and Settings\Administrator\Desktop\GetPAI\Out\IE.pdb
D:\Develop\sps\neuron2\x64\Release\dcomnet.pdb
C:\Users\cyttek\Downloads\xfs_cashXP\Debug\xfs_cash_ncr.pdb
C:\WRK\GHook\gHook\x64\Debug\gHookx64.pdb
c:\Users\user\Desktop\ImageAgent\ImageAgent\PreAgent\src\builder\agent.pdb 
```

## How to extract artifacts from files ?

There are quite a few tools out there that can help to analyze the interesting artifacts in a file. Some of my favorite tools are listed below; however, use the one you are comfortable with. 

![dark mode only](/images/yara/extract_tools.PNG){: .dark   }
![dark mode only](/images/yara/extract_tools.PNG){: .light   }

Be careful when using automated rule creation tools such as YaraGen.py. This requires additional manual rule review before rolling out in a production environment.

### Option 1 : Using CyberChef

Here, I will use the CyberChef tool to extract interesting artifacts from a Windows PE file.

### Option 2 : Using Strings

Here, I will use the Linux built-in utility to extract interesting artifacts from a Windows PE file.

###  Option 3 : Using FLOSS

Here, I will use the Mandiant FLOSS (FLARE Obfuscated String Solver) tool to extract interesting artifacts from a Windows PE file.

###  Option 4 : Using Ghidra

Here, I will use the Ghidra Tool to extract interesting artifacts from a Windows PE file.

###  Option 5 : Using YARA itself

Finally, we can use the YARA engine itself to extract interesting artifacts from a file.

## Code Block vs Data Block

When writing a rule, we can create a high-fidelity rule that focuses on a specific malware sample associated with a particular campaign. Even though the rule detects the malware, the flip side is that when threat actors reuse the same malware for another campaign and change certain parameters, the rule cannot detect the new variant.

In most cases, especially malware authors spend a significant amount of time developing the malware and often reuse certain underlying code bases such as **tunnel** techniques, **encryption** algorithms, antivirus **evasion** methods, data **exfiltration**, etc. Changing these code bases requires a significant amount of effort and time. 

In some cases, I have seen threat actors deploy multiple variants of the same malware in an ongoing campaign by changing the C2 URL only.

In the analogy below, it's the same person but with small changes to the appearance. It looks different, but under the hood, it's all the same.

![light mode only](/images/yara/codevsdata.PNG){: .light  }
![dark mode only](/images/yara/codevsdata.PNG){: .dark   }

Another analogy is something like making a pizza. The dough, tomato sauce, and cheese are common in all pizzas (`the code block`), but based on the customer's needs, they can add chicken, meat, vegetables, etc (`the data block`).

Having a rule focused on these code blocks can be a very good approach and can detect not just one variant but also other variants from similar threat actors. This is the reason some YARA rules work effectively even after a few years.

> Code block-based YARA rules also helps to attribute the threat actor to an extent, but not always
{: .prompt-info }

In the next section, we will explore how rule engineering to create effective detection patterns.