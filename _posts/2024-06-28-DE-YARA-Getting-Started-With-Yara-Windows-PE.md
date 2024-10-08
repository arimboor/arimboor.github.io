---
title: Part 1 - Getting started with YARA and Windows PE Files
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-28 12:00:00 -500
categories: [Detection Engineering - YARA and its Ecosystems, Part 1 - Introduction to YARA and Writing detection rules]
tags: [Yara, Windows PE]
pin: true
math: true
mermaid: true
image:
  path: /images/yara_main.png
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

### Windows PE File - Quick Internals

This is a huge topic with plenty of great blog posts, books, and YouTube videos available. I recommend everyone reading this content to check them out. Here, I'm aiming to cover the basic understanding you need to begin analyzing Windows PE from a YARA perspective. There are plenty of free tools available to quickly triage Windows PE files, like PEsudio, PEbear, floss, capa, strings, or you can even use YARA itself for triaging PE files.

The diagram below is a logical representation of a typical Windows PE file. It's important to know some of the key artifacts in a Windows PE file that will help when analyzing and writing detection rules in YARA. As shown in the diagram, a PE file can be logically split into 'Headers' and 'Sections'.

![Desktop View](/images/yara/yara_PE_header.png)

The PE file structure is a kind of container that the Windows OS understands and uses to load the file from the disk to the memory. It contains details the operating system needs, such as DLL imports, addresses, permissions, etc. Please Note, the addresses of the PE file on disk (raw address ) and in memory (virtual address) are different; however, this topic is more relevant for malware reverse engineering folks. To better understand the PE structure, let's open a sample Windows PE/ EXE in a hex editor. 

![Desktop View](/images/yara/yara_pe_hex_view.png)

- The first 64 bytes in a Windows PE files is the MZ header and last 4 bytes of this is the offset to the PE signature.
- The raw address 0x400h is typically the beginning of the execution code.
- The Rich header is an optional header and may contain information related to the OS build environment. Please note that not all PE files will have a Rich header.
- The .text section of the PE file generally contains the execution code of the program.

The hex view is quite good for analyzing the file; however, it is much easier to triage the PE file using tools such as PEStudio or PEBear, which automatically parse the PE files instead of manually going through them with a hex editor.

Here are some notes related to Windows PE files that are useful from a YARA perspective for identifying standout patterns:

- [x] The 'MZ' header is useful in a YARA perspective to detect the type of file we are dealing with. Windows EXE and DLL files have this header, and you can use this value when writing YARA rules. There is a concept called "magic numbers" in YARA, which refers to a sequence of bytes, typically represented in hexadecimal format, used to identify file types. I have covered this concept in more detail in the rule engineering section.

- [x] Entropy typically means the randomness of the file. In most cases, more randomness means a higher chance the file is encrypted, obfuscated, compressed, etc. We can calculate the entropy for the whole PE file or for each section when writing YARA rules. Using entropy-based detection is useful for detecting packers, which are typically found in malicious code. Packers are explained in the upcoming section.

- [x] The import table section provides the underlying operating system with the dependencies for the PE file, such as .dll files in a Windows environment. Instead of including all the required features and functionalities in the same PE file, we can leverage the underlying operating system libraries when writing a program and reference those.

- [x] In a normal Windows PE file, you can find one section flagged as X (executable). However, if you find more than one section in a PE file flagged as X (executable region), that should raise a red flag. It may indicate that we are dealing with packers.

- [x] PE files contain a couple of timestamps, which can be handy when writing detection rules. I'll cover one such example in the upcoming section based on a detection by Kaspersky Labs.

The table below shows some of the key timestamps we can use when writing the rules:

| Time Function                                                                | description   | 
| ----------------------------------------------------------------------------- | ---------- |
| pe.timestamp | PE timestamp  | 
| pe.export_timestamp         | the timestamp the export data was created   | 
| pe.resource_timestamp | the PE resource timestamp | 
| pe.signatures.not_before  | the timestamp on which the validity period for signature begins. |
| pe.signatures.not_after|the timestamp on which the validity period for signature ends.| 

The image below provides a quick overview of the interesting fields from a rule engineering perspective, using PEStudio.

![Desktop View](/images/yara/yara_pestudio_intro.svg)

## Dealing with Packed PE Files in YARA 

There are many legitimate use cases for using packers before distributing software, but these same packers can also be leveraged by threat actors to obfuscate malicious code and evade detection. There are numerous free, open-source, and commercial packers available, and by default, the YARA engine cannot unpack code on its own.

![Desktop View](/images/yara/yara-pack.gif){: width="672" height="289" .w-50 .right}

Some of the anomalies we can spot quickly are as follows. Please note that none of these guarantees the use of a packer, and multiple detection logic should be considered before finalizing the rule.

- [ ] Known Packer signature in the PE file header,
- [x] High Entropy (>7.0) for the PE Sections,
- [x] Relatively fewer strings are found in the PE file.
- [ ] Fewer function imports in the PE Import table.
- [ ] Flagged more than one executable (X) region in the file.

However, it's worth noting that VirusTotal’s YARA implementation in the cloud has some capabilities to unpack certain known packers. Similarly, you can build custom capabilities using the YARA Python module, but this functionality is not provided by default with the YARA engine.

In the past, I have used the  [**ProtectMyTooling**](https://github.com/mgeeky/ProtectMyTooling) project for packing code. This tool is quite effective and allows for multiple layers of packing through a simple user interface.

![Desktop View](/images/yara/protectmytool.png)

##  Types of Common File Hashes  

With so many file hashes available, it can be difficult to keep track of all of them. In simple terms, a hash is a unique signature for a file, generated using a one-way mathematical algorithm like MD5, SHA-1, SHA-256, SHA-512, etc.
![Desktop View](/images/yara/yara-brad.gif){: width="672" height="289" .w-50 .left}
 This value is unique to the file or input. Nowadays, there are many different types of hashes, and it can be overwhelming to know them all. On the VirusTotal online platform, you can find the most commonly used hashes in malware research and detection, which is a good starting point when you begin writing patterns and signatures using YARA rules. I have highlighted a few of these hashes and tried to explain some of them. The algorithms and other parameters are not within the scope of this section; however, I would like to detail the imphash due to its relevance in YARA-based detection.

![Desktop View](/images/yara/yara-hash.PNG){: width="672" height="289" }

- [x] Rich header hash : This hash is generated based on the optional PE Rich Header, which may provide clues about the environment in which the program was developed. Sometimes, it helps to identify multiple variants of a campaign or code developed by similar threat actors.
- [x] imphash : To calculate an imphash, all imported DLLs and their linked functions are saved in string format, concatenated, and then cryptographically hashed.
- [x] vhash: Available on the VirusTotal platform & can help identify similar files.
- [x] dhash:  Available on the VirusTotal platform, &  can help identify files with similar icons.
- [x] Permhash : Based on the hash, the declared permissions are applied to Chromium-based browser extensions and APKs.

In the following example, I took two distinct malware samples and generated their SHA-256 hashes. As expected, both hashes were different. However, when I generated the IMPHASH values, both hashes matched. This is a useful artifact when writing YARA rules. An IMPHASH-based rule can detect multiple variants of the same malware or different types of malware from the same threat actor, as they may reuse certain code and features across their malware.

![Desktop View](/images/yara/yara_imphash.png)

If you go to VirusTotal, you can use the tag shown below to search for similar hash files.

![Desktop View](/images/yara/imphash_vt.png)

In the next section, we will explore how to extract interesting artifacts from Windows PE files to create effective detection patterns.