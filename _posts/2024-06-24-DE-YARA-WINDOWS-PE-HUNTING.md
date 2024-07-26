---
title: Bytes of Insights - Hunting for Windows malwares using YARA. 
description: Bytes of Insights - Hunting for Windows malwares using YARA.
date: 2024-04-24 12:00:00 -500
categories: [Detection Engineering, Bytes of Insights - Hunting for Windows malwares using YARA]
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


![light mode only](/images/yara/yara3_white.PNG){: .light  } 
![dark mode only](/images/yara/yara3.PNG){: .dark  }


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

### Enterprise Ecosystem?


![light mode only](/images/yara/yara_eco_white.PNG){: .light  } 
![dark mode only](/images/yara/yara_eco.PNG){: .dark  }

> Python Module : Developers can leverage YARA Python bindings for implementing various use cases
{: .prompt-info }


> Malware developers sometimes leverage publicly available YARA rules written by security researchers to understand how their malware code is being detected. Often, they change their campaign's code as a result. This is one reason why not all YARA rules are published on the internet by security researchers and companies.
{: .prompt-danger }


Instead of putting everything in one blog post, I’ve divided the topics into smaller subtopics. This makes it easier to digest. Feel free to jump into any topic or follow along in order.

1. Part 1 - Getting started with YARA for Windows PE File Analysis 
2. Part 2 - Windows PE File Insights from YARA perspective.
3. Part 3 - Extract Windows PE Artifacts to build YARA rules 
4. Part 4 - YARA Rule Engineering & Modules for Windows Files.
5. Part 5- Threat Hunting using YARA on Windows Enviroment.
6. Extended YARA using VT
7. Ecosystem - Osquery
8. Ecosystem - Velociraptor 
9. Ecosystem - Zeek 
10. Ecosystem - Veem Backup



This is a huge topic with plenty of great blog posts, books, and YouTube videos available. I recommend everyone reading this blog to check them out. Here, I'm aiming to cover the basic understanding you need to begin analyzing Windows PE from a YARA perspective.

There are plenty of free tools available to quickly triage Windows PE files, like PEsudio, PEbear, floss, capa, strings, or you can even use YARA itself for triaging PE files.

The diagram below is a logical representation of a typical Windows PE file. It's important to know some of the key artifacts in a Windows PE file that will help when analyzing and writing detection rules in YARA. As shown in the diagram, a PE file can be logically split into 'Headers' and 'Sections'.

![Desktop View](/images/yara/yara_PE_header.png)

To better understand the PE structure, let's open a sample Windows EXE in a hex editor. The first 64 bytes in a Windows PE files is the MZ header and last 4 bytes of this is the offset to the PE signature.

![Desktop View](/images/yara/yara_pe_hex_view.png)

The PE file structure is a kind of container that the Windows OS understands and uses to load the file from the disk to the memory. It contains details the operating system needs, such as DLL imports, addresses, permissions, etc.

The addresses of the PE file on disk (raw address ) and in memory (virtual address) are different; however, this topic is more relevant for malware reverse engineering folks.

The raw address 0x400h is typically the beginning of the execution code.

The hex view is quite good for analyzing the file; however, it is much easier to triage the PE file using tools such as PEStudio or PEBear, which automatically parse the PE files instead of manually going through them with a hex editor.

The 'MZ' header is useful in a YARA perspective to detect the type of file we are dealing with. Windows EXE and DLL files have this header, and you can use this value when writing YARA rules.

The Rich header is an optional header and may contain information related to the OS build environment. Please note that not all PE files will have a Rich header.

The .text section of the PE file generally contains the execution code of the program.

Entropy typically means the randomness of the file. In most cases, more randomness means a higher chance the file is encrypted, obfuscated, compressed, etc. We can calculate the entropy for the whole PE file or for each section when writing YARA rules. Using entropy-based detection is useful for detecting packers, which are typically found in malicious code. Packers are explained in the upcoming section.

The import table section provides the underlying operating system with the dependencies for the PE file, such as .dll files in a Windows environment. Instead of including all the required features and functionalities in the same PE file, we can leverage the underlying operating system libraries when writing a program and reference those.

In a normal Windows PE file, you can find one section flagged as X (executable). However, if you find more than one section in a PE file flagged as X (executable region), that should raise a red flag. It may indicate that we are dealing with packers.

![Desktop View](/images/yara/yara_pestudio_intro.svg)

PE files contain a couple of timestamps, which can be handy when writing detection rules. I'll cover one such example in the upcoming section based on a detection by Kaspersky Labs.

The table below shows some of the key timestamps we can use when writing the rules:


| Time Function                                                                | description   | 
| ----------------------------------------------------------------------------- | ---------- |
| pe.timestamp | PE timestamp, as an epoch integer  | 
| pe.export_timestamp         |he timestamp the export data was created   | 
| pe.resource_timestamp | Resource timestamp | 
| pe.signatures.not_before  | Unix timestamp on which the validity period for this signature begins. |
| pe.signatures.not_after| Unix timestamp on which the validity period for this signature ends.| 


## Dealing with Packed PE Files 

![Desktop View](/images/yara/yara-pack.gif){: width="672" height="289" .w-50 .right}


Some of the anomalies we can spot quickly are as follows. Please note that none of these guarantees the use of a packer, and multiple detection logic should be considered before finalizing the rule.

- [ ] Known Packer signature in the PE file header,
- [x] High Entropy (>7.0) for the PE Sections,
- [x] Relatively fewer strings are found in the PE file.
- [ ] Fewer function imports in the PE Import table.
- [ ] Flagged more than one executable (X) region in the file.


By default, the YARA engine cannot parse packers. However, we can either use YARA Python to unpack them if we know how, or use the VirusTotal online platform's YARA engine, which can parse a few known packers and apply the rules.

![Desktop View](/images/yara/protectmytool.png)

<!-- prod above -->





<!-- 

? what about .net excuatables 
? export table senarious 
Complie code 
Byte code 
Add pestudio / pe bear  / yara –D
pe.imphash() == "2524e5e9fe04d7bfe5efb3a5e400fe4b"

Packer to sandbox
VT search tags 
entropy
https://forensicitguy.github.io/adventures-in-yara-hashing-entropy/
Explain the API hashing 

OLE2 format 

Office OpenXML format
*By default : Yara can’t deflate the compressed file to look inside


challenge in rule writing : certain file formats make writing YARA rules more difficult. 
For instance, malware stored in the Office Open XML file format is generally more tricky to detect than the OLE2 compound storage, because of the additional layer of ZIP compression. 
Since YARA itself doesn’t support ZIP decompression natively, you need to handle that with external tools. 

Explian OLE2 format 

https://0xdf.gitlab.io/2019/03/27/analyzing-document-macros-with-yara.html
https://www.mandiant.com/resources/blog/detecting-embedded-content-in-ooxml-documents

### How to identify the common file types on Windows?
### Compile code VS Byte Code
### How to identify the file types?
### Dealing with compressed files 


```bash
import "pe"
rule INFO_ASPACK_PACKER {
	meta:
		description = "Detection of ASPACK Packer renamed section names"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "866028bad1dd43edb256416a71896584e02294cba419dd508a8a2afc81ac5ebc"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack" or
                pe.sections[i].name == ".adata" or
                pe.sections[i].name == "ASPack" or
                pe.sections[i].name == ".ASPack"
            )
        )
}
```

```bash
rule INDICATOR_EXE_Packed_VMProtect {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with VMProtect."
        snort2_sid = "930049-930051"
        snort3_sid = "930017"
    strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}
```

```bash
rule INDICATOR_EXE_Packed_LLVMLoader {
    meta:
        author = "ditekSHen"
        description = "Detects LLVM obfuscator/loader"
        clamav_sig = "INDICATOR.Packed.LLVMLoader"
    strings:
        $s1 = "exeLoaderDll_LLVMO.dll" fullword ascii
        $b = { 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 ?? 96 01 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? 45 78 69
               74 50 72 6f 63 65 73 73 00 4b 45 52 4e 45 4c 33
               32 2e 64 6c 6c 00 00 00 00 00 00 }
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x0158) and ((pe.exports("StartFunc") and 1 of ($s*)) or all of ($s*) or ($b))
}
```




https://www.youtube.com/watch?v=fWV8Dh_RBZU&ab_channel=MalwareAnalysisForHedgehogs
https://securelist.com/the-devils-in-the-rich-header/84348/
https://forensicitguy.github.io/rich-header-hashes-with-pefile/
https://github.com/RichHeaderResearch/RichPE
-->

##  Types of Common File Hashes  
In simple terms, a hash is a unique signature for a file, generated using a one-way mathematical algorithm like MD5, SHA-1, SHA-256, SHA-512, etc.
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

## Identify File Types 


Decoding Magic Numbers 


![Desktop View](/images/yara/magic_numbers.png)
_Full screen width and center alignment_


We can write rule conditions that depend on data stored at a certain file offset or memory virtual address, using the following functions,

**int** 8/16/32 | reads 8, 16, and 32 bits signed integers  - `little-endian` format | 
**uint** 16/32 | reads 16, and 32 bits signed integers  - `little-endian` format | 
**int** 8/16/32**be** | reads 8, 16, and 32 bits signed integers  -` big-endian` format | 
**uint** 16/32**be** | reads 16, and 32 bits signed integers  - `big-endian` format | 

{% include embed/youtube.html id='oMAvSpq9fYY' %}


> In a `little-endian` format the byte order is reversed with the most significant byte on the right
{: .prompt-tip }

Here are some of the most commonly used magic numbers I have come across while writing rules

**Magic Number** | **Description** | 
uint16(0) == 0x5a4d | MZ signature at offset 0 |
uint16be(0) == 0x4D5A | MZ signature at offset 0 | 
uint32(uint32(0x3C)) == 0x00004550 | PE signature at offset stored in MZ header at 0x3C | 
uint32be(0) == 0x7f454c46 | Linux ELF signature at offset 0 | 
uint16(0) == 0x457f | Linux ELF signature at offset 0| 
uint32(0) == 0xfeedface | MacOS macho2 |
uint32(0) == 0xfeedfacf | MacOS macho64 | 
uint32(0) == 0xcefaedfe | MacOS macho64_2 | 
uint32(0) == 0xcffaedfe | MacOS macho64_3 | 
uint32be(0) == 0x504b0304 | unencrypted xlsx,  pkzip, DOCX, PPTX, XLSX (PKZIP) |
int16(0) == 0x4B50 | pkzip | 
uint32be(0) == 0xd0cf11e0 | encrypted xlsx = CDFV2  DOC, PPT, XLS |
uint16(0) == 0xcfd0 | Word/Office Document| 
uint32be(0) == 0x7B5C7274 | RTF signature at offset 0| 
uint32(0) == 0x74725C7B | rtf signature at offset 0| 
uint32be(0) == 0x4d494d45 | MIME header |
uint32(0) == 0x21726152 | Rar! | 
uint32(0) == 0x52617221 | rar signature at offset 0 | 
uint32(0) == 0x04034b50 | zip signature at offset 0 | 
uint16(0) == 0x1f8b | gzip signature at offset 0 | 
uint32(0) == 0x377abcaf |  7zip signature at offset 0 | 
uint32(0) == 0x75737461 | tar signature at offset 0| 
uint32(32769) == 0x43443030 | iso |
uint32be(0) == 0x3c3f786d | <?xm |
uint16(0) == 0x004c | Windows lnk signature at offset 0| 
uint32(0) == 0x25504446 | pdf signature at offset 0| 
uint32(0) == 0x53514c69 | sqlite signature at offset 0 | 
uint32(0) == 0x89504e47 | png signature at offset 0 | 

<!-- one note check this E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 -->










<!--
int16(uint32(0x3C) + 0x5c) == 0x0001
uint16(0) == 0x3f3c 
uint16(0) == 0x253c
uint16(0) == 0x6568 
uint16(0) == 0x7566
uint16(0) == 0x457f
uint16(0) == 0xfeff
uint16(0) == 0x2123
uint16(0) == 0x004c 
uint16(0) == 0x3558
uint16(0) == 0xcfd0
uint16(0) == 0x4b50
uint16(0) == 0x7375
uint16(0) == 0x7566
uint16(0) == 0x0d7b
uint16(0) == 0xfeca 
uint16(0) == 0xfacf 
uint16(0x10) == 0x0002
uint16(0) == 0xedac
uint16(0) == 0xb0b0 // AV sigs file
uint16(0) == 0x5953 // AV sigs file
uint16be(filesize-2) == 0x2722 or  /* Footer 1 */
uint16(0) == 0x004c 
uint16(0) == 0x6152
uint16(0) == 0x4947 
uint16(0) == 0x6620
uint16(0) == 0x7473
uint16(filesize-3) == 0x0d25 
uint16(uint32(0x3C)+0x18) == 0x020B
uint16(0) == 0x544
uint16(0) == 0x5A4D 
uint16(0) == 0xCFD0 
uint16(0) == 0xC3D4 
uint16(0) == 0xfacf 
uint16(0) == 0x4b50
uint16(0) == 0x2123
uint16(0) == 0x6553
uint32(0) == 0x4D583F3C or uint32(0) == 0x6D78F3C ) /* <?XM or <?xm */
uint32(0) == 0x66676572 // not regf (registry hives)
uint32(0) == 0xE011CFD0
uint32(4) == 0x464c457f
uint32(0x28) == 0x00000000
uint32(0x28) == uint32(0x2c)
uint32(0) == 0x434d5953 // Symantec AV sigs file
int32(uint32(0x3c) ^ uint32(0x28)) ^ uint32(0x28) == 0x00004550
uint32(0) == 0x464c457f 
uint32(0) == 0xBEBAFECA 
uint32(0) == 0xFEEDFACE 
uint32(0) == 0xFEEDFACF 
uint32(0) == 0xCEFAEDFE
uint32(4) == 0x00021401
uint32be(0) == 0x696d706f // import
uint32(0) == 0x752f2123  ! may be macos
uint32(0) == 0x0000004c 
uint32be(0) == 0x41747472 
uint32be(0) == 0x61747472 
uint32be(0) == 0x41545452  //File start with Attribute
uint32(0) == 0x46445025 
uint32(1) == 0x6674725C
uint32(uint32(0x3C)) == 0x0000AD0B /* malformed PE header > 0x0bad */
uint32(0) == 0x4e4f435b
uint32(uint32(0x3C)) == 0x00004550 
uint32(0) == 0x2D2D2D2D
uint32(0) == 0x4450250a
uint32be(0x0) == 0x4C000000
uint32be(0) == 0x7B5C7274
(uint32(0) == 0x616f733c or uint32(0) == 0x54534f50)  //'<soa' or 'POST'   
uint32be(0) == 0xD0CF11E0
uint32(0) == 0x46445025
uint8(4) == 0x66 
uint8(5) == 0x31 
uint8(6) == 0x5c
uint8(2) == 0x46 /* GIF */
uint8(11) == 0x00 /* Background Color Index != 0 */
uint8(12) == 0x00 /* Pixel Aspect Ratio != 0 */
int8(filesize-1) == 0x3b /* Trailer (trailes are often 0x00 byte padded and cannot server as sole indicator) */
uint8(filesize-1) == 0x0a
uint8(28) == 0x4D
-->



<!--![Desktop View](/images/yara/test3.svg) -->


<!--{% include embed/youtube.html id='Balreaj8Yqs' %} -->

## What are interesting artifacts ?

To build a YARA rule to detect malicious code, we would first need to analyze and extract interesting artifacts from the file. The following are common interesting artifacts found in a file, such as a Windows PE Executable. Please note that there could be other interesting artifacts as well that can be found, but it will be difficult to include all of them in the blog.

![light mode only](/images/yara/x){: .light  }
![dark mode only](/images/yara/ioc.PNG){: .dark   }

> **`Unique Strings`** can be anything, including a `typo error` in the code, as malware authors are often found in non-English speaking countries.
{: .prompt-info }

## How to extract artifacts from files ?

There are quite a few tools out there that can help to analyze the interesting artifacts in a file. Some of my favorite tools are listed below; however, use the one you are comfortable with. 

![light mode only](/images/yara/xx.PNG){: .light  }
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

