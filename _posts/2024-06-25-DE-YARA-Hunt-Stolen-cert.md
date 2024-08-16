---
title: Part 4.1 - Hunting for files with Stolen code-signing Cert.
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-25 12:00:00 -500
categories: [Bytes of Insights - YARA for Incident Response & Malware Hunting, Threat hunting with YARA for Microsoft Windows Endpoints]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/yara_main.png
  
---

In software, one way to establish trust in a code is by signing it with a trusted code signing certificate. This practice involves cryptographically signing software to increase trust and confidence. The operating system verifies these signatures through the concept of a certificate chain.

Threat actors often use this technique to bypass security controls when infecting an endpoint. Since the binary is signed by a third-party trusted authority, Windows operating systems tend to consider it legitimate software. In recent years, we have witnessed high-profile breaches where malware binaries were signed by trusted authorities. 

Here are some headlines related to threat actors exploiting trust by signing code with stolen certificates.

![Desktop View](/images/yara/yara_cert_01.drawio.png)

> `Authenticode` is a Microsoft code-signing technology that identifies the publisher of Authenticode-signed software and verifies that the software has not been tampered.
{: .prompt-tip }

Here are some well-known certificates used for signing malware code. Refer to the project [**lolcerts**](https://github.com/WithSecureLabs/lolcerts) to find more information on such certificates.

Issuer | Serial | Status | Source | 
DigiCert [MicroStar(MSI)]| 0b:88:60:32:86:1d:95:53:c6:8f:80:33:13:a9:89:75 | revoked | leaked|
VeriSign [NVIDIA] | 43:bb:43:7d:60:98:66:28:6d:d8:39:e1:d0:03:09:f5 | revoked | leaked| 
VeriSign [NVIDIA] | 14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18 | revoked | leaked| 
Sectigo [Hangil IT Co] | 01:39:dd:e1:19:bb:32:0d:fb:9f:5d:ef:e3:f7:12:45 | revoked | 
DigiCert [AnyDesk] | 0d:bf:15:2d:ea:f0:b9:81:a8:a9:38:d5:3f:76:9d:b8 | revoked | leaked |
VeriSign [HackingTeam] | 0f:1b:43:48:4a:13:69:c8:30:38:dc:24:e7:77:8b:7d | expired | malicious |
LAMERA [dprk]| 87:9f:a9:42:f9:f0:97:b7:4f:d6:f7:da:bc:f1:74:5a | revoked| malicious |

To obtain more samples for analyzing and writing rules, you can use the following VirusTotal search tags as shown below:

- For example, you can search for a specific serial number and filter by timestamp.

```bash
fs:"2022-03-01T00:00:00+" ( signature:"43 bb 43 7d 60 98 66 28 6d d8 39 e1 d0 
 03 09 f5" OR signature:"14 78 1b c8 62 e8 dc 50 3a 55 93 46 f5 dc c5 18" )
```
- For example, you can search for a specific serial number and look for positive detections greater than 5.

```bash
signature:"0d bf 15 2d ea f0 b9 81 a8 a9 38 d5 3f 76 9d b8" p:5+
```



There are multiple ways that threat actors can obtain a code signing certificate, such as `stealing the certificate` from a legitimate organization through system compromise, `registering a front company` to present to the certificate signing authority as a genuine business, or `purchasing a stolen certificate` from the underground market.

### Writting Detction Rule

We can use YARA's `PE module` to write a detection rule that looks for a certificate serial number. The signature object is an array and we can loop through all the certificates in the PE header and look for the one we are interested in. The `timestamp is very important` to reduce false positives, as this is a valid certificate used to sign legitimate software. We typically determine the known time when the certificate was stolen and search only those files whose `compile time` is after that. Here is the rule snippet for the rule logic,

```bash
import "pe"

rule cert {
   ...............
   .................
   condition:
      uint16(0) == 0x5a4d and 
      pe.timestamp < 1640995200 and
      for any i in (0 .. pe.number_of_signatures) : 
      (pe.signatures[i].serial == "14:78:1b:c8:62:e8:dc:50:3a:55:93:46:f5:dc:c5:18" )            
    }
```

Here is one sample YARA rule to detect malware with [**stolen code signing certificates**](https://github.com/ditekshen/detection/blob/master/yara/indicator_knownbad_certs.yar) .

This YARA rule can also be used for `threat attribution`, as the same certificate may be used to sign other campaigns. However, this attribution is not always accurate, as the same certificate can be shared among different threat actor groups.

I’m linking an article here written by [**Trend Micro**](https://www.trendmicro.com/en_us/research/18/d/understanding-code-signing-abuse-in-malware-campaigns.html), which I found very insightful in the context of stolen certificates. Have a look, if you have time.


<!--

demoCertificate output from YARA 
demo to show process runnig with ston certifcate 
Pe.timestamp
create a single rule file with all the S/N

stolen certs
https://github.com/Rafiot/HackedTeamCerts
https://github.com/utoni/PastDSE/tree/main/certs

aws cert scnning. not sure what is teh UC here 
https://buckets.grayhatwarfare.com/files?extensions=pfx%2Cp12

how to use signtool to sign the code 
https://axelarator.github.io/posts/codesigningcerts/
https://github.com/secretsquirrel/SigThief

sample for demo 
https://cloud.google.com/blog/topics/threat-intelligence/hunting-attestation-signed-malware

genearl IR hutnig rules 
https://github.com/ditekshen/detection/tree/master/yara

How Certificate works on Windows (add video)

https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
https://posts.specterops.io/what-is-it-that-makes-a-microsoft-executable-a-microsoft-executable-b43ac612195e
https://posts.specterops.io/certified-pre-owned-d95910965cd2
https://specterops.io/wp-content/uploads/sites/3/2022/06/SpecterOps_Subverting_Trust_in_Windows.pdf
https://learn.microsoft.com/en-us/windows-hardware/drivers/install/authenticode


https://github.com/avast/authenticode-parser 
https://github.com/secretsquirrel/SigThief
https://captmeelo.com/redteam/maldev/2022/11/07/cloning-signing.html
https://axelarator.github.io/posts/codesigningcerts/
https://furia.cc/blogs/entry/12-cloning-a-code-signing-certificate-or-how-to-reduce-antivirus-detections-in-60-seconds/
https://github.com/Tylous/Limelighter

below kernel32.dll code signing demo can be added to the bog + ppt
https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
-->






