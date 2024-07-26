---
title: Part 4 - YARA Rule Engineering & Modules for Windows Files.
description: Examples of text, typography, math equations, diagrams, flowcharts, pictures, videos, and more.
date: 2024-04-25 12:00:00 -500
categories: [Detection Engineering, Analyzing Windows PE Files using YARA rules]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/wallpaper_chik.jpg
  
---

<!-- PROD -->

## Approach

hhex 
https://www.youtube.com/watch?v=jHz8fD9TqZw&ab_channel=InsaneCyber
https://www.youtube.com/watch?v=VljT6UytBg8&ab_channel=CyberD0M

![light mode only](/images/yara/xxs.PNG){: .light  }
![dark mode only](/images/yara/approach.PNG){: .dark   }


## What are the building blocks

 
hex byte 
https://www.malwarebytes.com/blog/news/2013/10/using-yara-to-attribute-malware


### Building rules :  define patterns 

#### Modifiers 

**Keyword**	|**String Types**|	**Notes**|
nocase	|Text, Regex	| Ignore case	
wide	|Text, Regex	|Emulate UTF16 by interleaving null (0x00) characters
ascii	|Text, Regex	|match ASCII characters
xor	| Text	| XOR text string with single byte keys
base64	|Text	|Convert to 3 base64 encoded strings	
base64wide	|Text	|Convert to 3 base64 encoded strings, then interleaving null characters
fullword	|Text, Regex	|Match is not preceded or followed by an alphanumeric character	






private |	Hex, Text, Regex|	Match never included in output

hex patterns 

on raw bytes

nible
jump, 
groups

if anythinf doent make senes efor ascisi make it hex



wildcards | { 6D 81 6C **`??`** **`??`** 72 65 }
jumps | { 6D 81 6C **`[1-3]`** 65 }
alternatives | { **`(6D | 7D)`** 61 6C 77 61 72 65 }


### Building rules :  Operators / Loops

### Building rules : define conditions

### Building rules :  modules 

Modules have functions which can be used when writing a YARA rule. They often do the heavy lifting so that we can write less code when developing rules. Consider it as modules we import in programming languages such as Python in order to reuse existing code to achieve something. This will ease our work.

![light mode only](/images/yara/xxs.PNG){: .light  }
![dark mode only](/images/yara/modules.PNG){: .dark   }

Here is the link to all available modules. Have a look before writing your next YARA rule; there may be something already there.

https://yara.readthedocs.io/en/latest/modules.html

There is one caveat, though. The modules are highly dependent on the YARA version, hence it is important to check which YARA version is running on the target application. If the target application is running with a lower YARA version than the one you tested the rules with, then there may be a chance that it won't work. This is one reason people often complain that the `rules work perfectly fine in the test environment but not in production`. Also, note that some of the tools did not implement all the YARA features into their tech stack due to various performance reasons. Read the documentation of the respective tech stack before writing the rules and include only the modules supported by the target tool


#### PE Module 

The PE module exposes most of the fields present in a Microsoft Windows  PE file format header. here are some of the commonly used functions when writting rules related to .exe and .dll ,

pe.timestamp | pe.signatures.*


#### Math Module 

The Math module helps to calculate certain values from portions of the file. here are some of the commonly used functions when writting rules,

math.entropy

#### Console Module 

The console module helps the analysts in writing and debugging rules by logging information during execution, such as PE header details.

I'll primarily use this module for debugging rules or for file analysis itself. For instructions on utilizing this module for file analysis, please refer to Part 2 of the documentation

#### VT Module 


## Global and Private Rules


<!-- PROD End -->

https://engineering.avast.io/know-your-yara-rules-series-5-everything-you-need-to-know-about-regular-expressions-in-yara/


https://github.com/Neo23x0/signature-base/blob/master/yara/vuln_proxynotshell_cve_2022_41040.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/vuln_moveit_0day_jun23.yar

keepass
https://github.com/Neo23x0/signature-base/blob/master/yara/vuln_keepass_brute_forcible.yar

https://github.com/Neo23x0/signature-base/blob/master/yara/vul_confluence_questions_plugin_cve_2022_26138.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/vul_cve_2020_0688.yar

webshell
https://github.com/Neo23x0/signature-base/blob/master/yara/thor-webshells.yar

hacktool
https://github.com/Neo23x0/signature-base/blob/master/yara/thor-hacktools.yar

## IOC

strings:
      $xip1 = "98.176.196.89" ascii fullword 
      $xip2 = "68.235.178.32" ascii fullword
      $xip3 = "208.113.35.58" ascii fullword
      $xip4 = "144.34.179.162" ascii fullword
      $xip5 = "97.77.97.58" ascii fullword

https://github.com/Neo23x0/signature-base/blob/master/yara/apt_stuxnet.yar
## pdb

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

## 
-->




<!--
CABBAGEE 
FACEDEAF
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_hizor_rat.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/apt_muddywater.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/mal_ducktail_compromised_certs_jun23.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/log_teamviewer_keyboard_layouts.yar
https://www.binarydefense.com/resources/blog/creating-yara-rules-based-on-code/
https://github.com/Neo23x0/signature-base/blob/master/yara/generic_anomalies.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/general_officemacros.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/general_cloaking.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_webshells.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_suspicious_strings.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_ps_jab.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_office_dropper.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_recon_indicators.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_rats_malwareconfig.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_powershell_susp.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_powershell_invocation.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_phish_attachments.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_onenote_phish.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_mal_scripts.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_mal_link.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_invoke_thehash.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_impacket_tools.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_imphash_detection.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_icon_anomalies.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_hunting_susp_rar.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_hta_anomalies.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_google_anomaly.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_fireeye_redteam_tools.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_file_anomalies.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_excel_auto_open_evasion.yar
-->

https://www.linkedin.com/pulse/yara-rules-assembly-emeka-agu/


webshell
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_cn_webshells.yar

CS
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_cobaltstrike_by_avast.yar
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_cobaltstrike.yar


logic to explin the hex 
https://github.com/Neo23x0/signature-base/blob/master/yara/gen_gcti_cobaltstrike.yar

{CA BB AG EE}
   $export = {55 8B EC 83 EC 50 (3A|66 3B) ?? 74}
        $wind = {(66 3B|3A) ?? 74 [1-14] BB 69 04 00 00 53 E8 [5-7] 74}
little edian 
ecoding formasr - file or network data 
 "Little-Endian" and "Big-Endian", refers to the byte order in which data is stored


 wanncry - for classifcation

 https://github.com/Neo23x0/signature-base/blob/master/yara/crime_wannacry.yar


<!-- 
### What to avoid ?
rule SUSP_TH_APT_UNC4736_TradingTech_Cert_Apr23_1 {
   meta:
      description = "Threat hunting rule that detects samples signed with the compromised Trading Technologies certificate after May 2022"
      author = "Florian Roth"
      reference = "https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise"
      date = "2023-04-20"
      score = 65
      id = "9a05fba9-9466-5b69-9207-27ad01d6eb8b"
   strings:
      $s1 = { 00 85 38 A6 C5 01 8F 50 FC } /* serial number */
      $s2 = "Go Daddy Secure Certificate Authority - G2" /* CA */
      $s3 = "Trading Technologies International, Inc"
   condition:
      pe.timestamp > 1651363200 /* Sunday, May 1, 2022 12:00:00 AM */
      and all of them
}

rule SUSP_ZIP_NtdsDIT : T1003_003 {
   meta:
      description = "Detects ntds.dit files in ZIP archives that could be a left over of administrative activity or traces of data exfiltration"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      reference = "https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/"
      date = "2020-08-10"
      id = "131ed73d-bb34-5ff6-b145-f95e4469d7f9"
   strings:
      $s1 = "ntds.dit" ascii 
   condition:
      uint16(0) == 0x4b50 and
      $s1 in (0..256)
}

rule SUSP_RAR_NtdsDIT {
   meta:
      description = "Detects suspicious RAR file that contains ntds.dit or SAM export"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
      date = "2019-12-16"
      modified = "2022-11-15" // only synced the name with our internal rule
      score = 70
      id = "da9e160f-3213-5027-bb0f-bf80ab3d5318"
   strings:
      $x1 = "ntds.dit0" ascii fullword
      $x2 = { 0? 53 41 4D 30 01 00 03 }  // SAM0
      $x3 = { 0? 73 61 6D 30 01 00 03 }  // sam0
   condition:
      uint32(0) == 0x21726152 // Rar!
      and 1 of them
}


rule Suspicious_Size_chrome_exe {
    meta:
      description = "Detects uncommon file size of chrome.exe"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      nodeepdive = 1
      date = "2015-12-21"
      modified = "2022-09-15"
      noarchivescan = 1
      id = "f164394a-5c02-5056-aceb-044ee118578d"
    strings:
      $fp1 = "HP Sure Click Chromium Launcher" wide
      $fp2 = "BrChromiumLauncher.exe" wide fullword
    condition:
      uint16(0) == 0x5a4d
      and filename == "chrome.exe"
      and ( filesize < 500KB or filesize > 5000KB )
      and not 1 of ($fp*)
}

List of Magic Numbers that can be used for Yara Rules








https://blog.securitybreak.io/100daysofyara-challenge-04c966eab1ae


```bash
for any i in (0 .. pe.number_of_sections) : 
    (( pe.sections[i].name == "SE" ))

OR 
            for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains "UPX"
            )
        )
```


metedata 
imprts
stoings 
condtions 

string mosifiers 


yoiu can store 1000 rules ina asigle rule 


## strings are the content

text , regex, hex 


modidier 


defauklt ascii & case senstive 

nocase = case insenetive 

wide -> UTF16 -> null spaces after each latetr 

fullword -> delimeyed by non-alphanumeric char = +jinto+ not jintoA

base64 & base64wide (may be powersell scroiopt)

xor = single byte xor
alkso provide options with XOR with keys or XOR with set of keys 

xor[0x3c] -> signe key

xor[ox01 0xff] -> rang of keys


demo on extractinf using stongs 

findout a sample for sting extarction 


regex basic 
-----------


/  /i = case in sensetive 

concept of atom and serching 



find out some interestinf ara rukes with regex and add it 

use cybeehf to wite cyberchef 


hex
---




## modules

entropy
pe

yaya -D


## condtions

loop

contins , i contins, startwrih, wndwideth, macthces 

for all xxx in xx


expaling console.hex to explain the MZ header  

pe.timestamp vs pe.export_timestamp 

read the blog and find out any interesting sampoles 

not looking for ascii sting : string or stings.exe

utf16 = wide 

write one rule and optimze it known goodwares 

first verty specfic and another one more looose 

just find out the pe infomation on the file 

```bash
import "pe"
    rule PE_Debug_Rule 
    {
        conditon:
            true
    }
```

too many resousrce in pe head is abnormal ? find 
export dll is normal ?


what is TTP rule 

write rule from TTP blog to demo the threal intel and malware classification 

goodwares 

dowanload windows iso an unzip with 7 ziop thsts it 

create windows 11 and 10 on inux and scan using velociraptor 




hunt based news -> certificate stlen 





typoical initial entry -> exel -> vba + dowper > infection 

next stage 

powershell 


next stage 

exe, dll, 
elf

mach-o




windows ecurtaia -> exe/ dll / .net

linux
elf

mac
machO
DMG

slide for workflow for malware infection & data leakge (hunt for confidential document)

vlociraprt -> how to add more than one path on uara.glob 



take a very famoyus sample like wanncry and find out w how ro do classifiction 

how to do a stings analysis on multipl file ? any script ot tools available ? ceck 







what ware exports
-----------------
dll ( export the funcytion )
exe  ( mostly oiport function) & the exoirt is very linitef
pe.export_timestip = time of he export dietctory was created on the ee , its in the epich : can find timestobing ?


pe.nuber_of_exports 
pe.export_deatils
pe.export_dll



Code Signing 
============

what is it

image from internet 

also knows as in windows =  Authtocode 

for Trust 


how to get it


glomming -> insert the code insie 

obtin cert user false complamny 

Microst partner Develipment center -?

stonlen certificate 

pe.signatures. * chgeck those 


list of timestimaps in yara to extarct careta losy 

how a normal code signing certi look like 


compoemse small compies andn get the certificate 

Hermetica digitl ltd

if not findiang a good sining smple on VT then downlaod samole and search for signed malwares 



https://malpedia.caad.fkie.fraunhofer.de/actor/charming_kitten


? delphi malawre how much ? is it common #


threat hunting -> debv using TTP

IR -> IOC 

Malware - classification 

engkigh : the file sixe looks absert 


entropy

```bash
import "console"
import "math"


rule a 
{

condtion:
for any/all section/ resousrces in pe.sections: / pe.resources # explain the differentv 
(
console.log(mayh.entrpy(offset, logth, size))

)


}

```

test in velociraprt the console.log options 


group the rules based on groeups 



global - > filtering rules : preconstions 
private  -> 


expmale : pe exucaltion < 100 or erbssrll on linux 


how to use this IR traiaging 



https://github.com/malpedia/signator-rules
https://github.com/mikesxrs/Open-Source-YARA-rules
https://github.com/reversinglabs/reversinglabs-yara-rules/tree/develop/yara
https://github.com/chronicle/GCTI/tree/main/YARA
https://github.com/Neo23x0/signature-base/tree/master
https://github.com/Yara-Rules/rules
https://github.com/mthcht/ThreatHunting-Keywords-yara-rules
https://github.com/CybercentreCanada/CCCS-Yara
https://github.com/filescanio/fsYara/tree/master
https://github.com/The-DFIR-Report/Yara-Rules
https://github.com/0xZainRaza/Secure-File-Scan
https://github.com/radareorg/r2yara
https://github.com/YARAHQ/yara-forge


-->


