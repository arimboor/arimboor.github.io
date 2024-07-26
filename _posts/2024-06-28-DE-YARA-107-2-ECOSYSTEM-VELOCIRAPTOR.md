---
title: Part 7.2 - Yara Ecosysyem . Velociraptor
description: Examples of text, typography, math equations, diagrams, flowcharts, pictures, videos, and more.
date: 2024-04-28 12:00:00 -500
categories: [Detection Engineering, Analyzing Windows Files using YARA rules]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/wallpaper_chik.jpg
---







<!-- PROD -->


- Generic.Detection.Yara.Glob
- Linux.Detection.Yara.Glob
- MacOS.Detection.Yara.Glob
- Windows.Detection.Yara.Glob

- Linux.Detection.Yara.Process
- MacOS.Detection.Yara.Process
- Windows.Detection.Yara.Process
- Windows.System.VAD


- Windows.Forensics.FilenameSearch
- Windows.Search.Yara
- Windows.Detection.Yara.NTFS



Type 1 


- Generic.Detection.Yara.Zip
- Windows.Detection.Yara.Device
- Windows.Detection.Yara.PhysicalMemory (load the `winpmem` driver, then yara scan the physical memory and remove the driver. NOTE: This artifact is experimental and can crash the system!)
- Windows.Detection.Yara.UEFI



Type 3 
- Generic.Applications.Office.Keywords
- Windows.Carving.CobaltStrike
- Windows.Detection.TemplateInjection
- Windows.Forensics.SolarwindsSunburst

Type 3

- Generic.Detection.Yara.SSH
- Windows.Scanner.Yara.Parsed  - Exchange.Windows.Scanner.Yara.Parsed
- Windows.Detection.Yara.UEFI
- Windows.Detection.IdatLoader
- Windows.Carving.Qakbot
- Windows.Detection.BruteRatel
- Windows.Detection.USBYara
- Windows.Carving.SquirrelWaffle
- Detection.Application.CursedChrome


PathGlob
SizeMax
SizeMin
UploadHits
DateAfter
DateBefore
NumberOfHits
nameRegex
AlsoUpload

ContextBytes
NTFS_CACHE_TIME
YaraUrl
YaraRule
TargetGlob
ZipFilenameRegex
MaxRecursions
EarliestSILastChanged
LatestSILastChanged
EarliestFNCreation
LatestFNCreation


<!-- PROD END -->



prpcess tracker - kep it for some time even its existed 



artifact is sort of like a vql program Philosoraptor query language program so it automates a lot of the you know the manual stuff so in this case what I wanted to do is I

e usn journal now as you know

the usn uh is a is a journal in a file system that keeps track of file system

activity and in this case what we want to do is we want to find any kind of evidence of this particular file name to

be created and it sort of looks like PS key Dash and then there's the host name and then it's a DOT key you know at the

hunt 
monir
standalone connection 


how to build a VQL for standalone colector 

You can supply a compiled yara rule as produced by the yarac program. This is not recommended because it is not portable - the rule must have been compiled with the exact same version of Yara that is embedded in Velociraptor (Currently 4.5.0). Compiled rules are generally larger too than the plain text rules.

By default only the first 100mb of the file are scanned and scanning stops after one hit is found.

Compatibility with yara rules.
The YARA engine supports a number of directives that bring in unreasonably sized dependencies. Velociraptor’s Yara integration disables directive importing dependencies such as openssl and libmagic. This means that some rule conditions do not work (for example pe.number_of_signatures). Other condition are still supported (e.g. pe.imphash()). You can usually find equivalents to the Yara plugins in VQL plugins so rules can be rewritten to avoid this limitation.

If you have a large number of rules, you may use the yara-tools repository https://github.com/Velocidex/yara-tools to clean up the rules and verify that they will work with Velociraptor’s yara engine. The tool will automatically remove rules that are incompatible with Velociraptor and reduce the size of the rules by removing metadata and extra fluff.

YARA is a powerful keyword scanner that allows to search unstructured binary data based on user provided rules. YARA is optimized to scan for many rules simultaneously, making is an excellent choice for detecting suspicious binaries using common patterns.

Velociraptor supports YARA scanning of bulk data (via accessors) and memory using the yara() and proc_yara() plugins.

The yara() VQL plugin can accept an optional accessor parameter. If the accessor is specified, the plugin will read chunks of data from the accessor and apply the YARA rules on the string in memory. This allows you to apply YARA rules on any data that is available via an accessor including raw strings (using the data accessor), registry values (using the registry accessor) or NTFS parsed data (using the ntfs accessor) for example.

While this is convenient, it means that rules that examine the entire file will not work as expected. For example, the YARA pe module looks at the PE header, but when the file is read in chunks, only the first chunk contains the PE header. Similarly YARA rules that contain an expression checking a file offset will not work because the rules are applied to buffers in memory.

When an accessor is not specified, the yara() plugin assumes the filename refers to a filesystem path, and simply allows the YARA library to scan the file as is. The YARA library uses mmap() to map the entire file into memory and can therefore optimize the scan across the entire file.

It is therefore much faster to not specify an accessor to the yara() plugin if you just need to scan files on disk.

Example: drive by download
You suspect a user was compromised by a drive by download (i.e. they clicked and downloaded malware delivered by mail, ads etc).

You think the user used the Edge browser but for this example, assume you have no idea of the internal structure of the browser cache/history etc. Write an artifact to extract potential URLs from the Edge browser directory.

```bash
LET YaraRule = '''
rule URL {
  strings: $a = /https?:\\/\\/[a-z0-9\\/+&#:\\?.-]+/i
  condition: any of them
}
'''

SELECT * FROM foreach(
row={
   SELECT FullPath FROM glob(globs='''C:\Users\*\AppData\Local\Microsoft\Edge\**''')
}, query={
   SELECT str(str=Strings.Data) AS Hit,
          String.Offset AS Offset,
          FileName
   FROM yara(files=FullPath, rules=YaraRule)
})
```

Try to collect additional context around the hits to eliminate false positives. You can use other plugins to help verify other aspects of each hit before reporting it, thereby eliminating false positives.

exaple

Uploading files
One of the unique capabilities of Velociraptor is uploading file content from the endpoint. While the actual mechanism of uploading the file to the server is abstracted away, triggering a file upload from VQL is a simple matter of calling the upload() function. This makes it trivial to upload files based on any criteria of the query.

The upload() function simply requires an accessor and a filename to read the file out, and the file is uploaded to the server automatically. Optionally the function may also take a name parameter which renames the file as sent to the server.

Example: Collect all executables in users’ home directory
This is a common use of combining a glob() plugin with an upload() function:

```bash
SELECT upload(file=FullPath) AS Upload
FROM glob(globs='''C:\Users\*\Downloads\*''')
WHERE NOT IsDir

```
file.finder + yara 

Yara scanning is relatively expensive since we need to read data from disk! consider more targeted glob expressions to limit the number of disk reads Velociraptor will need to do to evaluate the query. If you find you do need to scan a lot of data, consider specifying client side throttling when launching the collection or hunt (using the Ops/Sec mechanism) - usually YARA scanning is not time critical.

<!--

https://docs.velociraptor.app/vql_reference/plugin/yara/
https://docs.velociraptor.app/docs/forensic/searching/
https://github.com/Velocidex/yara-tools
https://docs.velociraptor.app/exchange/artifacts/pages/yara.uefi/
https://blog.reconinfosec.com/securing-your-velociraptor-deployment
https://www.velocidex.com/resources/training_2020_public.pdf
https://dfrws.org/wp-content/uploads/2021/03/DFRWS-EU-2021-Velociraptor-Digging-Deeper.pdf
https://www.rapid7.com/blog/post/2022/02/03/velociraptor-version-0-6-3-dig-deeper-with-more-speed-and-scalability/
https://samsclass.info/152/proj/IR372.htm
https://www.rapid7.com/blog/post/2024/04/30/velociraptor-0-7-2-release-digging-deeper-than-ever-with-ewf-support-dynamic-dns-and-more/
https://www.velocidex.com/resources/crikeycon_2019.pdf
https://s3.amazonaws.com/resources.osdfcon.org/presentations/2021/Mike_Cohen_Velociraptor_OSDFCon_2021.pdf
https://mgreen27.notion.site/mgreen27/Velociraptor-DEATHcon-2023-25d9760af2ac4b419ff39c2a48f7bb2c
https://mgreen27.notion.site/Lab-VQL-yara-performance-535bfcce8ab04192b90f5f72739db7b6
-->

https://www.youtube.com/watch?v=M7bMfdmWR7A&ab_channel=JohnHammond
https://www.youtube.com/watch?v=ibl4-MzW-KI&ab_channel=VelocidexEnterprises
https://www.youtube.com/watch?v=V268q1nKn1c&ab_channel=SamBowne
https://www.youtube.com/watch?v=OcA1ihRttSE&ab_channel=MattGreen


Senarious

Live hunting 
Depoyed for IR case 

https://docs.velociraptor.app/docs/offline_triage/

use case 

https://sec-consult.com/blog/detail/bumblebee-hunting-with-a-velociraptor/
https://www.rapid7.com/blog/post/2024/02/29/how-to-hunt-for-uefi-malware-using-velociraptor/
https://www.bizarrebinaries.com/blog/velociraptor-hunting-for-moveit-iocs
https://blog.ecapuano.com/p/live-incident-response-with-velociraptor
https://www.nextron-systems.com/2023/11/03/integration-of-thor-in-velociraptor-supercharging-digital-forensics-and-incident-response/
https://docs.velociraptor.app/exchange/artifacts/pages/ws_ftp/
https://www.optiv.com/insights/source-zero/blog/selective-yara-scanning-whats-your-type
https://infosecwriteups.com/intro-to-malware-detection-using-yara-eacab8373cf4
also yara scan using somple powershell using pS Remoting 
https://github.com/yuankong666/Ultimate-RAT-Collection/tree/main/KjW0rm


high entropy - We hunted for instances of comadmin.dat, using both the Windows.Search.FileFinder and the Generic.Detection.Yara.Glob artifacts. The YARA rule is required to identify instances of this file presenting high-entropy.

Velociraptor provides an artifact that allows you to run YARA rules in memory, however do use this at your own discretion and based on your network stability, reliability and bandwidth as the document referencing this artifact actually warns users that the feature is experimental and can end up crashing your system!

windows.dection.yara.phisciamemeory


























