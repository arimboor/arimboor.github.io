---
title: Part 4.4 - Hunting for Packed PE executables.
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-23 12:00:00 -500
categories: [Detection Engineering - YARA and its Ecosystems, Part 1 - Introduction to YARA and Writing detection rules]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/yara_main.png
  
---



 <!-- add video for the packed exec-->

The following example illustrates various approaches to detecting Windows packed executables.

- In this example, the rule is looking for specific keywords a.k.a signatures, in a PE sections. By default, some packers add certain keywords to the PE headers to include their signature. This can be used as a detection method when writing a rule. Please note that adding such keywords to the PE header is optional, and someone could deliberately add keywords to deceive malware analysts.

```bash
import "pe"
rule basedOnString
{
    condition:
        for any i in (0 .. pe.number_of_sections): 
            (pe.sections[i].name == ".aspack")
}
```

- In the example, the rule is looking for file entries.

```bash
import "math"
rule basedOnEntropy {
  condition:
    math.entropy (0, filesize) > 7
}
```

- Instead of calculating the entropy for the entire file, which may not always be useful, the example calculates the entropy for each section. In general, an entropy value above 7.5 is something worth analyzing.

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


