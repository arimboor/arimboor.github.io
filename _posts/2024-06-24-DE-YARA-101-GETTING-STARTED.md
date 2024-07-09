---
title: Part 1 - Getting started with YARA. 
description: Examples of text, typography, math equations, diagrams, flowcharts, pictures, videos, and more.
date: 2024-04-24 12:00:00 -500
categories: [Detection Engineering, Analyzing Windows Files using YARA rules]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/YARA_Series.png
---


I believe there's no need to introduce [**YARA**](https://github.com/VirusTotal/yara) to anyone working in the cybersecurity domain, but I'd still like to briefly cover some basics so that we're all on the same page.

> Does YARA support multithreading? Find out more.
{: .prompt-tip }


### Why is pattern matching still significant ? 

![Desktop View](/images/yara/yara-face0.jpg){:  width="672" height="289"  .w-50 .right} 
Traditional hash-based indicators, which rely on precise matches, frequently fall short against advanced attackers. A single modification to the code can render these indicators ineffective, evading signature-based detections. 

A simple tweak will allow threat actor to get around hash-based detection. Hash-based detection is only effective for identifying known malware samples; it cannot detect a new variant of prevalent malware.


![Desktop View](/images/yara/yara-face.gif){: width="672" height="289" .w-50 .right}
A simple tweak will allow threat actor to get around hash-based detection. Hash-based detection is only effective for identifying known malware samples; it cannot detect a new variant of prevalent malware.



### What are the key use cases ?


- `Threat Detection`{: .filepath}
- `Malware Classification`{: .filepath}
- `Threat Attribution`{: .filepath}


![light mode only](/images/yara/yara1-w.PNG){: .light .w-75  .rounded-10 w='2212' h='768' } 
![dark mode only](/images/yara/yara1.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }




### Who is using YARA nowadays ?

https://virustotal.github.io/yara/

![Desktop View](/images/yara/yara3.PNG){: width="972" height="589" }
_Full screen width and center alignment_



### Ways of using YARA Engine ?


### How is the logic written?

Written in `KEY` and `VALUE` pairs 

![light mode only](/images/yara/yara4-w.PNG){: .light .w-75  .rounded-10 w='2212' h='768' } 
![dark mode only](/images/yara/yara4.PNG){: .dark .w-75  .rounded-10 w='2212' h='768' }

```bash
rule My_Rule 

{
    meta: 
             author = "Jinto Antony" 
        strings: 
             $string = “scotland" ascii wide nocase 
             $regex = /abcd[x-z]/ 
             $hex = { 63 62 61} 
        condition: 
             $hex at 0 and ( $re or $str ) 
} 
```


<!-- chat gpt end -->

<!--

Even spyware developers have been observed using YARA rules to detect their own malware. This helps them identify when their malware is starting to get exposed or when one of their campaigns is under investigation.
 This discovery was made when the hacking team used it to monitor exposure or investigations into their campaigns before researchers were aware of them.


Since 2014 (~10 years)
Widely adapted 
Pattern matching for files 
Detection for IR and Threat Hunting 
Threat Intel & malware research -> classification & threat actor attribution 

threa intel and malware resaearch 


Prepare a square image (PNG, JPG, or SVG) with a size of 512x512 or more, and then go to the online tool [**Real Favicon Generator**](https://realfavicongenerator.net/) and click the button <kbd>Select your Favicon image</kbd> to upload your image file.

In the next step, the webpage will show all usage scenarios. You can keep the default options, scroll to the bottom of the page, and click the button <kbd>Generate your Favicons and HTML code</kbd> to generate the favicon.

And then copy the remaining image files (`.PNG`{: .filepath} and `.ICO`{: .filepath}) to cover the original files in the directory `assets/img/favicons/`{: .filepath} of your Jekyll site. If your Jekyll site doesn't have this directory yet, just create one.








Traditional hash-based indicators, which rely on precise matches, frequently fall short against advanced attackers.
Those who don’t know the HASH -> it’s a …. 
A single modification to the code can render these indicators ineffective, evading signature-based detections. 
A simple tweak will allow them to get around hash-based detection
Hash-based detection is only effective for identifying known malware samples; it cannot detect a new variant of prevalent malware.



Praesent maximus aliquam sapien. Sed vel neque in dolor pulvinar auctor. Maecenas pharetra, sem sit amet interdum posuere, tellus lacus eleifend magna, ac lobortis felis ipsum id sapien. Proin ornare rutrum metus, ac convallis diam volutpat sit amet. Phasellus volutpat, elit sit amet tincidunt mollis, felis mi scelerisque mauris, ut facilisis leo magna accumsan sapien. In rutrum vehicula nisl eget tempor. Nullam maximus ullamcorper libero non maximus. Integer ultricies velit id convallis varius. Praesent eu nisl eu urna finibus ultrices id nec ex. Mauris ac mattis quam. Fusce aliquam est nec sapien bibendum, vitae malesuada ligula condimentum.



Praesent maximus aliquam sapien. Sed vel neque in dolor pulvinar auctor. Maecenas pharetra, sem sit amet interdum posuere, tellus lacus eleifend magna, ac lobortis felis ipsum id sapien. Proin ornare rutrum metus, ac convallis diam volutpat sit amet. Phasellus volutpat, elit sit amet tincidunt mollis, felis mi scelerisque mauris, ut facilisis leo magna accumsan sapien. In rutrum vehicula nisl eget tempor. Nullam maximus ullamcorper libero non maximus. Integer ultricies velit id convallis varius. Praesent eu nisl eu urna finibus ultrices id nec ex. Mauris ac mattis quam. Fusce aliquam est nec sapien bibendum, vitae malesuada ligula condimentum.

{: data-toc-skip='' .mt-4 .mb-0 }

Quisque egestas convallis ipsum, ut sollicitudin risus tincidunt a. Maecenas interdum malesuada egestas. Duis consectetur porta risus, sit amet vulputate urna facilisis ac. Phasellus semper dui non purus ultrices sodales. Aliquam ante lorem, ornare a feugiat ac, finibus nec mauris. Vivamus ut tristique nisi. Sed vel leo vulputate, efficitur risus non, posuere mi. Nullam tincidunt bibendum rutrum. Proin commodo ornare sapien. Vivamus interdum diam sed sapien blandit, sit amet aliquam risus mattis. Nullam arcu turpis, mollis quis laoreet at, placerat id nibh. Suspendisse venenatis eros eros.




Quisque egestas convallis ipsum, ut sollicitudin risus tincidunt a. Maecenas interdum malesuada egestas. Duis consectetur porta risus, sit amet vulputate urna facilisis ac. Phasellus semper dui non purus ultrices sodales. Aliquam ante lorem, ornare a feugiat ac, finibus nec mauris. Vivamus ut tristique nisi. Sed vel leo vulputate, efficitur risus non, posuere mi. Nullam tincidunt bibendum rutrum. Proin commodo ornare sapien. Vivamus interdum diam sed sapien blandit, sit amet aliquam risus mattis. Nullam arcu turpis, mollis quis laoreet at, placerat id nibh. Suspendisse venenatis eros eros.










> An example showing the `tip` type prompt.
{: .prompt-tip }

> An example showing the `info` type prompt.
{: .prompt-info }

> An example showing the `warning` type prompt.
{: .prompt-warning }

> An example showing the `danger` type prompt.
{: .prompt-danger }








AI -> use of AI in ranssomeware may be post expolitaion profiles 




Yara looks for patterns, like specific words or codes, in files. It's pretty smart; 
you can even tell it to look for certain types of files, and it understands logic, like saying "if this, then that." 
* 
To kick things off, we'll use a simple sample program.


Now, let's break down what Yara is in simpler terms. 
These rules are written in a language that's easy for humans to understand. 
it understands logic, like saying "if this, then that." 

All rules begin with the keyword "Rule" followed by the name of the rule. After that, you open a curly brace, and everything that comes after it until the closing curly brace is part of the rule. It's a simple and straightforward markup.

There are three sections in a Yara rule. 

META
First is the "meta" section, where you add metadata. It follows a key-value format. 
The comment should include not only the op codes but also the disassembled instructions, which I think is a good approach. 
It allows us to understand the bytes without having to find the sample on the internet. 
Another important addition is including information about the sample, such as the MD5. This is useful to confirm rule matches and examine the code or sample it was based on.
most crucial field is "description." It tells you what the rule does. The second most important field is "date" because knowing when the rule was created helps understand its relevance.


The comment should include not only the op codes but also the disassembled instructions, which I think is a good approach. 

It allows us to understand the bytes without having to find the sample on the internet. 

Another important addition is including information about the sample, such as the MD5. This is useful to confirm rule matches and examine the code or sample it was based on.

Now, let's talk about how Yara rules are structured. All rules begin with the keyword "Rule" followed by the name of the rule. After that, you open a curly brace, and everything that comes after it until the closing curly brace is part of the rule. It's a simple and straightforward markup.

There are three sections in a Yara rule. First is the "meta" section, where you add metadata. It follows a key-value format. For example, you might have a key like "description" with a value that describes what the rule does. The "meta" section is your way of providing extra information about the rule.

Now, let's discuss the most important field in the "meta" section. Any guesses? It's not the first one mentioned. Ah, someone said "hash." That's a good one, but the most crucial field is "description." It tells you what the rule does. The second most important field is "date" because knowing when the rule was created helps understand its relevance. If a rule was written two months ago, it might differ from one written six years ago. Both could be valuable, but the creation date affects our assumptions about their effectiveness and usage.

-->


the archtictutre sdo simple that eay yo could see thiks on aa lots of securuty products 


use cases

dection 

IR : triage /memdups /etc 

Threat Inel : live hunt , sandbox , malw classifcation 

exutbale -> PE / DLL , ELF