---
title: "Investigating CISCO Routers and Switches"
description: Historically, attackers targeted network devices for DoS, but now they exploit these devices like any other endpoints
date: 2025-01-25 12:00:00 -500
categories: [Responding to Incidents- A Field Guide]
tags: [Cisco]
pin: true
math: true
mermaid: true
image:
  path: /images/cisco/post.jpg
---

**Initial access**: Owning a router / switch device allows attackers to access data flows & launch further attacks on the infrastructure. This can be either by exploiting the vulnerabilities or by using valid credentials; however, in most cases, it was the stolen credentials that played out.

**Dumping the Config**: It's quite common in breaches for the threat actor to exfiltrate the device configuration in order to understand the network segments, access controls, NAT, identity configurations, and passwords for login, SNMP, etc.

**Lateral movement**: Moving from one compromised device to another within the network is a common approach. If the compromised organization is a telecommunications company or ISP, then the threat actor may go after the call records for the unencrypted calls.

### Investigation Playbook

✨This checklist can be handy when you're investigating a Cisco network device for any compromises. It helps you understand how a threat actor might exploit the native capabilities for their advantage.

![dark mode only](/images/cisco/checklist.JPG){: .dark  }


>The `Guest Shell` is a lightweight Linux container in Cisco IOS XE (not standard IOS) that allows users to run bash shell, scripts, or tools directly on the device.
{: .prompt-tip }

### Evidence of traffic sniffing.

Network devices like routers and switches are perfect targets for sneaking out data since the data flow through them, whether it's encrypted or not. Cisco devices have features like `Tpacap` or `Embedded Packet Capture` (EPC), which attackers often use to quietly monitor the traffic without messing with the network device.

You can check the device history or logs to see if attacker enabled and used features like EPC. Since these devices can run for years, like 2-3 years without rebooting, it's a good idea to check their memory by grabbing the `core dump`.

The command history for all commands entered through vty interfaces is stored in an internal buffer, and this command history buffer is included in core dump file generated. We can review the core dump to identify commands. Below is a similar command found in the Cisco core dump when the attacker tried to enable sniffing.

```text
coredumps/router-dxb_coredump.bin:monitor capture buffer%s%s%d 
coredumps/router-dxb_coredump.bin:monitor capture pointassociate%s%s 
coredumps/router-dxb_coredump.bin:monitor capture buffer%sfilter%sCapturepoint%sdoesnotexist 
coredumps/router-dxb_coredump.bin:monitor capture pointipv6cef%sall%s 
coredumps/router-dxb_coredump.bin:monitor capture pointipv6cef%spunt 
coredumps/router-dxb_coredump.bin:monitor capture pointipv6cef%sdrop 
coredumps/router-dxb_coredump.bin:monitor capture pointipv6cef%s%s%s 
coredumps/router-dxb_coredump.bin:monitor capture pointipv6process-switched%sfrom-us
```

### Cisco IOS Integrity Verification

Persistence is quite challenging on network devices compared to servers and endpoints. In most cases, attackers rely on memory-related tactics, techniques, and procedures (TTPs) or by adding privileged users to the appliance.

Another way attackers ensure persistence is by loading and running a backdoored IOS. By installing this malicious IOS, the threat actor makes sure there is always a persistence, even after rebooting the devices.

When investigating Cisco network devices, it's important to verify the `integrity` of the IOS running on the appliance. Cisco provides a few options to verify the authenticity of the IOS running in the memory and stored on the flash. Here are some of the checks I normally do to make sure the running IOS version is genuine. You can follow a Cisco link [**here**](https://sec.cloudapps.cisco.com/security/center/resources/integrity_assurance.html), which provides more detailed checks.

You can use these methods to identify modifications to Cisco IOS image files and run-time memory.

There are mainly three types of hash values it provides when running the command: `Computed` Hash, `Embedded` Hash, and `CCO` Hash.

```bash
verify flash0:c2900-universalk9-mz.SPA.151-43.M3.bin
```

In simple terms, the `Embedded Hash` is something Cisco computes and stores during the image build process. This can be used to verify the integrity of the IOS file, but not the IOS running in memory. 

The `Computed Hash` is something calculated when we issue the above command for the running IOS image. This value **should be the same** as the Embedded Hash; otherwise, the image may have been altered for backdoors.

Finally `CCO Hash`, on the other hand, is the hash of the whole image file. This can be shared with Cisco support to validate the integrity of the IOS.

```text
Computed Hash   SHA2: 8785156FB7B6DFC8FE0F08AC21AA8974
                      9ARE428A7BA83D19A14ABAC5C342B228
                      T789147163636DC5AB10CD3DDC4C2345
                      ABAE6B01105F5356C9F115156F26106A
                      
Embedded Hash   SHA2: 8785156FB7B6DFC8FE0F08AC21AA8974
                      9ARE428A7BA83D19A14ABAC5C342B228
                      T789147163636DC5AB10CD3DDC4C2345
                      ABAE6B01105F5356C9F115156F26106A
                      
CCO Hash        MD5 : AB4BD5287A236586ABD146F58E353456
Digital signature successfully verified in file flash0:c2900-universalk9-mz.SPA.151-43.M3.bin
```

Another feature Cisco provides is to verify integrity using the below commands; there are two methods: one to check the file stored on the appliance, and the other to check the running IOS.

```bash
show software authenticity file flash0:c2900-universalk9-mz.SPA.151-43.M3.bin
```
here is the output 

```text
File Name                     : flash0:c2900-universalk9-mz.SPA.151-43.M3.bin
Image type                    : Production
    Signer Information
        Common Name           : CiscoSystems
        Organization Unit     : C2900
        Organization Name     : CiscoSystems
    Certificate Serial Number : 3F693684
    Hash Algorithm            : SHA512
    Signature Algorithm       : 2048-bit RSA
    Key Version               : A
```

And the below is for what is currently running on the device.

```bash
show software authenticity running
```

here is the output 

```text
SYSTEM IMAGE
------------
Image type                    : Production
    Signer Information
        Common Name           : CiscoSystems
        Organization Unit     : C2900
        Organization Name     : CiscoSystems
    Certificate Serial Number : 3F693684
    Hash Algorithm            : SHA512
    Signature Algorithm       : 2048-bit RSA
    Key Version               : A

    Verifier Information
        Verifier Name         : ROMMON 1
        Verifier Version      : System Bootstrap, Version 15.0(1r)M15, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
```


**Side Notes**

Below are some basic tools I have used against the Cisco `core dump`, which were quite effective in identifying attacker behaviors in some of the cases I handled.

```bash
bulk_extractor -o out core_dump.bin

bulk_extractor -o out -x all -e net core_dump.bin # extarct pcap file

strings core_dump.bin | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > ips.txt

grep -R -a -F "monitor capture" coredumps/ > monitor.txt
```

> If a threat actor gets their hands on compromised credentials for Cisco devices, typical security features like safe coding libraries, ASLR, digitally signed software, and Cisco Secure Boot won't really help.
{: .prompt-warning }

If you're dealing with an incident involving Cisco network devices, definitely check out the Cisco documentation and scripts. Trust me, they'll be a huge help.

- [Cisco IOS Software Forensic Data Collection Procedures](https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/ios_forensic_investigation.html)
- [Cisco IOS XE Software Forensic Data Collection Procedures](https://sec.cloudapps.cisco.com/security/center/resources/forensic_guides/iosxe_forensic_guide.html)
- [Cisco IOS XR Software Forensic Data Collection Script](https://sec.cloudapps.cisco.com/security/center/resources/ios_xr_forensic_script.html)











