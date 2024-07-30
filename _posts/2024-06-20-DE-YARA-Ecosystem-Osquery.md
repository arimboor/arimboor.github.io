---
title: Part 5.1 - Yara Ecosysyem . OSQuery
description: Detection Engineering Using YARA Rules for Windows PE Files.
date: 2024-04-20 12:00:00 -500
categories: [Detection Engineering, Bytes of Insights - YARA for Incident Response & Malware Hunting]
tags: [Yara]
pin: true
math: true
mermaid: true
image:
  path: /images/wallpaper_chik.jpg
---


<!-- PROD -->

OSQuery does not have any native capability to monitor file changes; instead, it leverages the underlying OS subsystem to keep track of the file changes. As you know, file change monitoring, also known as file integrity monitoring, is quite expensive from a CPU and memory perspective and should be enabled for only critical file and folder locations. Below are some of the common locations where threat actors drop files during the initial compromise.

> File monitoring uses the `inotify` subsystem on Linux, `FSEvents` on macOS, and `ntfs_journal_events` on Windows.
{: .prompt-tip }

On Linux 

```text
/usr/bin/*
/usr/sbin/*
/root/.ssh/*
/home/%/.ssh/*
/apache/web/*
```

On Windows 

```text
C:/inetpub/wwwroot/*
User Profiles 
```
In OSQuery, we accomplish this through the `osquery.conf` file. The .conf file helps specify which files and folders are important for file integrity monitoring. Once any changes are detected in those locations, a YARA scan is initiated with a specific set of rules.


Refer to the link to understand [**known issues**](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/) when using the underlying OS subsystem for file integrity monitoring.



There are two YARA tables in osquery. The first table, called `yara_events`, utilizes osquery's Events framework to monitor filesystem changes and executes YARA when a file change event occurs. The second table, named `yara`, is used for performing an on-demand YARA scan.

The below example demonstrates running YARA scans against specific files or folders on demand. One typical use case is to scan a particular location based on known IOCs during a threat hunting exercise or when responding to an incident.

```sql
select * from yara where path = '/tmp/c99shell.php' and sigfile = '/etc/osquery/webshell.sig';
select * from yara where path LIKE '/tmp/%' and sigfile = '/etc/osquery/webshell.sig';

+--------------+----------------------------+
| target_path  | matches                    |
+--------------+----------------------------+
| /tmp/529.php | WebShell_php_webshells_529 |
| /tmp/529.php | WebShell_php_webshells_529 |
+--------------+----------------------------+

 select target_path, matches,time, strings from yara_events;
```
The below example illustrates viewing the output of a YARA scan triggered by file integrity monitoring, meaning whenever a file is created or modified in a particular location. One typical use case is monitoring the public-facing web server location to check for newly created files, for example, a malicious web shell dropped by the threat actor. Refer to the section titled <kbd>Configuring osquery for file integrity monitoring</kbd> for more details on how to implement this using OSquery and YARA"

```sql
select target_path, matches,time, strings from yara_events;
```

![light mode only](/images/yara/events.PNG){: .light .w-75 .rounded-10 w='1212' h='668' }
![dark mode only](/images/yara/events.PNG){: .dark .w-75  .rounded-10 w='1212' h='668' }

Similarly, the `process_events` table records all running process details and can execute YARA against the files stored on disk corresponding to the running processes.


<!-- how to scan full memeory -->


> Osquery uses Pubsub Framework for process tracking that works with the `BPF` or `Audit` or `OpenBSM ` etc to catpure the events.
{: .prompt-tip }


```sql
osquery> select distinct path from process_events;
+--------------------+
| path               |
+--------------------+
| /usr/bin/dash      |
| /usr/bin/run-parts |
+--------------------+
```
```sql
select * from yara where path in (select distinct path from process_events) \
        AND sigfile = '/etc/osquery/webshell.sig';
```






```sql
osquery> select distinct path from processes;

select path, name from processes group by path;


+------------------------------------------+
| path                                     |
+------------------------------------------+
| /usr/lib/systemd/systemd                 |
|                                          |
| /usr/sbin/sshd                           |
| /usr/lib/openssh/sftp-server             |
| /usr/bin/bash                            |
| /usr/bin/sudo                            |
| /usr/bin/tail                            |
| /usr/lib/upower/upowerd                  |
| /opt/osquery/bin/osqueryd                |
| /usr/lib/systemd/systemd-journald        |
| /usr/lib/systemd/systemd-udevd           |
| /usr/sbin/multipathd                     |
| /usr/lib/systemd/systemd-timesyncd       |
| /usr/bin/VGAuthService                   |
| /usr/bin/vmtoolsd                        |
| /usr/lib/systemd/systemd-networkd        |
| /usr/lib/systemd/systemd-resolved        |
| /usr/lib/accountsservice/accounts-daemon |
| /usr/sbin/cron                           |
| /usr/bin/dbus-daemon                     |
| /usr/sbin/irqbalance                     |
| /usr/bin/python3.8                       |
| /usr/lib/policykit-1/polkitd             |
| /usr/sbin/rsyslogd                       |
| /usr/lib/snapd/snapd                     |
| /usr/lib/systemd/systemd-logind          |
| /usr/lib/udisks2/udisksd                 |
| /usr/sbin/atd                            |
| /usr/sbin/agetty                         |
| /usr/sbin/ModemManager                   |
| /usr/bin/redis-check-rdb                 |
| /usr/sbin/mysqld                         |
+------------------------------------------+
```


```sql
select * from yara where path in (select distinct path from processes) \
          AND sigfile = '/etc/osquery/webshell.sig';
```



## Configuring osquery for file integrity monitoring 

```bash
{
  // Description of the YARA feature.
  "yara": {
    "signatures": {
      // Each key is an arbitrary group name to give the signatures listed
      "sig_group_1": [ "/Users/wxs/sigs/foo.yar", "/Users/wxs/sigs/bar.yar" ],
      "sig_group_2": [ "/Users/wxs/sigs/baz.yar" ]
    },
    "file_paths": {
      // Each key is a key from file_paths
      // The value is a list of signature groups to run when an event fires
      // These will be watched for and scanned when the event framework
      // fire off an event to yara_events table
      "system_binaries": [ "sig_group_1" ],
      "tmp": [ "sig_group_1", "sig_group_2" ]
    }
  },

  // Paths to watch for filesystem events
  "file_paths": {
    "system_binaries": [ "/usr/bin/%", "/usr/sbin/%" ],
    "tmp": [ "/Users/%/tmp/%%", "/tmp/%" ]
  }
}
```


```bash
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "schedule_splay_percent": "10",
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_file_events": "true",
    "disable_events": "false",
    "disable_audit": "false",
    "audit_allow_config": "true",
    "host_identifier": "hostname",
    "enable_syslog": "true",
"audit_allow_process_events": "true",
    "audit_allow_sockets": "true"

  },
  "schedule": {
    "crontab": {
      "query": "SELECT * FROM crontab;",
      "interval": 100
    },
     "file_events": {
      "query": "SELECT * FROM file_events;",
      "removed": false,
      "interval": 100
    },
    "system_profile": {
      "query": "SELECT * FROM osquery_schedule;"
    },
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 100
    }
  },
    "yara": {
    "signatures": {
      "sig_group_1": [ "/etc/osquery/webshell.sig" ]
    },
    "file_paths": {
      "homes": [ "sig_group_1" ],
      "tmp": [ "sig_group_1" ]
    }
  },

   "file_paths": {
    "homes": [
      "/root/.ssh/%%",
      "/home/%/.ssh/%%"
    ],
    "etc": [
      "/etc/%%"
    ],
    "tmp": [
      "/tmp/%%"
    ]
  },
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT user AS username FROM logged_in_users ORDER BY time DESC LIMIT 1;"
    ]
  }
}
```

```bash
sudo osqueryctl config-check
```


```bash
 sudo osqueryd --config_path /etc/osquery/osquery.conf --verbose
```

```bash
 sudo osqueryi --config_path /etc/osquery/osquery.conf --verbose
```

```bash
platform@platform:/var/log/osquery$ ls -lah
total 3.3M
-rw-r-----  1 root root    59K May  9 08:44 osqueryd.results.log
lrwxrwxrwx  1 root root     38 May  9 08:08 osqueryd.WARNING -> osqueryd.WARNING.20240509-080845.29454
-rw-r--r--  1 root root    79K May  8 21:32 osqueryd.WARNING.20240508-213253.2303
```

## Osquery Fleet: Installation & Configuration

There are quite a few fleet management software options out there. Personally, I like the one below, and here are the steps to bring the server online so that all the Osquery agents can be managed from one server and can perform threat hunting as well.

Step 1 : Download the lastest version from [**github**]( https://github.com/fleetdm/fleet/releases)

```bash
tar -xf fleet_<version>_linux.tar.gz
sudo cp fleet_<version>_linux/fleet /usr/bin/
fleet version
```
Step 2 : MySQL instllation and configuration 

```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql.service
# create password 
sudo mysql
ALTER USER "root"@"localhost" IDENTIFIED BY "Password1234";
flush privileges;
exit
echo 'CREATE DATABASE fleet;' | mysql -u root -p
```

Step 3 : Redis Instalaltion 

```bash
sudo apt-get install redis
sudo service redis start
```

Step 4 : Generate SSL certificate (FQDN should match with target hostname)

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes   -keyout server.key -out server.cert 
```

Step 5 : Prepare the Fleet database 

```bash
fleet prepare db --mysql_address=127.0.0.1:3306  --mysql_database=fleet --mysql_username=root --mysql_password=Password1234
```

Step 5 : Start the Feelt server 

```bash
fleet serve \
  --mysql_address=127.0.0.1:3306 \
  --mysql_database=fleet \
  --mysql_username=root \
  --mysql_password=Password1234 \
  --redis_address=127.0.0.1:6379 \
  --server_cert=server.cert \
  --server_key=server.key \
  --logging_json
```

Step 6 : Once logged in using UI, Copy the Fleet Enrollment key and save it in Osquery location 

```bash
echo 'jj5kY9c7bLslsHaiJvvZwa3/dm5GWuv6' | sudo tee /var/osquery/enroll_secret
```

Step 6 : Start the OSquery agent 

```bash
sudo /usr/bin/osqueryd \
  --enroll_secret_path=/var/osquery/enroll_secret \
  --tls_server_certs=server.cert \
  --tls_hostname=SERVER_NAME:8080 \
  --host_identifier=instance \
  --enroll_tls_endpoint=/api/osquery/enroll \
  --config_plugin=tls \
  --config_tls_endpoint=/api/osquery/config \
  --config_refresh=10 \
  --disable_distributed=false \
  --distributed_plugin=tls \
  --distributed_interval=3 \
  --distributed_tls_max_attempts=3 \
  --distributed_tls_read_endpoint=/api/osquery/distributed/read \
  --distributed_tls_write_endpoint=/api/osquery/distributed/write \
  --logger_plugin=tls \
  --logger_tls_endpoint=/api/osquery/log \
  --logger_tls_period=10
```

The Osquery output logs can be pushed to SIEM systems such as Splunk so that security analysts can create detection use cases based on the Osquery endpoint agent events/queries.

<!-- PROD END-->

<!-- 
https://192.168.0.77:8080/dashboard

UI : Explorer#123 / jaa6.arimb00r@gmail.com
https://osquery.readthedocs.io/en/stable/deployment/yara/
https://www.youtube.com/watch?v=yT00ksfLkKs&t=2688s&ab_channel=DerpCon
https://www.youtube.com/watch?v=ep6y89rx8ww&t=127s&ab_channel=SANSCyberDefense
https://www.youtube.com/watch?v=yT00ksfLkKs&ab_channel=DerpCon
https://cybersecurity.att.com/blogs/labs-research/malware-analysis-using-osquery-part-2
https://threatconnect.com/blog/playbook-fridays-deploy-yara-signature-cbresponse/
https://github.com/fleetdm/fleet
https://community.carbonblack.com/t5/Query-Exchange/Using-YARA-rules-to-detect-webshell/idi-p/118861
https://www.digitalocean.com/community/tutorials/how-to-monitor-your-system-security-with-osquery-on-ubuntu-16-04
https://fleetdm.com/guides/osquery-evented-tables-overview
https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/
https://osquery.readthedocs.io/en/stable/deployment/process-auditing/
https://github.com/osquery/osquery/blob/master/docs/wiki/deployment/yara.md
-->

can use this credit card skimming code + megacart + yara + breish airwaays to detect brisit airwayys 

create IOC for the bad patten and hunt for it 


