# Cyber Security Live Project
This repository is for my Tech Academy Live Project. 

## Introduction
**Roles:** Penetration tester (Offensive Stories). Incident Responder (Defensive Stories).

Here I learned to work as a team in a simulated real life environment. We would perform daily stand ups with a project manager and discuss our successes and our road blocks.

I was tasked with several different stories for my Live Project with The Tech Academy. Before getting to the stories, I learned how to set up a virtual machine using VirtualBox. From there, Kali Linux was installed. I then set up a proxy using the Foxy Proxy extension through Firefox.  

For the offensive Stories I was tasked with exposing several different vulnerabilities in the OWASP's Juice Shop. For the defensive stories, I was given different PCAP files for analysis with different questions and tasks to solve.  

## Core Technologies
- VirtualBox
- Firefox
  - Developer Tools
  - Foxy Proxy
- Kali Linux
  - Burp Suite
  - Wire Shark
 
## Offensive Stories
- [Logging in as an Admin and a User](#logging-in-as-admin-and-a-user)
- [Resetting Admin's Password](#resetting-admins-password)
- [Privilege Escalation](#privilege-escalation)
- [Access Administration Page](#access-administration-page)
- [Exploit CAPTCHA](#exploit-captcha)
- [Accessing and Downloading Secured Secret Documents](#accessing-and-downloading-secured-secret-documents)

## Defensive Stories
- [Malware Traffic](#malware-traffic)
- [Find the Culprit!](#find-the-culprit)
- [Erik's Coffee Shop](#eriks-coffee-shop)

---
- Jump to: [Introduction](#introduction), [Offensive Stories](#logging-in-as-admin-and-a-user), [Defensive Stories](#malware-traffic), [Learning and Challenges](#learning-and-challenges)
--- 

### Logging in as Admin and a User

This was my first time doing any sort of penetration testing. After successfully setting up Kali Linux in a virtual machine, and getting the OWASP Juice Shop up and running, I was tasked with logging in as an admin. Here I got to explore how powerful Burp Suite can be. On the log in screen, We were able to log in as an admin with a very simple SQL injection.

<img width="800" height="400" alt="sql injection" src="https://github.com/user-attachments/assets/32c8ae3e-2e66-47ef-9e75-6e4726ccf47a" />

From there we were tasked to log in as a user named "Bender". After exploring the site, we came across the users email. We then used that information and performed another SQL injectiong to log in as the user "Bender"

<img width="800" height="400" alt="bender sql injection" src="https://github.com/user-attachments/assets/d360ee86-9e8a-44d6-96c7-f6b69e507a7f" />

This first task was a wonderful introduction into getting my feet wet with Burp Suite.

---

### Resetting Admin's Password

In this assignment, I was tasked with resetting the Admin's password. Within the assignment we were not allowed to use any sort of injections. From the previous story we had the Admin's log in credentials. In order to figure out the Admin's password we executed a brute force attack. We used the intruder tool within Burp Suite to set up the attack.

<img width="800" height="400" alt="password attack" src="https://github.com/user-attachments/assets/8ae5b4c0-022c-4187-bdaa-7e1614188563" />

Once the attack was finished, we relied on the status code to see if any of the passwords were a hit. and indeed, the password of "Admin123" was a hit. Indicated by the 200 status code.

<img width="800" height="162" alt="password found" src="https://github.com/user-attachments/assets/ad10d7d8-9cdf-46f3-98b1-795346084ad7" />

---

### Privilege Escalation

With this assignment, we were tasked with escalating a user's privileges. Here we utilized Burp Suite's repeater tool to analyze the HTTP headers. When creating a new user we were able to identify that the reponse would designate a role to the new user. 

<img width="800" height="400" alt="new user intercept" src="https://github.com/user-attachments/assets/09291622-9a44-4e6e-b087-237fab3b6bdb" />

With that information, we were able to manipulate the HTTP header for a different new user. We simply inserted a new line of "role". We filled that line with the new users role as Admin.

<img width="800" height="400" alt="different user body change" src="https://github.com/user-attachments/assets/b9b6378f-1174-4d42-88f6-89f4598b9667" />

And now we have successfully created a new user with Admin privileges. 

---

### Access Administration Page

Here, we were tasked with finding a "hidden" administration page. This assignment did not involve Burp Suite, but some simple exploring using the Firefox developer tools. While exploring the webpage we were able to look at several different JavaScript files. While searching for the term "admin" in all of the JavaScript files, we got an interesting hit in the 'main.js'. There, we found `path: 'administration',`

<img width="800" height="271" alt="mainJS admin path" src="https://github.com/user-attachments/assets/ad62a672-c395-4a49-8d12-d1275adf2ad5" />

We were able to directly navigate to the administration page in the URL. With our recently acquired admin privileges we were able to manipulate user feedback, ratings, and personal shopping baskets.

---

### Exploit CAPTCHA

We were given the assignment of bypassing the CAPTCHA on the customer feedback page. Here I used Burp Suite to intercept the request and inspect the HTTP header. I learned that the 'captchaID' field could change without any issues. The header was sent to the intruder tool and a Null Payload attack was set up to overwhelm the service.

<img width="800" height="500" alt="intruder attack setup" src="https://github.com/user-attachments/assets/ae5965b3-91e9-49db-831f-5545467858e7" />

---

### Accessing and Downloading Secured Secret Documents

For this story, I was tasked with finding a "secret" and "hidden" document. Then, to download files. We were specifically asked to not use any sort of penetration testing tools, and to only explore the website for the first half of this assignment. While exploring the page there was a very unique link within the 'about us' section. After clicking on the link, the URL looked different from the rest of the website. 

<img width="693" height="182" alt="ftp:legal" src="https://github.com/user-attachments/assets/581b69d5-8cd0-4ad4-956c-d4eb8a456fff" />

While exploring the 'ftp' directory, we attempted to download the target JSON files. We received an error. The error tipped us off on to which types of files are allowed which exposes itself to a null byte attack.

<img width="669" height="342" alt="files allowed" src="https://github.com/user-attachments/assets/99e9e2be-619c-4f27-873b-7c9453a94143" />

From here we enter `../../pack.json.back%00.md` into the URL, but we received another error. Here we used the Burp Suite encoder tool. I entered %00 into the encoder. With the new opput from the encoder, I entered that into the URL in place of the %00.

<img width="604" height="238" alt="decoder" src="https://github.com/user-attachments/assets/b075941b-3de3-4d3f-81c8-98cf957a3300" />

The double encoded null byte attack worked and I was able to successfully download the JSON file. 

---

### Malware Traffic

For this defensive story, a friend's computer has been compromised and encrypted. Somewhere and sometime they downloaded ransomware and are asking us to help identify when and where the issues arose. They have provided PCAP files for analysis. 

While sorting through the files, we were able to identify the IOC through a very unique and abnormal hostname. 

<img width="800" height="336" alt="shockwaveHTTP" src="https://github.com/user-attachments/assets/48bcd9ae-8e7c-47c1-b171-2feb3b00bea3" />

Inspecting the TCP path of that abnormal hostname revealed a Shockwave-flash object. There are several known vulnerabilites for this file type. The friend in this story has said that they clicked on a link that promised free movies.

<img width="800" height="510" alt="groupprogram" src="https://github.com/user-attachments/assets/71dfa678-7326-454c-8e27-0fd907458f51" />

Sorting the PCAP file cronologically, this first shockwave-flash object forced a redirect to a different IP address of 62.75.195.236. This new IP address contains the malware that infected the computer. Inspecting and following the TCP path for the host IP address 62.75.195.236 revealed a hidden executable file. 

<img width="800" height="446" alt="ThisProgramCantDOS" src="https://github.com/user-attachments/assets/dcef3b83-afee-4e26-9c45-550508902802" />

The malware was exported and checked on hybrid-analysis.com revealing that it is indeed a known executable malware with a SHA-256 of 532fld6b8faf6e54e3f6f9279e9720bf9f27257d2b75ce72e86ed3ca6578fafb

<img width="800" height="393" alt="cantDOSransomware" src="https://github.com/user-attachments/assets/8ddeded5-521f-48a3-8995-d7c7321d3899" />

Through further exploration of exported HTTP files, I was able to pull the ransomware's HTML. Using ChatGPT, I was able to clean up the HTML, implement some basic CSS, and run the ransomware website.

<img width="800" height="534" alt="givememoney" src="https://github.com/user-attachments/assets/ea41e13b-7d3c-480a-96ac-60cac666d09c" />

---

### Find the Culprit!

A machine has become infected. I was tasked with using the PCAP file provided to find information about the victim machine and figuring out where the root cause of the infection began.

We can use wireshark to analyze the PCAP files and find information about the infected machine. A great way to gather information on the infected machine is to check for any DHCP requests. In the first image we are able to find the MAC and IP address. The second image contains the victim machine’s name. 

Victim details:  
Date and Time: 09-22-2015 Between 22:41 and 22:57 UTC  
Victim IP address: 10.54.112.205  
Victim MAC address: 00:50:8b:01:2f (Hewlett Packard)  
Victim Host Name: Pendjiek-PC  
Victim Operating System: Windows  

<img width="800" height="495" alt="dhcp search" src="https://github.com/user-attachments/assets/fe289969-d5e9-4f3b-949a-488d6ccc8f5b" />

<img width="561" height="239" alt="host name" src="https://github.com/user-attachments/assets/1873927c-fa44-4c0f-ae29-527fb1f5c54b" />

We also discovered some suspcious domains here.

<img width="800" height="130" alt="suspiciousdomain" src="https://github.com/user-attachments/assets/a0516a77-f81c-4757-a5b5-c301a4a7c844" />


From there, not much else could be deciphered from the PCAP files. Using hybrid-analysis.com, I used the IP search feature. The search gave me a list of all the times that IP address has been reported. One of the items on the list had the same date, September 22, 2015 as the provided PCAP files. Also take note that AV Detection found the executable file RFQ_GMBH.exe to be a lokibot malware. 

<img width="800" height="255" alt="matchingdate" src="https://github.com/user-attachments/assets/91f649c6-b2b8-4c82-be05-2e75d4911239" />

Upon further inspection, the report on hybrid-analysis also had the same suspicious domains that were in the provided PCAP files. 

<img width="800" height="170" alt="matchingwebsites" src="https://github.com/user-attachments/assets/12646f5a-c088-42c1-a8df-d1f9c1d4ea03" />

With the information above, we can all but assume that we have found the source of the malware on the infected machine. 

---

### Erik's Coffee Shop

A local coffee shop has been compromised. They have tasked us with identifying the two user hosts and then identifying which machine got infected. Lastly, what is the type of malware and where did it come from.

This task was split into two separate tasks. The first task being identifying the two host clients, and then figuring out which host was infected. The second part of the assignment was then to figure out what kind of malware was installed. After some investigation the machines seem to be sharing a local network. Kerberos is a common protocol between machines sharing a local network. Using kerberos as a filter in wireshark we were able to gain valuable information about the machines in use.

<img width="800" height="830" alt="kerberossearch" src="https://github.com/user-attachments/assets/ac96247b-e20f-4bfc-a1e3-f0b17b3c6d43" />

Machine Details:  
Host 1: 10.0.0.149 - DESKTOP-C10SKPY - alyssa.fitzgerald  
Host 2: 10.0.0.167 - DESKTOP-GRIONXA - elmer.obrien (infected machine)  

We now have the two machines that could potentially be infected. Our next task is to find the malicious file. In wireshark, using the filter “this program” can sometimes be used in finding an executable file. Luckily enough, we got a hit. The destination IP address is 10.0.0.167. Make note of if this is indeed the malicious file so we know which machine got infected. 

<img width="800" height="135" alt="thisprogramsearch" src="https://github.com/user-attachments/assets/e1b3a6a6-ba9b-4baf-ba02-317d80bcd14d" />

Following the TCP stream gives us this information. We now have the Host name “alphapioneer.com”. The content type is labeled as image/png while it is clearly an executable file. The “MZ” being a give away, as well as the “this program cannot be run in DOS”. This is why the “this program” filter in wireshark can be useful.

<img width="800" height="600" alt="notpng" src="https://github.com/user-attachments/assets/05175b60-43db-45ca-8f38-71156535bae8" />

Exporting the HTTP file and uploading it to virustotal.com reveals that it is a qbot malware. A type of malware commonly used in phishing attacks that steals banking information and other credentials.

---

## Learning and Challenges

- Team Environment: Learned how to share and articulate problems and roadblocks. Collaboration in problem solving. 
- Setting up Kali Linux: I learned how to set up a virtual machine on my own personal computer. Using VirtualBox I was able to install Kali Linux. From there, I learned how to set up a Docker Image in the virtual machine so I can spin up the OWASP's Juice Shop to conduct my penetration testing stories. This helped me gain a small amount of comfort with the Linux command line.
- Burp Suite: For all the offensive stories mentioned above, I used the Burp Suite Community edition. Even then, it is an incredibly powerful tool for conducting penetration testing. I learned how to use key tools within burp suite such as the repeater and the intruder.
- Wireshark: Configuring Wireshark and customizing columns. Learning different "trick" filters to help decifer and find clues. 
- How to Google: I googled way more on this live project than anticipated. Particularly in the defensive portion of the stories. I googled IP address, suspicious websites, and what different types of malware do. 

---
- Jump to: [Introduction](#introduction), [Offensive Stories](#logging-in-as-admin-and-a-user), [Defensive Stories](#malware-traffic), [Learning and Challenges](#learning-and-challenges)
---

