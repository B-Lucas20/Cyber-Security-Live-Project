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
- Malware Traffic
- Find the Culprit!
- Erik's Coffee Shop

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












