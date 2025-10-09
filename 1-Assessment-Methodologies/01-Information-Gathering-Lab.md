---
tags:
  - "#lab"
  - "#ctf"
  - "#red_team"
  - "#T1592_002"
topic: Information Gathering
date: 2025-10-09
---
# Objective

Skill Check Labs are interactive, hands-on exercises designed to validate the knowledge and skills you’ve gained in this course through real-world scenarios. Each lab presents practical tasks that require you to apply what you’ve learned. Unlike other INE labs, solutions are not provided, challenging you to demonstrate your understanding and problem-solving abilities. Your performance is graded, allowing you to track progress and measure skill growth over time.

# Walkthrough

- Accessed `http://target.ine.local/robots.txt` Known the host is running on Wordpress, get sensitive URL, and got Flag 1

  <img width="677" height="251" alt="Robots File" src="https://github.com/user-attachments/assets/c2a6ac34-37b0-4f06-b074-6bea8337f4d6" />

- Attempted to access `http://target.ine.local/wp-admin/` and was redirected to `https:/target.ine.local/wp-login.php`

  <img width="1015" height="610" alt="WP Login Page" src="https://github.com/user-attachments/assets/aae84215-d9b4-4dfe-81cb-048be4a50ced" />

- Ran command `curl http:/target.ine.local/wp-login.php` and discovered the website was running on Wordpress version 6.5.3

  <img width="911" height="247" alt="Service Version Discovery" src="https://github.com/user-attachments/assets/abdd860c-dc17-4ae8-8142-573dea39f33c" />

- Ran command `whatweb http://target.ine.local`. Knew more information about the technologies used by the website and got the FLAG 2.
  
- Ran command `wpscan --url http://target.ine.local` and find the website configuration backup file `http://target.ine.local/wp-config.bak`. Also we found an interesting directory on the website `/wp-content`, which might be worth to explore later

  <img width="791" height="117" alt="WP Config Backup" src="https://github.com/user-attachments/assets/9ccf227f-3822-4a08-b714-254344a41e0d" />

  <img width="1241" height="341" alt="WP Content Directory" src="https://github.com/user-attachments/assets/17e33b4b-0e4b-42da-8260-a558b1a214a4" />


- In the backup file, found the FLAG 4.

- Ran command `drib http://target.ine.local/wp-content` to see if there's anything interested. Found `http://target.ine.local/wp-content/uploads`, and it seems we can find fun things there.

  <img width="736" height="485" alt="Uploads Directory" src="https://github.com/user-attachments/assets/8ef8af64-4995-4c98-8a49-0e7df2b89086" />

- Browsed the `/uploads` directory in browser and found the FLAG 3.

- Ran command `trrack http://target.ine.local` to mirror the website

  <img width="368" height="212" alt="Website Mirroring" src="https://github.com/user-attachments/assets/483203e8-2a90-4da7-af8a-cbe19ad97bfa" />

- Browsed the files dumped and found the FLAG 5 in the file `xmlrpc0db0.php`

# Key Finds
- FLAG1{d4b967540cad4cd5953e3ff1974c77c7}
- FLAG2{e63a338d49794c368b3949db14e11cb0}
- FLAG3{569d39fda7b749b99a1c04f8d8f3e089}
- FLAG4{a9aefe6fa8fc4a3d850c98f394a7bbd4}
- FLAG5{1f42aa70e3b34a97a9bbb3f87357b410}
