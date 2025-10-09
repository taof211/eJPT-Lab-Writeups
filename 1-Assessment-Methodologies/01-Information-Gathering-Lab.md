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
  
- Attempted to access `http://target.ine.local/wp-admin/` and was redirected to `https:/target.ine.local/wp-login.php`

- Ran command `curl http:/target.ine.local/wp-login.php` and discovered the website was running on Wordpress version 6.5.3

- Ran command `whatweb http://target.ine.local`. Knew more information about the technologies used by the website and got the FLAG 2.

- Ran command `wpscan --url http://target.ine.local` and find the website configuration backup file `http://target.ine.local/wp-config.bak`. Also we found an interesting directory on the website `/wp-content`, which might be worth to explore later

- In the backup file, found the FLAG 4.

- Ran command `drib http://target.ine.local/wp-content` to see if there's anything interested. Found `http://target.ine.local/wp-content/uploads`, and it seems we can find fun things there.
  ![[Uploads Directory.png]]
- Browsed the `/uploads` directory in browser and found the FLAG 3.

- Ran command `trrack http://target.ine.local` to mirror the website

- Browsed the files dumped and found the FLAG 5 in the file `xmlrpc0db0.php`

# Key Finds
- FLAG1{d4b967540cad4cd5953e3ff1974c77c7}
- FLAG2{e63a338d49794c368b3949db14e11cb0}
- FLAG3{569d39fda7b749b99a1c04f8d8f3e089}
- FLAG4{a9aefe6fa8fc4a3d850c98f394a7bbd4}
- FLAG5{1f42aa70e3b34a97a9bbb3f87357b410}