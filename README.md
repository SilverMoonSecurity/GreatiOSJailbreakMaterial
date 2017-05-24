# ios/MacOS

twitter@ http://twitter.com/Flyic

twitter@ http://twitter.com/SparkZheng

weibo@ http://weibo.com/zhengmin1989

## Jail Break Projects:

iOS 8.4.1 Yalu Open Source Jailbreak Project: https://github.com/kpwn/yalu

OS-X-10.11.6-Exp-via-PEGASUS: https://github.com/zhengmin1989/OS-X-10.11.6-Exp-via-PEGASUS

iOS 9.3.* Trident exp: https://github.com/benjamin-42/Trident

iOS 10.1.1 mach_portal incomplete jailbreak: https://bugs.chromium.org/p/project-zero/issues/detail?id=965#c2

iOS 10.12 jailbreak source code: https://github.com/kpwn/yalu102

Local Privilege Escalation for macOS 10.12.2 and XNU port Feng Shui: https://github.com/zhengmin1989/macOS-10.12.2-Exp-via-mach_voucher

incomplete iOS 10.2 jailbreak for 64 bit devices by qwertyoruiopz and marcograssi code:https://github.com/kpwn/yalu102

Exception-oriented exploitation by Ian Beer Code:https://github.com/xerub/extra_recipe


### Bugs & Vulnerability:
#### Local Privilege Esclation

* MACOS 10.12.2 mach_voucher HeapOverFlow
https://jaq.alibaba.com/community/art/show?articleid=781


* MACOS 10.12.5-， CVE-2017-2545 io_connect_get_notification_semaphore 导致内核vblSemaphore对象 UAF
 http://blogs.360.cn/blog/pwn2own-using-macos-kernel-vuln-escape-from-safari-sandbox/
 
   360 Pwn2Own 2017比赛，用户态调用io_connect_get_notification_semaphore获取信号量后，可以销毁该信号量。此时，内核中vblSemaphore仍指向一个已经销毁释放的信号量对象。当用户态继续调用io_connect_get_notification_semaphore获取vblSemaphore并使用该信号量时，就会触发UAF（释放后使用）的情况。利用这个接口，我们可以把内核中 IOFramebuffer::getNotificationSemaphore的UAF问题，转化为内核地址信息泄漏和任意代码执行。

#### iCloud Authentication Bug
* CVE-2017–2448, 
iCloud OTR签名校验中第一步读取四个字节后返回值设为success，第二步在长度过短校验失败的情况下没有更新返回值直接返回，导致后续函数认为校验通过。攻击者可以通过中间人拦截解密icloud keychain以及其中的各种密码。 
http://m.weibo.cn/status/4105419439985137?wm=3333_2001&from=1074193010&sourcetype=weixin


# Android
## Summary paper
（阿里云）开发者福利：史上最全Android 开发和安全系列工具
https://zhuanlan.zhihu.com/p/25261296

## Linux kernel exploit
https://github.com/xairy/linux-kernel-exploitation

# JavaScript
## Security
* a javascript static security analysis tool Code:https://github.com/dpnishant/jsprime

Keep updating...please follow, thanks.


