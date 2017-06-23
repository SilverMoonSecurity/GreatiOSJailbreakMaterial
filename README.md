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
* CVE-2016-4654, Posted by PanGu, fixed in ios10.0 beta2
methodCall(IOMobileFramebuffer::swap_submit) in IOMobileFramebufferUserClient heap overflow

* CVE-2016-4655 , is_io_registry_entry_get_property_bytes about OSNumber  to cause  Kernel Stack info leak

* IOAccelResource2 video card interface bug
 which is bridge the user mode application and vedio card
 a. IOAccelResource2 OOM+double free bug, 
 IOAccelResource2::newResourceWithIOSurfaceDeviceCache中不再对deviceCache进行release操作， fixed in iOS 10.0 beta 1
 b. IOAccelResouce2 空指针引用漏洞
 IOAccelSharedUserClient2::page_off_resource in IOAccelSharedUserClient2, fixed in ios 10.2
 
* CVE-2016-7644, set_dp_control_port UAF
* CVE-2017-2360 host_self_trap UAF
  上述两个漏洞因，Port对象维护独立的Zone中，风水较难， ios 10.3以后类似漏洞几乎绝迹
  
* CVE-2017-2370 for ios 10.2
 Posted by Ian Beer, Project Zero in 2017-04-18
 Discovery and exploitation of CVE-2017-2370, a heap buffer overflow in the mach_voucher_extract_attr_recipe_trap mach trap.
 https://googleprojectzero.blogspot.hk/2017/04/exception-oriented-exploitation-on-ios.html
 https://bugs.chromium.org/p/project-zero/issues/detail?id=1004
 https://bugs.chromium.org/p/project-zero/issues/detail?id=1004#c4
 
* MACOS 10.12.2 mach_voucher HeapOverFlow
https://jaq.alibaba.com/community/art/show?articleid=781


* MACOS 10.12.5-， CVE-2017-2545 io_connect_get_notification_semaphore 导致内核vblSemaphore对象 UAF
 http://blogs.360.cn/blog/pwn2own-using-macos-kernel-vuln-escape-from-safari-sandbox/
 
   360 Pwn2Own 2017比赛，用户态调用io_connect_get_notification_semaphore获取信号量后，可以销毁该信号量。此时，内核中vblSemaphore仍指向一个已经销毁释放的信号量对象。当用户态继续调用io_connect_get_notification_semaphore获取vblSemaphore并使用该信号量时，就会触发UAF（释放后使用）的情况。利用这个接口，我们可以把内核中 IOFramebuffer::getNotificationSemaphore的UAF问题，转化为内核地址信息泄漏和任意代码执行。

#### iCloud Authentication Bug
* CVE-2017–2448, 
iCloud OTR签名校验中第一步读取四个字节后返回值设为success，第二步在长度过短校验失败的情况下没有更新返回值直接返回，导致后续函数认为校验通过。攻击者可以通过中间人拦截解密icloud keychain以及其中的各种密码。 
http://m.weibo.cn/status/4105419439985137?wm=3333_2001&from=1074193010&sourcetype=weixin

### Exploit mitigation:

# Android
## Summary paper
（阿里云）开发者福利：史上最全Android 开发和安全系列工具
https://zhuanlan.zhihu.com/p/25261296

## Android/Linux kernel exploit
* A bunch of links related to Linux kernel fuzzing and exploitation
https://github.com/xairy/linux-kernel-exploitation

* linux-kernel-exploits Linux平台提取漏洞集合 https://www.sec-wiki.com
https://github.com/SecWiki/linux-kernel-exploits

* Phoenix Talon 
CVE-2017-8890本身是一个 double free 的问题，使用setsockopt()函数中MCAST_JOIN_GROUP选项，并调用accept()函数即可触发该漏洞。
http://mp.weixin.qq.com/s/6NGH-Dk2n_BkdlJ2jSMWJQ

* Android wifi vulnerability POC 2016-2017
Mosec 2017, POCs reported by 360 Qihook flankersky about Pixel xl(Qualcomm)and Android 6P(Broadcom)
https://github.com/flankersky/android_wifi_pocs

# JavaScript
## Security
* a javascript static security analysis tool Code:https://github.com/dpnishant/jsprime

Keep updating...please follow, thanks.


