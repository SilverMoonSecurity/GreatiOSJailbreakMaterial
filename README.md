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

iOS 10.3.2 XPC Userland Jailbreak Exploit Tutorial（CVE-2017-7047 ）的调试视频，上周五推送过一篇陈良对该 Exploit 的分析： https://www.youtube.com/watch?v=mzjRNvv69M8&sns

iOS 越狱开发者 Siguza 和 tihmstar 今日正式发布了 iOS 9.3.5 不完美越狱：http://www.cnbeta.com/articles/tech/638919.htm

### Bugs & Vulnerability:
#### XPC bug
*CVE-2017-7047 Fixed-2017-July-19
    Many iOS/MacOS sandbox escapes/privescs due to unexpected shared memory-backed xpc_data objects
    This is an exploit for CVE-2017-7047, a logic error in libxpc which allowed
malicious message senders to send xpc_data objects that were backed by shared memory.
Consumers of xpc messages did not seem to expect that the backing buffers of xpc_data objects
could be modified by the sender whilst being processed by the receiver.

    This project exploits CVE-2017-7047 to build a proof-of-concept remote lldb debugserver
stub capable of attaching to and allowing the remote debugging all userspace
processes on iOS 10.0 to 10.3.2.

#### Safari bug
*  CVE-2017-2533, theTOCTOU issue indiskarbitrationd
*  CVE-2017-2534,a quirky configuration of the Speech Synthesis service which allows us toeasily execute arbitrary code in its context.
*  CVE-2017-2535/ZDI-17-356, a logic issue in theApple Security framework that allows us to bypass the authorization sandbox

https://github.com/phoenhex/files/tree/master/exploits/safari-sbx

http://qbview.url.cn/getResourceInfo?appid=31&url=https%3A%2F%2Fphoenhex.re%2F2017-07-06%2Fpwn2own-sandbox-escape%3Fnsukey%3DWdZZ51ES0kgaC51Cs8s46wyep1xL%252FkMQ6oSrMP0Hsr2tbDsTgQMcKk%252FSDG7EJeckW2tIdcxvFu9M1kuz63NL8DPhtvFfC8gw%252F3BuUE5JmGVKQOck0ht0nwBEeqfzyuKiSDY09fW%252Fq%252Bv2nQkYqZhffLMymSgb%252F1fnxV3vXWjwMYEigXbUvJQbBEBeTeAd%252BGT2&version=10000&doview=1&ua=Mozilla%2F5.0+(Windows+NT+6.1%3B+WOW64)+AppleWebKit%2F537.36+(KHTML%2C+like+Gecko)+Chrome%2F39.0.2171.95+Safari%2F537.36+MicroMessenger%2F6.5.2.501+NetType%2FWIFI+WindowsWechat+QBCore%2F3.43.556.400+QQBrowser%2F9.0.2524.400&keeplink=0&reformat=0

* Safari exploit for iOS 10.3.2 and MacOS 10.12.4
CVE-2017-2533: TOCTOU in diskarbitrationd
CVE-2017-2535: PID reuse logic bug in authd
CVE-2017-2534: Arbitrary dylib loading in speechsynthesisd
CVE-2017-6977: NULL ptr dereference in nsurlstoraged
https://github.com/maximehip/Safari-iOS10.3.2-macOS-10.12.4-exploit-Bugs

#### Local Privilege Esclation
*  setattrlist() 
  iOS 内核漏洞介绍： https://www.antid0te.com/blog.html
* IoconnectCallMethod condition race，fixed in iOS 10.2
   CVE-2016-7624, CVE-2016-7625, CVE-2016-7714, CVE-2016-7620
  当IOKit的IOConnectCallMethod中的inputStruct长度超过4096时，IOKit会将用户态内存映射到内核，作为用户输入数据：
  -用户态和内核态的buffer共享同一物理内存
  -用户态对buffer的修改会立即体现在内核态buffer上
  -产生条件竞争问题
  
* CVE-2016-4654, Posted by PanGu, fixed in ios10.0 beta2
methodCall(IOMobileFramebuffer::swap_submit) in IOMobileFramebufferUserClient heap overflow

* CVE-2016-4655 , is_io_registry_entry_get_property_bytes about OSNumber  to cause  Kernel Stack info leak, fixed in iOS 10.0.1

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
   
* CVE-2017-2357
     Partial initialization。 The vulnerability lies in IOAudioFamilyvoid IOAudioControlUserClient::sendChangeNotification(UInt32 notificationType) (<= 204.4)。
The kernel sends a message with 8 bytes kernel heap data to the user space.
Source code:
https://opensource.apple.com/source/IOAudioFamily/IOAudioFamily-204.4/


* CVE-2017-2358
A vcall is invoked blindly of uninitialized stack variable in function AMDRadeonX4000_AMDAccelShared::SurfaceCopy in MADRademonXx00.kext
https://www.usenix.org/conference/woot17/workshop-program/presentation/xu


#### iOS 11 iCloud Bypass Bug
https://www.youtube.com/watch?v=U1cFcD-s48M&feature=youtu.be
iOS 11 iCloud Bypass on iPad & iPhone - Huge Activation Lock Flaw
#### iCloud Authentication Bug
* CVE-2017–2448, 
iCloud OTR签名校验中第一步读取四个字节后返回值设为success，第二步在长度过短校验失败的情况下没有更新返回值直接返回，导致后续函数认为校验通过。攻击者可以通过中间人拦截解密icloud keychain以及其中的各种密码。 
http://m.weibo.cn/status/4105419439985137?wm=3333_2001&from=1074193010&sourcetype=weixin

### iCloud keychain
* ? iOS 10.3, iCloud keychain protocol bug
http://www.zdnet.com/article/icloud-security-flaw-icloud-keychain-iphone-mac-passwords-vulnerable/

Before  iOS 10.3 
我们知道什么字节进行翻转可以获得无效的签名，同时也可以获得许可，我们能够发送一个错误的签名，并修改协商报文，然后接收它。从设备中获得了一个许可，而这样他们就能以纯文本的形式看到Keychain中的所有东西。有了这个bug以后，我就就不需要直接去窃取iCloud Keychain了，只需要知道他们的帐户名称，我就可以访问他们的iCloud帐户了

### sandbox escape
* xpc_data objects 
Many iOS/MacOS sandbox escapes/privescs due to unexpected shared memory-backed xpc_data objects： https://bugs.chromium.org/p/project-zero/issues/detail?id=1247
 
### Exploit mitigation:

* 限制某些HeapSpray对象的创建数量
  IOAccelResource2超过1000， 
* 简化一些“危险”接口
  is_io_service_open_extended 允许传入序列化数据并调用OSUnserializeXML做内存布局
  Simplified in iOS 10.2.
* enhance KPP/AMCC
  -iOS 10 beta 2中内核Got表开始收KPP/AMCC保护
  -PanGu 9.3.3中修改Got的方法被禁止， PE_i_can_has_debugger
  -Luca iOS 10.1.1中AMCC绕过的方法被修补
* 限制使用task_for_pid 0
  - 获得 kernel task port 成了许多越狱的标配
  - 特别是Ian Beer的mach_portal巧妙获取kernel task port
  -iOS 10.3中对用户态进程使用kernel task port做了限制
     --不允许任何用户态进程通过kernel task port读写内核内存
     -- Ian beer mach_portal的内核利用被缓解
  -  iOS 11中进一步限制APP读写其他进程内存
     --Ian Beer用户态port劫持的方法被缓解
*  64位SMAP的引入(iPhone 7)
  - iOS 6中早已针对ARM机型将内核地址与用户态地址隔离
     --内核空间无法访问用户态地址
  -  而ARM64机型只有SMEP
     -- 禁止内核态执行用户态地址的代码
     -- 但内核态可以访问用户空间的地址
  -  为ARM64内核漏洞利用提供便利
     -- 省去了泄露内核堆地址的步骤
     --例如： PanGu 9.3.3越狱， Yalu102越狱中都有访问用户态内存的环节
  - iphone7后禁止内核态访问用户态空间内存
     -- 对内核信息泄露有了更高的要求
  
*  Summary
  - iOS 10，苹果极大加强了内核安全性
  - 沙盒内的漏洞几乎绝迹
    -- 今后越狱需要过沙盒+沙盒外内核漏洞的组合利用
  - 对于一些经典漏洞，苹果更偏向以机制性的改进来彻底杜绝整类问题而不仅仅修复单一漏洞
  - 苹果对一些常见利用手段进行缓解，使得漏洞利用变得更加困难
  
 
# Windows
## Summary paper
 * windows-kernel-exploits Windows平台提权漏洞集合  
 https://github.com/SecWiki/windows-kernel-exploits
 
 * Windows exploit POC
 https://github.com/WindowsExploits/Exploits
 
 
 ## Exploit tricks
 windows_kernel_address_leaks - 从用户态泄露 Windows 内核地址的方法汇总： 
 https://github.com/sam-b/windows_kernel_address_leaks
  
# Android
## Summary paper
（阿里云）开发者福利：史上最全Android 开发和安全系列工具
https://zhuanlan.zhihu.com/p/25261296

移动APP漏洞自动化检测平台建设
https://security.tencent.com/index.php/blog/msg/109

## Android/Linux kernel exploit
* A bunch of links related to Linux kernel fuzzing and exploitation
https://github.com/xairy/linux-kernel-exploitation

* linux-kernel-exploits Linux平台提取漏洞集合 https://www.sec-wiki.com
https://github.com/SecWiki/linux-kernel-exploits


* CVE-2017-9445: Out-of-bounds write in systemd-resolved with crafted TCP payload (systemd)
http://openwall.com/lists/oss-security/2017/06/27/8
    Certain sizes passed to dns_packet_new can cause it to allocate a buffer
that's too small. A page-aligned number - sizeof(DnsPacket) +
sizeof(iphdr) + sizeof(udphdr) will do this - so, on x86 this will be a
page-aligned number - 80. Eg, calling dns_packet_new with a size of 4016
on x86 will result in an allocation of 4096 bytes, but 108 bytes of this
are for the DnsPacket struct.
    A malicious DNS server can exploit this by responding with a specially
crafted TCP payload to trick systemd-resolved in to allocating a buffer
that's too small, and subsequently write arbitrary data beyond the end
of it.

* CVE-2017-8890， Phoenix Talon about Socket of Linux
CVE-2017-8890本身是一个 double free 的问题，使用setsockopt()函数中MCAST_JOIN_GROUP选项，并调用accept()函数即可触发该漏洞。
http://mp.weixin.qq.com/s/6NGH-Dk2n_BkdlJ2jSMWJQ

* Android wifi vulnerability POC 2016-2017
Mosec 2017, POCs reported by 360 Qihook flankersky about Pixel xl(Qualcomm)and Android 6P(Broadcom)
https://github.com/flankersky/android_wifi_pocs
http://www.tuicool.com/articles/YnENFnu 漏洞挖掘之利用Broadcom的Wi-Fi栈（一）

* CVE-2016-6738 Exp
https://github.com/jiayy/android_vuln_poc-exp/tree/master/EXP-CVE-2016-6738

* CVE-2017-10663, CVE-2017-10662, and CVE-2017-0750
Vulnerability in F2FS File System Leads To Memory Corruption on Android, Linux
CVE-2017-10663 is due to the absence of a buffer boundary check in the appropriate source code. 
CVE-2017-10662 is an integer overflow.
CVE-2017-0750 is also caused by the absence of a buffer boundary check.
http://blog.trendmicro.com/trendlabs-security-intelligence/vulnerability-f2fs-file-system-leads-memory-corruption-android-linux/


# Virtual Machine
## Vmware work station
*  CVE-2017-4901, VMware Workstation and Fusion updates address critical out-of-bounds memory access vulnerability.
VMware实现了多种虚拟机（下文称为guest）与宿主机（下文称文host）之间的通信方式。其中一种方式是通过一个叫做Backdoor的接口，这种方式的设计很有趣，guest只需在用户态就可以通过该接口发送命令。VMware Tools也部分使用了这种接口来和host通信。

https://zhuanlan.zhihu.com/p/27733895?utm_medium=social&utm_source=wechat_timeline&from=timeline&isappinstalled=1

* Vware drag and drop
ZDI 之前分析了一个 VMware drag-and-drop 相关的 UAF 漏洞，这个漏洞通过一个叫做 "Backdoor" 的 RPC 接口触发，今天这篇 Blog ZDI 写了一个工具用于 Backdoor 接口的辅助分析、Fuzz 和 Exploit 开发： https://www.zerodayinitiative.com/blog/2017/8/1/pythonizing-the-vmware-backdoor

# JavaScript
## Security
* a javascript static security analysis tool Code:https://github.com/dpnishant/jsprime


# Machine Learning
## Summary
* 人工智能之机器学习 machine-learning
https://github.com/wangxiaoleiAI/machine-learning

Keep updating...please follow, thanks.

