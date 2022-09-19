# tinyfirewall
一个基于 Linux 5.x netfilter 的勉强可用状态检测防火墙

## 实现主要功能

1. 能够对 tcp 连接的状态建立较为规整的状态机，udp 和 icmp 仅建立极简单的连接 ( 若通过防火墙规则就建立，超时后断开 )
2. rule  : 最新添加条目匹配优先级最高，可以覆盖之前规则
3. log   : 文件名称为启动时日期，记录由内核线程和信号量完成
4. nat   : 仅实现对部分 tcp 的 nat 转化， 即添加条目须 ip 和 port 全部设置

## 目录结构

1. **kmodule** - - - - - - - - - - - - - -内核模块

   - message.h - - - - - - - - - -主要包含 netlink 与用户态通信


   - myfirewall.c - - - - - - - - - hook api 以及初始化，收尾


   - tablelist.h - - - - - - - - - - rule, nat 单链表, stateTable 哈希链表 


   - sharedstruct.h - - - - - - - -与用户态公用的结构包含常用数据


2.  **user** - - - - - - - - - - - - - - - - CLI


  - main.cpp - - - - - - - - - - main						 

  - message.h - - - - - - - - - netlink 通信 与 cmdManager 解析命令行参数

  - parser.h - - - - - - - - - - - 包含对 netlink 收到数据包的解析器

  - config.h - - - - - - - - - - - rule.tb 读取抽出相关有效信息


3. **log**
   - xxxx-xx-xx.log - - - - - - - -某天的日志


4. **conf**
   - rule.tb - - - - - - - - - - - - -规则表, # 开头为注释  **内含格式说明 （ 不推荐使用**


## 使用

​	make 编译 make load 装载模块 make unload 卸载 make clean 清除

​	RULE 表 NAT 表 可增删查，删除依据 -l 的序号

​    CONN 连接表  只能查看

​	NAT 表 增加时必须指定 两个 ip 和 port，规则表 增加时选项内含默认值(port 为 0 是全部端口，cidr 默认 32， protocol 默认 ANY（使用协议号而不是字符串），action 默认 deny（0 deny 1 accept）)

```shell
*** TABLENAME : NAT\RULE\CONN ***
*** A command must include one of ( -l| -d| -a| -i| -h ) ***

USAGE: fwctl -l TABLENAME
       fwctl -d TABLENAME --id IDNUM (FROM --list)
       fwctl -a TABLENAME --sip SRCIP --dip DSTIP --sport SPORT --dport DPORT --[protocol|scidr|action]

Options:
  --list      -l  list table messages
  --delete    -d  delete a table item
  --append    -a  append a table item
  --help      -h  show this message
  --init      -i  load rule file and add all to fire wall
  --sip           set src ip
  --dip           set dst ip
  --sport         set src port
  --dport         set dst port

BELOW OPTIONS ARE ONLY FOR FIREWALL RULE ADD
  --scidr         set src cidr (DEFAULT 32)
  --dcidr         set dst cidr (DEFAULT 32)
  --action        set action   (DEFAULT DENY)
  --protocol  -p  set protocol (DEFAULT ANY)
```



## 测试环境

​		先后在 linux 5.4.0-54-generic (seed 20.04) 和 linux 5.15.0 (ubuntu 20.04.1) 上进行测试，内核中关于文件读写和时间获取函数略有不同，分别对应 v0.1.0 v0.1.1 不同内核应该相差不大

​		**建议使用 nc 对 udp 和 tcp 进行测试，主要是有关 tcp nat 的测试 nc 发送数据大小可控。**

## 存在的问题

1. nat 转化问题较大，关于 nat 转化后数据包checksum的计算，当数据包较长时 (300+Bytes)，校验和会出错导致一方无法收到数据包(wireshark 抓不到)，致使只能单向通信（一般只有向外的 nat 转换校验和会出错）。

   当利用 nat 进行端口映射只在本地连接测试便不会存在问题。

   也许与 `ethtool rx tx` 设置有关，时间有限不再测试了。

2. 有关 softirq 的锁机制，虽然不加锁基本不会出问题，但是一旦在整个遍历链表操作上加锁必然死锁，所以最后选择仅在必要操作中加锁，测试中无死锁现象

3. 不同 linux 内核版本有些函数可能已有变化
