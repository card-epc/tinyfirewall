#ifndef STATE_HASHTABLE_H
#define STATE_HASHTABLE_H

#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/xxhash.h>
#include <linux/slab.h>
#include <linux/icmp.h>
#include <linux/rtc.h>
#include <linux/timex.h>
#include <linux/timer.h>
#include <linux/timekeeping.h>
#include "sharedstruct.h"


// Hash Table Config
#define HASHBITS (10)
#define HTABSIZE (1 << HASHBITS)
#define HASHMASK ((HTABSIZE) - 1)

#define IP_FMT_ARGS(ip) \
    (((uint8_t*)&(ip))[3]), (((uint8_t*)&(ip))[2]), (((uint8_t*)&(ip))[1]), (((uint8_t*)&(ip))[0])

#define UTC_BY_SEC (ktime_get_real_seconds() - RTC_TIMESTAMP_BEGIN_1900/NSEC_PER_SEC + 8*3600)

#define LOG_INFO(fmt, ...) \
    logmsgList_add("\033[37m[INFO]\033[0m "fmt, __VA_ARGS__)

#define LOG_WARN(fmt, ...) \
    logmsgList_add("\033[33m[WARN]\033[0m "fmt, __VA_ARGS__)

#define LOG_ERROR(fmt, ...) \
    logmsgList_add("\033[31m[ERROR]\033[0m "fmt, __VA_ARGS__)

#define stateTable_entry(pos)    hlist_entry(pos, st_hashlistNode, hlistNode)
#define natList_entry(pos)       list_entry(pos, natlistNode, listnode)
#define ruleList_entry(pos)      list_entry(pos, rulelistNode, listnode)
#define logmsgList_entry(pos)    list_entry(pos, logmsglistNode, listnode)


enum LOGLEVEL { INFO, WARNING, ERROR };

typedef struct {
    char    msg[100];
    struct list_head listnode;
} logmsglistNode;

typedef struct {
    NatTableItem natitem;
    struct list_head listnode;
} natlistNode;

typedef struct {
    RuleTableItem ruleitem;
    struct list_head listnode;
} rulelistNode;

typedef struct {
    StateTableItem st_item;
    struct hlist_node hlistNode;
} st_hashlistNode;


extern bool default_rule;
extern struct file *logfile;
extern uint32_t startTimeStamp;
extern uint32_t tot_rules;
extern uint32_t tot_nats;
extern uint32_t tot_conns;
extern struct mutex mtx;
extern struct work_struct log_work;

extern unsigned long   lockflags;
extern spinlock_t stateHashTable_lock;

const uint32_t hashseed = 0xabcd1234;

// Declare data structure
DECLARE_HASHTABLE(st_heads, HASHBITS);
LIST_HEAD(rulelist);
LIST_HEAD(natlist);
LIST_HEAD(logmsglist);

inline uint32_t nowBysec(void) {
    ktime_t t = ktime_to_us(ktime_get());
    return t / USEC_PER_SEC - startTimeStamp;
}

static void log_write(void* buf, uint32_t len) {
    int64_t ret;
    loff_t pos = 0;
    mm_segment_t old_fs = get_fs();

    set_fs(KERNEL_DS);

    ret = vfs_write(logfile, buf, len, &pos);
    if (ret == -EINVAL) {
        printk("VFS WRITE EINVAL");
    } else if (ret != len) {
        printk("write exists error. RET %lld", ret);
    } else {
        printk("Log An Item");
    }

    set_fs(old_fs);
}

static bool logmsgList_add(const char* fmtstr, ...) {

    // logmsglistNode* logmsgnode = container_of_safe(msgstr, logmsglistNode, msg);

    logmsglistNode* logmsgnode;
    va_list argptr;
    int32_t tot_write = 0;
    ktime_t t = UTC_BY_SEC;
    struct rtc_time tm_now;
    rtc_time_to_tm(t, &tm_now);


    va_start(argptr, fmtstr);
    logmsgnode = (logmsglistNode*)kmalloc(sizeof(logmsglistNode), GFP_KERNEL);

    if (logmsgnode == NULL) {
        printk("logmsg List Add Kmalloc Error");
        return 0;
    }

    memset(logmsgnode->msg, 0, sizeof(logmsgnode->msg));
    tot_write = sprintf(logmsgnode->msg, "[%02d:%02d:%02d] ", tm_now.tm_hour, tm_now.tm_min, tm_now.tm_sec);
    tot_write += vsprintf(logmsgnode->msg + tot_write, fmtstr, argptr);

    if (tot_write < 0) {
        printk("VSPRINTF ERROR");
        return 0;
    }
    logmsgnode->msg[tot_write] = '\n';


    mutex_lock(&mtx);
    list_add_tail(&logmsgnode->listnode, &logmsglist);
    mutex_unlock(&mtx);

    va_end(argptr);
    schedule_work(&log_work);
    return 1;
}

static void logmsgList_destory(void) {
    struct list_head *pos, *n; 
    logmsglistNode *p;
    
    if (!list_empty(&logmsglist)) {
        printk("There are Some Logs Lost");
        LOG_WARN("EXIT TOO FAST LOGS LOST", NULL);
    }

    list_for_each_safe(pos, n, &logmsglist) {
        p = logmsgList_entry(pos);
        list_del(pos);
        kfree(p);
    }  
}
static bool natList_add(const NatTableItem* cnitem) {
    natlistNode* natnode;
    
    natnode = (natlistNode*)kmalloc(sizeof(natlistNode), GFP_KERNEL);
    if (natnode == NULL) {
        printk("nat List Add Kmalloc Error");
        LOG_ERROR("NAT LIST NODE KMALLOC FAILED", NULL);
        return 0;
    }
    
    memcpy(&natnode->natitem, cnitem, sizeof(NatTableItem));

    list_add(&natnode->listnode, &natlist);
    ++tot_nats;

    LOG_INFO("F: %u.%u.%u.%u:%u L: %u.%u.%u.%u:%u  --> NAT ADD", 
                IP_FMT_ARGS(cnitem->external_ip), cnitem->external_port,
                IP_FMT_ARGS(cnitem->internal_ip), cnitem->internal_port);
    return 1;
}

static void natList_del(uint32_t idnum) {
    uint32_t idx = idnum;
    struct list_head *pos, *n;
    natlistNode* p;

    if (idx > tot_nats) return;
    list_for_each_safe(pos, n, &natlist) {
        if (idx == 0) {
            p = natList_entry(pos);

            list_del(pos);
            --tot_nats;

            printk("nat List Node %u was Del", idnum);
            LOG_INFO("F: %u.%u.%u.%u:%u L: %u.%u.%u.%u:%u --> NAT DEL", 
                    IP_FMT_ARGS(p->natitem.external_ip), p->natitem.external_port,
                    IP_FMT_ARGS(p->natitem.internal_ip), p->natitem.internal_port);
            kfree(p);
            break;
        } else {
            --idx;
        }
    }
}

static void natList_destory(void) {
    struct list_head *pos, *n; 
    natlistNode *p;
    list_for_each_safe(pos, n, &natlist) {
        p = natList_entry(pos);

        list_del(pos);

        printk("A natNode Delete IN DESTORY");
        kfree(p);
    }
}
static bool ruleList_add(const RuleTableItem* critem) {
    rulelistNode* rulenode;
    
    rulenode = (rulelistNode*)kmalloc(sizeof(rulelistNode), GFP_KERNEL);
    if (rulenode == NULL) {
        printk("Rule List Add Kmalloc Error");
        LOG_ERROR("RULE NODE KMALLOC FAILED", NULL);
        return 0;
    }
    
    memcpy(&rulenode->ruleitem, critem, sizeof(RuleTableItem));
    list_add(&rulenode->listnode, &rulelist);

    ++tot_rules;
    LOG_INFO("Src: %u.%u.%u.%u/%u:%u Dst: %u.%u.%u.%u/%u:%u --> RULE ADD",
            IP_FMT_ARGS(rulenode->ruleitem.src_ip), rulenode->ruleitem.src_cidr, rulenode->ruleitem.src_port,
            IP_FMT_ARGS(rulenode->ruleitem.dst_ip), rulenode->ruleitem.dst_cidr, rulenode->ruleitem.dst_port);
    return 1;
}

static void ruleList_del(uint32_t idnum) {
    uint32_t idx = idnum;
    struct list_head *pos, *n;
    rulelistNode* p;

    if (idx > tot_rules) return;
    list_for_each_safe(pos, n, &rulelist) {
        if (idx == 0) {
            p = ruleList_entry(pos);
            list_del(pos);
            --tot_rules;
            printk("Rule List Node %u was Del", idnum);
            LOG_INFO("Src: %u.%u.%u.%u/%u:%u Dst: %u.%u.%u.%u/%u:%u --> RULE DEL",
                    IP_FMT_ARGS(p->ruleitem.src_ip), p->ruleitem.src_cidr, p->ruleitem.src_port,
                    IP_FMT_ARGS(p->ruleitem.dst_ip), p->ruleitem.dst_cidr, p->ruleitem.dst_port);
            kfree(p);
            break;
        } else {
            --idx;
        }
    }
}

static void ruleList_destory(void) {
    struct list_head *pos, *n; 
    rulelistNode *p;

    list_for_each_safe(pos, n, &rulelist) {
        p = ruleList_entry(pos);

        list_del(pos);
        printk("A RuleNode Delete IN DESTORY");
        kfree(p);
    }
}

static bool check_firewall_rules(const StateTableItem *citem, bool isIn) {
    uint8_t  proto;
    uint32_t srcmask, dstmask;

    struct list_head *pos, *n; 
    rulelistNode *p;

    struct {
        uint32_t src_ip;   // --> foreign 
        uint32_t dst_ip;   // --> local
        uint16_t src_port;
        uint16_t dst_port;
    } info;

    memcpy(&info, &citem->core, sizeof(info));
    proto = citem->proto;
    if (!isIn) {
        SWAP_VALUE(info.src_ip, info.dst_ip);
        SWAP_VALUE(info.dst_port, info.src_port);
    }

    if (citem->proto == ICMP) {
        printk("SRC_IP %u\nDST_IP %u\n", info.src_ip, info.dst_ip);
    }

    list_for_each_safe(pos, n, &rulelist) {
        p = ruleList_entry(pos);
        
        if (p->ruleitem.protocol == 0 || p->ruleitem.protocol == proto) {
            printk("RULE TEST PROTOCOL PASS");
            srcmask = GETMASK(p->ruleitem.src_cidr);
            dstmask = GETMASK(p->ruleitem.dst_cidr);
            if ((info.src_ip & srcmask) == p->ruleitem.src_ip && 
                (info.dst_ip & dstmask) == p->ruleitem.dst_ip) {
                printk("RULE TEST IPADDR TEST PASS");
                if (proto == ICMP) {
                    return p->ruleitem.action;
                } else {
                    if ((!p->ruleitem.src_port || p->ruleitem.src_port == info.src_port) &&
                        (!p->ruleitem.dst_port || p->ruleitem.dst_port == info.dst_port)) {
                        printk("RULE TEST PORT PASS");
                        return p->ruleitem.action;
                    }
                }
            }
        }
    }

    LOG_INFO("F: %u.%u.%u.%u:%u L: %u.%u.%u.%u:%u P: %u --> NO RULE MATCH",
            IP_FMT_ARGS(citem->core.foren_ip), citem->core.fport,
            IP_FMT_ARGS(citem->core.local_ip), citem->core.lport, citem->proto);
    return default_rule;

}

static bool statehashTable_add(const StateTableItem* citem) {
    // GET HASH
    st_hashlistNode *listnode;
    uint32_t hash = 12345678;

    hash = xxh32(&citem->core, corelen, hashseed);
    listnode = (st_hashlistNode*)kmalloc(sizeof(st_hashlistNode), GFP_KERNEL);
    if (listnode == NULL) {
        printk("Hash Table Add Kmalloc Error");
        LOG_ERROR("HASH TABLE NODE KMALLOC FAILED", NULL);
        return 0;
    }
    
    memcpy(&listnode->st_item, citem, stateItemlen);

    // spin_lock_irqsave(&stateHashTable_lock, lockflags);
    hash_add(st_heads, &(listnode->hlistNode), hash);    
    ++tot_conns;
    // spin_unlock_irqrestore(&stateHashTable_lock, lockflags);
    LOG_INFO("F: %u.%u.%u.%u:%u L: %u.%u.%u.%u:%u P: %u --> CONN ADD",
            IP_FMT_ARGS(citem->core.foren_ip), citem->core.fport,
            IP_FMT_ARGS(citem->core.local_ip), citem->core.lport, citem->proto);
    
    return 1;
}

static void statetable_node_del(struct hlist_node *pos)  { 
    st_hashlistNode *p = stateTable_entry(pos);
    hlist_del(pos);
    --tot_conns;
    LOG_INFO("F: %u.%u.%u.%u:%u L: %u.%u.%u.%u:%u P: %u --> CONN DEL",
            IP_FMT_ARGS(p->st_item.core.foren_ip), p->st_item.core.fport,
            IP_FMT_ARGS(p->st_item.core.local_ip), p->st_item.core.lport, p->st_item.proto); 
    kfree(p);
}

// Check Connection Status Include Time Expired, if exists then return State Node
static struct hlist_node* statehashTable_exist(const StateTableItem* citem) {

    uint32_t hash = xxh32(&citem->core, corelen, hashseed);
    uint32_t st_head_idx = hash_32(hash, HASHBITS);
    struct hlist_node *pos, *n;
    st_hashlistNode *p;

    // spin_lock_irqsave(&stateHashTable_lock, lockflags);
    hlist_for_each_safe(pos, n, &st_heads[st_head_idx]) {
        p = stateTable_entry(pos);
        // This connection must be unique, so if status is wrong, return 0;
        if (memcmp(&p->st_item.core, &citem->core, corelen) == 0) {
            // p->st_item.state = 3;
            if (p->st_item.expire >= nowBysec()) {
                return pos;
            } else {
                printk("ONE CONNCTION EXPIRED %u : %u", p->st_item.expire, nowBysec());
                LOG_INFO("F: %u.%u.%u.%u:%u L: %u.%u.%u.%u:%u P: %u --> CONN EXPIRED",
                        IP_FMT_ARGS(p->st_item.core.foren_ip), p->st_item.core.fport,
                        IP_FMT_ARGS(p->st_item.core.local_ip), p->st_item.core.lport, p->st_item.proto);
                statetable_node_del(pos);
                --tot_conns;
                break;
            }
        }
    }
    // spin_unlock_irqrestore(&stateHashTable_lock, lockflags);
    return NULL;
}


static void statehashTable_init(void) {
    printk("hashlist is starting...\n");
    hash_init(st_heads);
}

static void statehashTable_destory(void){
    int i, a = 0;
    st_hashlistNode *p;
    struct hlist_node *pos, *n;

    for (i = 0; i < HTABSIZE; i++) {
        hlist_for_each_safe(pos, n, &st_heads[i]){
            hlist_del(pos);
            p = stateTable_entry(pos);

            kfree(p);
            a++;
            printk("Head %d has removed from the hashlist ...\n", i);
        }
    }
    printk("Total : %d. hash list is exiting...\n", a);
}

#endif
