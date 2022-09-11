#ifndef STATE_HASHTABLE_H
#define STATE_HASHTABLE_H

#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/xxhash.h>
#include <linux/slab.h>
#include "sharedstruct.h"

extern spinlock_t stateHashTable_lock;
extern unsigned long   lockflags;
extern uint32_t startTimeStamp;
extern bool default_rule;
extern uint32_t tot_rules;
extern uint32_t tot_nats;
extern uint32_t tot_conns;

// Hash Table Config
#define HASHBITS 10
#define HTABSIZE (1 << HASHBITS)
#define HASHMASK ((HTABSIZE) - 1)

#define stateTable_entry(pos) hlist_entry(pos, st_hashlistNode, hlistNode)
#define natList_entry(pos)    list_entry(pos, natlistNode, listnode)
#define ruleList_entry(pos)   list_entry(pos, rulelistNode, listnode)

#define statetable_node_del(pos) \
{ static_assert(__same_type((pos), struct hlist_node*));hlist_del(pos);kfree(stateTable_entry(pos));--tot_conns; }

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


const uint32_t hashseed = 0xabcd1234;

// Declare data structure
DECLARE_HASHTABLE(st_heads, HASHBITS);
LIST_HEAD(rulelist);
LIST_HEAD(natlist);

inline uint32_t nowBysec(void) {
    ktime_t t = ktime_to_us(ktime_get());
    return t / USEC_PER_SEC - startTimeStamp;
}

static bool natList_add(const NatTableItem* cnitem) {
    natlistNode* natnode;
    
    natnode = (natlistNode*)kmalloc(sizeof(natlistNode), GFP_KERNEL);
    if (natnode == NULL) {
        printk("nat List Add Kmalloc Error");
        return 0;
    }
    
    memcpy(&natnode->natitem, cnitem, sizeof(NatTableItem));
    list_add(&natnode->listnode, &natlist);

    ++tot_nats;
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
            kfree(p);
            --tot_nats;
            printk("nat List Node %u was Del", idnum);
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
        return 0;
    }
    
    memcpy(&rulenode->ruleitem, critem, sizeof(RuleTableItem));
    list_add(&rulenode->listnode, &rulelist);

    ++tot_rules;
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
            kfree(p);
            --tot_rules;
            printk("Rule List Node %u was Del", idnum);
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

    return default_rule;

}

static bool statehashTable_add(const StateTableItem* citem) {
    // GET HASH
    st_hashlistNode *listnode;
    uint32_t hash = 12345678;

    printk("Hash Table Add an Item");

    hash = xxh32(&citem->core, corelen, hashseed);
    listnode = (st_hashlistNode*)kmalloc(sizeof(st_hashlistNode), GFP_KERNEL);
    if (listnode == NULL) {
        printk("Hash Table Add Kmalloc Error");
        return 0;
    }
    
    memcpy(&listnode->st_item, citem, stateItemlen);

    // printk("BEFORE ADD EXPIRED %u", listnode->st_item.expire);
    // spin_lock_irqsave(&stateHashTable_lock, lockflags);
    hash_add(st_heads, &(listnode->hlistNode), hash);    
    ++tot_conns;
    // spin_unlock_irqrestore(&stateHashTable_lock, lockflags);
    
    return 1;
}

// Check Connection Status, if exists then return Status
static struct hlist_node* statehashTable_exist(const StateTableItem* citem) {

    uint32_t hash = xxh32(&citem->core, corelen, hashseed);
    uint32_t st_head_idx = hash_32(hash, HASHBITS);
    struct hlist_node *pos, *n;
    st_hashlistNode *p;
    int i = 0;

                // spin_lock_irqsave(&stateHashTable_lock, lockflags);
    hlist_for_each_safe(pos, n, &st_heads[st_head_idx]) {
        // p = hlist_entry(pos, st_hashlistNode, hlistNode);
        p = stateTable_entry(pos);
        // This connection must be unique, so if status is wrong, return 0;
        if (memcmp(&p->st_item.core, &citem->core, corelen) == 0) {
            // p->st_item.state = 3;
            if (p->st_item.expire >= nowBysec()) {
                return pos;
            } else {
                printk("ONE CONNCTION EXPIRED %u : %u", p->st_item.expire, nowBysec());
                hlist_del(pos);
                kfree(p);
                --tot_conns;
                break;
            }
        }
        printk("%d COMPARE TEST", i++);
    }
                // spin_unlock_irqrestore(&stateHashTable_lock, lockflags);
    return NULL;
}

static void statehashTable_del(const StateTableItem* citem) {

    uint32_t hash = xxh32(&citem->core, corelen, hashseed);
    uint32_t st_head_idx = hash_32(hash, HASHBITS);
    struct hlist_node *pos, *n;
    st_hashlistNode *p;

    // printk("DEL INDEX: %d", st_head_idx);
    // spin_lock(&stateHashTable_lock);
    hlist_for_each_safe(pos, n, &st_heads[st_head_idx]){
        // p = hlist_entry(pos, st_hashlistNode, hlistNode);
        p = stateTable_entry(pos);
        if (memcmp(&p->st_item.core, &citem->core, corelen) == 0) {
            // printk("StatehashTable_del function");
            // printCoreMsg(&p->st_item);
            hlist_del(pos);
            kfree(p);
            --tot_conns;
        }
    }
    // spin_unlock(&stateHashTable_lock);
}

static void statehashTable_init(void) {
    //init head node
    // int i;
    // struct hlist_node *pos;
    // st_hashlistNode *p;
    // StateTableItem item = { .state = 1, .core.foren_ip = 1234, .core.local_ip = 5678 };

    printk("hashlist is starting...\n");
    /* INIT_HLIST_HEAD(&st_heads); */
    hash_init(st_heads);

}

static void statehashTable_destory(void){
    int i, a = 0;
    st_hashlistNode *p;
    struct hlist_node *pos, *n;

    for (i = 0; i < HTABSIZE; i++) {
        //遍历数字链表
        hlist_for_each_safe(pos, n, &st_heads[i]){
            //删除哈希节点
            hlist_del(pos);
            // p = hlist_entry(pos, st_hashlistNode, hlistNode);
            p = stateTable_entry(pos);

            // printCoreMsg(&p->st_item);

            kfree(p);
            a++;
            printk("Head %d has removed from the hashlist ...\n", i);
        }
    }
    printk("Total : %d. hash list is exiting...\n", a);
}

#endif
