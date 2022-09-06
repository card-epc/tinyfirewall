#ifndef STATE_HASHTABLE_H
#define STATE_HASHTABLE_H

#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/xxhash.h>
#include <linux/slab.h>
#include "message.h"


// Hash Table Config
#define HASHBITS 10
#define HTABSIZE (1 << HASHBITS)
#define HASHMASK (HTABSIZE - 1)

enum Protocol { tcp = 0, udp, icmp, others };

DECLARE_HASHTABLE(st_heads, HASHBITS);


// static int32_t stateTCPItemCmp(const struct StatusTableItem* ctableitem, const struct StatusTableItem* cquertitem) {
//     // if ((ctableitem->src_ip == cquertitem->src_ip &&))
// }

static int32_t statehashTable_add(const StatusTableItem* citem) {
    // GET HASH
    st_hashlistNode *listnode;
    uint32_t hash = 12345678;

    printk("Hash Table Add an Item");

    hash = xxh32(&citem->iport, corelen, hashseed);
    listnode = (st_hashlistNode*)kmalloc(sizeof(st_hashlistNode), GFP_KERNEL);
    if (listnode == NULL) {
        printk("Hash Table Add Kmalloc Error");
        return -1;
    }
    
    memcpy(&listnode->st_item, citem, itemlen);

    hash_add(st_heads, &(listnode->hlistNode), hash);    
    
    return 0;
}

// Check Connection Status, if exists then return Status
static StatusTableItem* statehashTable_exist(const StatusTableItem* citem) {

    uint32_t hash = xxh32(&citem->iport, corelen, hashseed);
    uint32_t st_head_idx = hash_32(hash, HASHBITS);
    struct hlist_node *pos, *n;
    st_hashlistNode *p;
    int i = 0;

    hlist_for_each_safe(pos, n, &st_heads[st_head_idx]) {
        p = hlist_entry(pos, st_hashlistNode, hlistNode);
        // This connection must be unique, so if status is wrong, return 0;
        if (memcmp(&p->st_item.iport, &citem->iport, corelen) == 0) {
            // p->st_item.state = 3;
            return &p->st_item;
        }
        printk("%d COMPARE TEST", i++);
    }
    return NULL;
}

static void statehashTable_del(const struct StatusTableItem* citem) {

    uint32_t hash = xxh32(&citem->iport, corelen, hashseed);
    uint32_t st_head_idx = hash_32(hash, HASHBITS);
    struct hlist_node *pos, *n;
    st_hashlistNode *p;

    // printk("DEL INDEX: %d", st_head_idx);
    hlist_for_each_safe(pos, n, &st_heads[st_head_idx]){
        p = hlist_entry(pos, st_hashlistNode, hlistNode);
        if (memcmp(&p->st_item.iport, &citem->iport, corelen) == 0) {
            // printk("StatehashTable_del function");
            // printCoreMsg(&p->st_item);
            hlist_del(pos);
            kfree(p);
        }
    }
}

static void statehashTable_init(void) {
    //init head node
    // int i;
    // struct hlist_node *pos;
    // st_hashlistNode *p;
    // StatusTableItem item = { .state = 1, .iport.foren_ip = 1234, .iport.local_ip = 5678 };

    printk("hashlist is starting...\n");
    /* INIT_HLIST_HEAD(&st_heads); */
    hash_init(st_heads);


    // //遍历链表
    // for (i = 0; i < HTABSIZE; i++) {
    //     hlist_for_each(pos, &st_heads[i]){
    //         //取得数字节点的数据域
    //         p =   hlist_entry(pos, st_hashlistNode, hlistNode);
    //         printk("Head %d data:%d\n", i, p->st_item.state);
    //     }
    // }
}

static void statehashTable_exit(void){
    int i, a = 0;
    st_hashlistNode *p;
    struct hlist_node *pos, *n;

    for (i = 0; i < HTABSIZE; i++) {
        //遍历数字链表
        hlist_for_each_safe(pos, n, &st_heads[i]){
            //删除哈希节点
            hlist_del(pos);
            p = hlist_entry(pos, st_hashlistNode, hlistNode);

            printCoreMsg(&p->st_item);

            kfree(p);
            a++;
            printk("Head %d has removed from the hashlist ...\n", i);
        }
    }
    printk("Total : %d. hash list is exiting...\n", a);
}

#endif
