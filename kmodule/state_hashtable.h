#ifndef STATE_HASHTABLE_H
#define STATE_HASHTABLE_H

#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/xxhash.h>
#include <linux/slab.h>
#include "message.h"


extern spinlock_t stateHashTable_lock;
extern unsigned long   lockflags;

// Hash Table Config
#define HASHBITS 10
#define HTABSIZE (1 << HASHBITS)
#define HASHMASK (HTABSIZE - 1)

#define stateTable_entry(pos) hlist_entry(pos, st_hashlistNode, hlistNode)

#define statetable_node_del(pos) \
{ static_assert(__same_type((pos), struct hlist_node*));hlist_del(pos);kfree(stateTable_entry(pos)); }

DECLARE_HASHTABLE(st_heads, HASHBITS);


static int32_t statehashTable_add(const StateTableItem* citem) {
    // GET HASH
    st_hashlistNode *listnode;
    uint32_t hash = 12345678;

    printk("Hash Table Add an Item");

    hash = xxh32(&citem->core, corelen, hashseed);
    listnode = (st_hashlistNode*)kmalloc(sizeof(st_hashlistNode), GFP_KERNEL);
    if (listnode == NULL) {
        printk("Hash Table Add Kmalloc Error");
        return -1;
    }
    
    memcpy(&listnode->st_item, citem, itemlen);

    // printk("BEFORE ADD EXPIRED %u", listnode->st_item.expire);
    // spin_lock_irqsave(&stateHashTable_lock, lockflags);
    hash_add(st_heads, &(listnode->hlistNode), hash);    
    // spin_unlock_irqrestore(&stateHashTable_lock, lockflags);
    
    return 0;
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
                break;
            }
        }
        printk("%d COMPARE TEST", i++);
    }
                // spin_unlock_irqrestore(&stateHashTable_lock, lockflags);
    return NULL;
}

static void statehashTable_del(const struct StateTableItem* citem) {

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

static void statehashTable_exit(void){
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

            printCoreMsg(&p->st_item);

            kfree(p);
            a++;
            printk("Head %d has removed from the hashlist ...\n", i);
        }
    }
    printk("Total : %d. hash list is exiting...\n", a);
}

#endif
