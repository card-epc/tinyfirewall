
// hashlist.c
// Created by linux on 2020/9/25.
//
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("linux");
#define N 10
//数字链表
struct numlist{
    struct hlist_head hlistHead;
};
//数字链表节点
struct numnode{
    int num;
    struct hlist_node hlistNode;
};
struct  numlist nhead;
struct  numnode nnode;

static int __init hlist_init(void){
    //init head node
    struct hlist_node *pos;
    struct numnode *listnode;
    int i;

    printk("hashlist is starting...\n");
    //初始化头节点
    INIT_HLIST_HEAD(&nhead.hlistHead);

    for ( i = 0; i < N; ++i) {
        listnode = (struct numnode *)kmalloc(sizeof(struct numnode),GFP_KERNEL);
        listnode->num = i+1;
        //添加节点在头节点之前
        hlist_add_head(&(listnode->hlistNode),&nhead.hlistHead);

        printk("Node %d has added to the hash list...\n",i+1);

    }
    //遍历链表
    i = 1;
    struct numnode *p;

    hlist_for_each(pos,&nhead.hlistHead){
        //取得数字节点的数据域
        p =   hlist_entry(pos,struct numnode,hlistNode);
        printk("Node %d data:%d\n",i,p->num);
        i++;
    }
    return 0;
}

static void __exit hashlist_exit(void){
    struct hlist_node *pos,*n;
    struct numnode *p;
    int i;

    i =1;
    //遍历数字链表
    hlist_for_each_safe(pos,n,&nhead.hlistHead){
        //删除哈希节点
        hlist_del(pos);
        //取得删除节点的数据域值
        p =   hlist_entry(pos,struct numnode,hlistNode);
        kfree(p);
        printk("Node %d has removed from the hashlist ...\n",i++);

    }
    printk("hash list is exiting...\n");
}

module_init(hlist_init);
module_exit(hashlist_exit);
