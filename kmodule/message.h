#ifndef __MESSAGE_H
#define __MESSAGE_H


#include <linux/printk.h>
#include <linux/xxhash.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/ktime.h>
#include "tablelist.h"
#include "sharedstruct.h"

extern struct sock* nlsock; 

static int32_t sendtouser(const uint8_t* buf, uint32_t len) {

    struct sk_buff* nl_skb;
    struct nlmsghdr* nl_hdr;

    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if (NULL == nl_skb) {
        printk("nlmsg_new ERROR");
        return -1;
    }

    nl_hdr = nlmsg_put(nl_skb, 0, 0, USER_MSG, len, 0);
    if (NULL == nl_hdr) {
        printk("nlmsg_put ERROR");
        nlmsg_free(nl_skb);
        return -1;
    }

    memcpy(nlmsg_data(nl_hdr), buf, len);
    
    return netlink_unicast(nlsock, nl_skb, STATIC_PORT, MSG_DONTWAIT);
}

static void sendNatsToUser(void) {
    NatTableItem tot_items[tot_nats];
    uint32_t idx = 0;
    struct list_head *pos, *n;
    natlistNode* p;

    list_for_each_safe(pos, n, &natlist) {
        p = natList_entry(pos);
        memcpy(tot_items + idx++, &p->natitem, natItemlen);
    }

    sendtouser((void*)tot_items, sizeof(tot_items));
}

static void sendRulesToUser(void) {
    RuleTableItem tot_items[tot_rules];
    uint32_t idx = 0;
    struct list_head *pos, *n;
    rulelistNode* p;

    list_for_each_safe(pos, n, &rulelist) {
        p = ruleList_entry(pos);
        memcpy(tot_items + idx++, &p->ruleitem, ruleItemlen);
    }

    sendtouser((void*)tot_items, sizeof(tot_items));
}

static void sendConnToUser(void) {
    StateTableItem tot_items[tot_conns];
    int i, idx = 0;
    uint32_t timenow = nowBysec();
    st_hashlistNode *p;
    struct hlist_node *pos, *n;

    for (i = 0; i < HTABSIZE; i++) {
        hlist_for_each_safe(pos, n, &st_heads[i]) {
            p = stateTable_entry(pos);
            if (p->st_item.expire < timenow) { 
                p->st_item.expire = 0;
                printk("Head %d doesn't send to the user ... because of expire\n", i);
            } else {
                memcpy(tot_items + idx++, &p->st_item, stateItemlen);
                printk("Head %d has send to the user ...\n", i);
            }
        }
    }
    sendtouser((void*)tot_items, idx * stateItemlen);
}

static void recvfromuser(struct sk_buff* skb) {
    struct nlmsghdr *nl_hdr = NULL;
    uint8_t *data = NULL;
    uint8_t type, id;
    NatTableItem  nitem;
    RuleTableItem ritem;
    // const char *str = "This is KERNEL";
    uint32_t payload_len = skb->len - NLMSG_HDRLEN;
    printk("Recv Pkg Len : %u\n", skb->len);
    if (skb->len >= nlmsg_total_size(0)) {
        nl_hdr = nlmsg_hdr(skb);
        data = nlmsg_data(nl_hdr);
        type = *data;
        printk("type %u", type);
        printk("Length %u", payload_len);
        switch (type) {
            case RULE_ADD:
                printk("ADD RULE");
                memcpy(&ritem, data + 1, ruleItemlen);
                ruleList_add(&ritem);
                break;
            case RULE_SHOW:
                printk("RULE_SHOW");
                sendRulesToUser();
                break;
            case RULE_DEL:
                id = *(data + 1);
                printk("RULE DEL %u", id);
                ruleList_del(id);
                break;
            case NAT_ADD:
                printk("NAT ADD");
                memcpy(&nitem, data + 1, natItemlen);
                natList_add(&nitem);
                break;
            case NAT_SHOW:
                printk("NAT_SHOW");
                sendNatsToUser();
                break;
            case NAT_DEL:
                id = *(data + 1);
                printk("NAT_DEL %u", id);
                natList_del(id);
                break;
            case CONNETION_SHOW:
                printk("CONNETION_SHOW");
                sendConnToUser();
                break;
            case LOG:
                printk("LOG");
                break;
            default:
                printk("DEFAULT");
                printk("kernel Recv Data : %s", (char*)(data+1));
                break;
                
        }
    }
}







inline void printNowTime(void) {
    printk("TIME BY NOW PASS %u s", nowBysec());
}

void printIPaddr(const struct sk_buff* skb) {
    const struct iphdr* Header = ip_hdr(skb);
    uint32_t sipaddr = Header->saddr;
    uint32_t dipaddr = Header->daddr;
    printk("src IP: %d.%d.%d.%d", *((uint8_t*)(&sipaddr) + 0), *((uint8_t*)(&sipaddr) + 1),
                          *((uint8_t*)(&sipaddr) + 2), *((uint8_t*)(&sipaddr) + 3));
    printk("dst IP: %d.%d.%d.%d", *((uint8_t*)(&dipaddr) + 0), *((uint8_t*)(&dipaddr) + 1),
                          *((uint8_t*)(&dipaddr) + 2), *((uint8_t*)(&dipaddr) + 3));
}

void printTransPort(const struct sk_buff* skb) {
    const struct tcphdr* Header = tcp_hdr(skb);
    printk("src port: %hu, dst port: %hu", htons(Header->source), htons(Header->dest));
}

void printTcpFlags(const struct sk_buff* skb) {
    const struct tcphdr* Header = tcp_hdr(skb);
    printk("syn: %u, ack: %u, psh: %u, fin: %u, rst: %u, ugr: %u",
            Header->syn, Header->ack, Header->psh, Header->fin, Header->rst, Header->urg);
}

void printCoreMsg(const StateTableItem* citem) {
    uint32_t fipaddr = citem->core.foren_ip;
    uint32_t lipaddr = citem->core.local_ip;
    printk("forei IP: %d.%d.%d.%d", *((uint8_t*)(&fipaddr) + 0), *((uint8_t*)(&fipaddr) + 1),
                          *((uint8_t*)(&fipaddr) + 2), *((uint8_t*)(&fipaddr) + 3));
    printk("local IP: %d.%d.%d.%d", *((uint8_t*)(&lipaddr) + 0), *((uint8_t*)(&lipaddr) + 1),
                          *((uint8_t*)(&lipaddr) + 2), *((uint8_t*)(&lipaddr) + 3));
    printk("forei Port: %hu", (citem->core.fport));
    printk("local Port: %hu", (citem->core.lport));
    printk("proto: %u, state: %u", citem->proto, citem->state);
}


#endif
