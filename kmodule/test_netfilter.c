#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/netlink.h>
#include <linux/in_route.h>
#include <net/ip.h>
#include <linux/mutex.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include "message.h"
#include "state_hashtable.h"

#define USER_MSG  24
#define USER_PORT 50

#define ICMP  1
#define TCP   6
#define UDP  17

static struct sock* nlsock = NULL;


typedef struct hlist_head st_hashlistHead;




static int32_t sendtouser(const char* buf, uint32_t len) {

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
    return netlink_unicast(nlsock, nl_skb, USER_PORT, MSG_DONTWAIT);
}

static void recvfromuser(struct sk_buff* skb) {
    struct nlmsghdr* nl_hdr = NULL;
    char* data = NULL;
    const char* str = "This is KERNEL";
    printk("Recv Pkg Len : %u\n", skb->len);
    if (skb->len >= nlmsg_total_size(0)) {
        nl_hdr = nlmsg_hdr(skb);
        data = nlmsg_data(nl_hdr);
        if (data != NULL) {
            printk("kernel Recv Data : %s", data);
            sendtouser(str, strlen(str));
        }
    }
}

struct netlink_kernel_cfg cfg = {
    .input = recvfromuser,
};

static uint8_t get_TCP_sign(const struct tcphdr* head) {
    if (head->rst) {
        return RST;
    } else if (head->syn) {
        return (head->ack) ? (SYNACK) : (SYN);
    } else if (head->fin) {
        return (head->ack) ? (FINACK) : (FIN);
    } else if (head->ack) {
        return ACK;
    }
    return UNDEFINED;
}

static int32_t check_firewall_rules(const struct sk_buff *citem) {
    return 1;
}

static uint32_t check_tcp_status(const struct sk_buff* skb, int8_t trans_buf[10][6], int8_t isIn) {
    int8_t stateTemp;
    StatusTableItem* retItemptr;
    struct iphdr* ipHeader = ip_hdr(skb);
    struct tcphdr* tcpHeader = tcp_hdr(skb);
    
    StatusTableItem temp = {
        .proto = TCP,
        .iport.foren_ip = isIn ? ipHeader->saddr : ipHeader->daddr,
        .iport.local_ip = isIn ? ipHeader->daddr : ipHeader->saddr,
        .iport.fport = isIn ? htons(tcpHeader->source) : htons(tcpHeader->dest),
        .iport.lport = isIn ? htons(tcpHeader->dest) : htons(tcpHeader->source),
        .state = get_TCP_sign(tcpHeader),
    };
    

    retItemptr = statehashTable_exist(&temp);
    if (tcpHeader->fin) {
        printk("FIN PKT RECVED : NOW STATE %d", retItemptr->state);
    }
    if (retItemptr) {
        stateTemp = trans_buf[retItemptr->state][temp.state];
        // -1 means maintain old state
        if (stateTemp != -1) {
            if (stateTemp == CLOSED) {
                printk("CLOSED GET ONE <--> DELETE ONE FROM TABLE");
                statehashTable_del(retItemptr);
            } else {
                printk("STATE CHANGE from %d to %d", retItemptr->state, stateTemp);
                retItemptr->state = stateTemp;
            }
        }
        return NF_ACCEPT;
    } else if(check_firewall_rules(skb)) {
        printk("PASS FIREWALL");
        temp.state = trans_buf[0][temp.state];
        printk("FIRST CATCH STATE : %d", temp.state);
        statehashTable_add(&temp);
        return NF_ACCEPT;
    } else {
        return NF_DROP;
    }
    
    printk("*******TCP********");
    printIPaddr(skb);
    printTransPort(skb);
    printTcpFlags(skb);
    printk("*******END********");
    printk(" ");
    return NF_ACCEPT;
}



static uint32_t test_nf_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *ipheader = ip_hdr(skb);
    /* const struct tcphdr* tcpheader = tcp_hdr(skb); */
    /* printk("this is test_nf_pre_routing 111"); */
    /* printk("out name : %s", state->out->name); */
    /* printk("in  name : %s", state->in->name); */
    /* printIPaddr(skb); */
    /* printk("Protocol %d", ipheader->protocol); */
    switch (ipheader->protocol) {
        case ICMP:
            break;
        case TCP:
            check_tcp_status(skb, in_tcp_state_tranform_buf, 1);
            break;
        case UDP:
            break;
        default:
            return NF_ACCEPT;
            
    }
    /* return NF_DROP; */
    return NF_ACCEPT;
}


static uint32_t test_nf_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    /* printk("this is test_nf_local_output 666"); */
    /* printk("out name : %s", state->out->name); */
    /* printk("in  name : %s", state->in->name); */
    const struct iphdr *ipheader = ip_hdr(skb);
    switch (ipheader->protocol) {
        case ICMP:
            break;
        case TCP:
            check_tcp_status(skb, out_tcp_state_tranform_buf, 0);
            break;
        case UDP:
            break;
        default:
            return NF_ACCEPT;
            
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops test_nf_ops[] = {
  {
    .hook = test_nf_pre_routing,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = 100,
  },
  {
    .hook = test_nf_post_routing,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = 100,
  },
};

static int __net_init test_netfilter_init(void) {
    nlsock = netlink_kernel_create(&init_net, USER_MSG, &cfg);
    if (NULL == nlsock) {
        printk("SOCK CREATE ERROR");
        return -1;
    }
    printk("SOCK CREATE SUCCESS");
    statehashTable_init();
    return nf_register_net_hooks(&init_net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}

static void __net_exit test_netfilter_exit(void) {
    sock_release(nlsock->sk_socket);
    statehashTable_exit();
    nf_unregister_net_hooks(&init_net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}

/* static struct pernet_operations test_netfilter_ops = { */
/*     .init = test_netfilter_init, */
/*     .exit = test_netfilter_exit, */
/* }; */

/* static int __init test_module_init(void) { */
/*     return register_pernet_subsys(&test_netfilter_ops);   */
/* } */
/*  */
/* static void __exit test_module_exit(void) { */
/*     unregister_pernet_subsys(&test_netfilter_ops);   */
/* } */

module_init(test_netfilter_init);
module_exit(test_netfilter_exit);

MODULE_LICENSE("GPL");
