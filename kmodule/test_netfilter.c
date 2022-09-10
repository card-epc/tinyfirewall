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
#include <linux/icmp.h>
#include "message.h"
#include "state_hashtable.h"

#define USER_MSG  24
#define USER_PORT 50

spinlock_t stateHashTable_lock;
unsigned long lockflags;

int32_t debug = 0;
uint32_t startTimeStamp = 0;
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
    if (debug < 1) {
        debug++;
        return 1;
    } else {
        return 1;
    } 
}

static uint32_t check_icmp_status(const struct sk_buff* skb, bool isIn) {
    bool isRequest;
    StateTableItem* retItemptr;
    struct hlist_node* exist_pos;
    struct iphdr* ipHeader = ip_hdr(skb);
    struct icmphdr* icmpHeader = icmp_hdr(skb);
    StateTableItem temp;
    memset(&temp, 0, sizeof(temp));

    isRequest = (icmpHeader->type == ICMP_REQUEST);
    temp.proto = ICMP, temp.state = icmpHeader->type;
    temp.core.foren_ip = ipHeader->daddr;
    temp.core.local_ip = ipHeader->saddr;
    // Make sure local ping foreign and foreign ping local are different
    /*   isIn    isRequest   foreignPort  localPort
     *    1          1            1           0  
     *    0          0            1           0
     *    1          0            0           1
     *    0          1            0           1
     */
    temp.core.fport = !(isIn ^ isRequest);
    temp.core.lport = (isIn ^ isRequest);

    if (isIn) { 
        SWAP_VALUE(temp.core.foren_ip, temp.core.local_ip);
    }


    exist_pos = statehashTable_exist(&temp);
    if (exist_pos) {
        retItemptr = &stateTable_entry(exist_pos)->st_item;
        retItemptr->expire = nowBysec() + ICMP_DELAY;
        printk("A ICMP CONNETION EXPIRED UPDATE TO %u", retItemptr->expire);
        return NF_ACCEPT;
    } else if(check_firewall_rules(skb)) {
        printk("PASS FIREWALL");
        if (temp.state == ICMP_REQUEST) {
            temp.expire = nowBysec() + ICMP_DELAY;
            printk("EXPIRED TIME %u", temp.expire);
            statehashTable_add(&temp);
        }
        return NF_ACCEPT;
    } else {
        return NF_DROP;
    }
}

static uint32_t check_udp_status(const struct sk_buff* skb, bool isIn) {
    StateTableItem* retItemptr;
    struct hlist_node* exist_pos;
    struct iphdr* ipHeader = ip_hdr(skb);
    struct udphdr* udpHeader = udp_hdr(skb);
    
    StateTableItem temp;
    memset(&temp, 0, sizeof(temp));
    temp.proto = UDP, temp.state = isIn;
    temp.core.foren_ip = ipHeader->daddr;
    temp.core.local_ip = ipHeader->saddr;
    temp.core.fport = htons(udpHeader->dest);
    temp.core.lport = htons(udpHeader->source);

    if (isIn) { 
        SWAP_VALUE(temp.core.foren_ip, temp.core.local_ip);
        SWAP_VALUE(temp.core.fport, temp.core.lport);
    }


    exist_pos = statehashTable_exist(&temp);
    if (exist_pos) {
        retItemptr = &stateTable_entry(exist_pos)->st_item;
        // equality means In/Out diections is the same
        // Can't Create a connection
        if (isIn == retItemptr->state) {
            ;
        }
        temp.expire = nowBysec() + UDP_DELAY;
        printk("UDP EXPIRED UPDATE TO %u", temp.expire);
        return NF_ACCEPT;
    } else if(check_firewall_rules(skb)) {
        printk("PASS FIREWALL");
        temp.expire = nowBysec() + UDP_DELAY;
        statehashTable_add(&temp);
        return NF_ACCEPT;
    } else {
        return NF_DROP;
    }
}

static uint32_t check_tcp_status(const struct sk_buff* skb, int8_t trans_buf[10][6], bool isIn) {
    int8_t stateTemp;
    StateTableItem* retItemptr;
    struct hlist_node* exist_pos;
    struct iphdr* ipHeader = ip_hdr(skb);
    struct tcphdr* tcpHeader = tcp_hdr(skb);
    
    StateTableItem temp;
    memset(&temp, 0, sizeof(temp));
    temp.proto = TCP, temp.state = get_TCP_sign(tcpHeader);
    temp.core.foren_ip = ipHeader->daddr;
    temp.core.local_ip = ipHeader->saddr;
    temp.core.fport = htons(tcpHeader->dest);
    temp.core.lport = htons(tcpHeader->source);

    if (isIn) { 
        SWAP_VALUE(temp.core.foren_ip, temp.core.local_ip);
        SWAP_VALUE(temp.core.fport, temp.core.lport);
    }
    

    exist_pos = statehashTable_exist(&temp);
    /* if (tcpHeader->fin) { */
    /*     printk("FIN PKT RECVED : NOW STATE %d", retItemptr->state); */
    /* } */
    if (exist_pos) {
        retItemptr = &stateTable_entry(exist_pos)->st_item;
        stateTemp = trans_buf[retItemptr->state][temp.state];
        // -1 means maintain old state
        if (stateTemp != -1) {
            if (stateTemp == CLOSED) {
                printk("CLOSED GET ONE <--> DELETE ONE FROM TABLE");
                statetable_node_del(exist_pos);
                /* statehashTable_del(retItemptr); */
            } else {
                temp.expire = nowBysec() + TCP_DELAY;
                printk("A TCP CONNETION UPDATE TO %u", temp.expire);
                if (retItemptr->state != stateTemp)
                    printk("STATE CHANGE from %d to %d", retItemptr->state, stateTemp);
                retItemptr->state = stateTemp;
            }
        } else {
            return NF_DROP;
        }
        return NF_ACCEPT;
    } else if(check_firewall_rules(skb)) {
        printk("PASS FIREWALL");
        temp.state = trans_buf[0][temp.state];
        printk("FIRST CATCH STATE : %d", temp.state);
        temp.expire = nowBysec() + TCP_DELAY;
        printk("A TCP CONNETION EXPIRED %u", temp.expire);
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
            return check_icmp_status(skb, true);
        case TCP:
            return check_tcp_status(skb, in_tcp_state_tranform_buf, true);
        case UDP:
            return check_udp_status(skb, true);
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
            return check_icmp_status(skb, false);
        case TCP:
            return check_tcp_status(skb, out_tcp_state_tranform_buf, false);
        case UDP:
            return check_udp_status(skb, false);
        default:
            return NF_ACCEPT;
            
    }
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
    RuleTableItem item = {
        .protocol = 0, .action = 1,
        .dst_port = 0, .src_port = 0,
        .dst_ip = 0, .src_ip = 0,
        .dst_cidr = 0, .dst_cidr = 0
    };

    nlsock = netlink_kernel_create(&init_net, USER_MSG, &cfg);
    if (NULL == nlsock) {
        printk("SOCK CREATE ERROR");
        return -1;
    }
    printk("SOCK CREATE SUCCESS");
    statehashTable_init();

    spin_lock_init(&stateHashTable_lock);

    startTimeStamp = nowBysec();
    
    ruleList_add(&item);
    ruleList_add(&item);
    
    return nf_register_net_hooks(&init_net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}

static void __net_exit test_netfilter_exit(void) {
    sock_release(nlsock->sk_socket);
    statehashTable_exit();
    ruleList_destory();
    nf_unregister_net_hooks(&init_net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}


module_init(test_netfilter_init);
module_exit(test_netfilter_exit);

MODULE_LICENSE("GPL");
