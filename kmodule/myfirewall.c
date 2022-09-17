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
#include <net/tcp.h>
#include <net/checksum.h>
#include <linux/sem.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/icmp.h>
#include "message.h"


struct netlink_kernel_cfg cfg = {
    .input = recvfromuser,
};

// Define TCP_STATUS (some States are combined or deleted)
enum TCP_STATUS { CLOSED = 1, LISTEN, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT, LAST_ACK  };
// Define TCP DATAPACKET SIGN
enum TCP_SIGN { SYN, SYNACK, ACK, RST, FIN, FINACK, UNDEFINED };
// Define UDP STATE
enum UDP_STATE { PREBUILD, BUILD };

static int8_t in_tcp_state_tranform_buf[10][6] = {
    { LISTEN, SYN_SENT, ESTABLISHED, CLOSED, ESTABLISHED, FIN_WAIT2 }, // FIRST RECV IN PKT, CHOOSE A STATE
    { -1, -1, -1, -1, -1, -1 },                             // CLOSED
    { LISTEN, -1, -1, CLOSED, -1, -1 },                     // LISTEN
    { -1, SYN_SENT, -1, CLOSED, -1, -1 },                   // SYN_SENT
    { -1, -1, ESTABLISHED, CLOSED, -1, -1 },                // SYN_RECV
    { -1, -1, ESTABLISHED, CLOSED, CLOSE_WAIT, CLOSE_WAIT },// ESTABLISHE
    { -1, -1, FIN_WAIT2, CLOSED, -1, CLOSED },              // FIN_WAIT1
    { -1, -1, -1, CLOSED, -1, CLOSED },                     // FIN_WAIT2
    { -1, -1, -1, CLOSED, -1, -1 },                         // CLOSE_WAIT
    { -1, -1, CLOSED, CLOSED, -1, -1 }                      // LAST_ACK
};

static int8_t out_tcp_state_tranform_buf[10][6] = {
    { SYN_SENT, SYN_RECV, ESTABLISHED, CLOSED, FIN_WAIT1, LAST_ACK }, // FIRST SEND OUT PKT, CHOOSE A STATE
    { -1, SYN_SENT, -1, -1, -1, -1 },                       // CLOSED
    { -1, SYN_RECV, -1, CLOSED, -1, -1 },                   // LISTEN
    { -1, -1, ESTABLISHED, CLOSED, -1, -1 },                // SYN_SENT
    { -1, -1, ESTABLISHED, CLOSED, -1, -1 },                // SYN_RECV
    { -1, -1, ESTABLISHED, CLOSED, FIN_WAIT1, FIN_WAIT1},   // ESTABLISHE
    { -1, -1, -1, CLOSED, -1, -1 },                         // FIN_WAIT1
    { -1, -1, CLOSED, CLOSED, -1, -1 },                     // FIN_WAIT2
    { -1, -1, -1, CLOSED, LAST_ACK, LAST_ACK },             // CLOSE_WAIT
    { -1, -1, -1, CLOSED, -1, -1 }                          // LAST_ACK
};

// Default Rule (if Rule List don't match)
bool default_rule = true;

spinlock_t stateHashTable_lock;
spinlock_t ruleList_lock;
spinlock_t natList_lock;
unsigned long lockflags;

struct sock* nlsock = NULL;

uint32_t startTimeStamp = 0;
uint32_t tot_rules = 0;
uint32_t tot_nats  = 0;
uint32_t tot_conns = 0;

char   logfilename[30];
struct file *logfile = NULL;
struct mutex mtx;
bool   isStop = false;
struct semaphore log_sem;
struct task_struct* log_task;

inline void logfile_init_name(void) {
    ktime_t t = UTC_BY_SEC;
    struct rtc_time tm;
    rtc_time_to_tm(t, &tm);
    sprintf(logfilename, "log/%04d-%02d-%02d.log", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

int log_func(void* d) {
    while (1) {
        if (down_interruptible(&log_sem) != -EINTR && !isStop) {
            if (!list_empty(&logmsglist)) {

                logmsglistNode *node = logmsgList_entry(logmsglist.next);
                
                /* printk("logMSG: %s", node->msg); */
                log_write(node->msg, strlen(node->msg));

                mutex_lock(&mtx);
                list_del(logmsglist.next);
                mutex_unlock(&mtx);

                kfree(node);
            }
        }
        if (isStop) { break; }
    }
    return 1;
}


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

static bool check_nat_tranform_in(struct sk_buff *skb) {
    natlistNode *p;
    struct list_head *pos, *n; 
    struct iphdr *ipHeader = ip_hdr(skb);
    struct tcphdr *tcpHeader = tcp_hdr(skb);
    uint32_t *ip_ptr   = (&ipHeader->daddr);
    uint16_t *port_ptr = (&tcpHeader->dest);
    uint32_t ip_val    = ntohl(*ip_ptr);
    uint16_t port_val  = ntohs(*port_ptr);
    uint16_t tot_len   = ntohs(ipHeader->tot_len);
    uint16_t iph_len   = ip_hdrlen(skb);


    list_for_each_safe(pos, n, &natlist) {
        p = natList_entry(pos);
        if (p->natitem.external_ip == ip_val && p->natitem.external_port == port_val) {
            printk("NAT IN TRANFORM");
            *ip_ptr = htonl(p->natitem.internal_ip);
            *port_ptr = htons(p->natitem.internal_port);
            tcpHeader->check = 0;
            skb->csum = csum_partial((uint8_t *)tcpHeader, tot_len-iph_len, 0);
            tcpHeader->check = csum_tcpudp_magic(ipHeader->saddr, ipHeader->daddr,
                    ntohs(ipHeader->tot_len) - iph_len, ipHeader->protocol, skb->csum);
            ipHeader->check = 0;
            ipHeader->check = ip_fast_csum(ipHeader, ipHeader->ihl);
            return 1;

        }
    }

    return 0;

}

static bool check_nat_tranform_out(struct sk_buff *skb) {
    uint8_t *page;
    uint32_t frag_len, frag_offset;
    natlistNode *p;
    struct list_head *pos, *n; 
    struct iphdr *ipHeader = ip_hdr(skb);
    struct tcphdr *tcpHeader = tcp_hdr(skb);
    struct skb_shared_info *info = skb_shinfo(skb);
    uint32_t *ip_ptr   = (&ipHeader->saddr);
    uint16_t *port_ptr = (&tcpHeader->source);
    uint32_t ip_val    = ntohl(*ip_ptr);
    uint16_t port_val  = ntohs(*port_ptr);
    uint16_t tot_len   = ntohs(ipHeader->tot_len);
    uint16_t tcp_len   = tot_len  - ipHeader->ihl * 4;
    uint32_t datalen   = skb->len - ipHeader->ihl * 4 - tcpHeader->doff * 4;
    uint32_t data_checksum = 0;
    /* struct tcphdr* tcph = (struct tcphdr *)((__u32 *)ipHeader + ipHeader->ihl); */

    /* for (; i < skb->len; i++) { */
    /*     [> unsigned char *user_data = (unsigned char *)((unsigned char *)tcph + (tcph->doff * 4)); <] */
    /*     printk("data[%d] %02x", i, ((uint8_t*)skb)[i]); */
    /* } */
    /* user_data[0] = 0xff; */
    
    list_for_each_safe(pos, n, &natlist) {
        p = natList_entry(pos);
        if (p->natitem.internal_ip == ip_val && p->natitem.internal_port == port_val) {
            printk("NAT OUT TRANFORM");
            *ip_ptr = htonl(p->natitem.external_ip);
            *port_ptr = htons(p->natitem.external_port);
            tcpHeader->check = 0;
            ipHeader->check = 0;
            ipHeader->check = ip_fast_csum(ipHeader, ipHeader->ihl);

            // METHOD 1 GET DATA BUT CHECK SUM ERROR DON'T KNOW WHY
            /* if (skb_is_nonlinear(skb)) */
            /*     skb_linearize(skb); */
            /* for (i = 0; i < datalen; i++) */
            /*     printk("%x", *((char*)skb->data + ipHeader->ihl * 4 + tcpHeader->doff * 4 + i)); */
            /* data_checksum = csum_partial((uint8_t*)skb->data + ipHeader->ihl*4 + tcpHeader->doff*4, datalen, 0); */
            
            // If need to calculate Data Checksum
            if (datalen > 0) {

                // Old Method -- Extract Data From Page
                printk("nr_flag %u", info->nr_frags);
                if (info->nr_frags) {

                    page = page_address(info->frags[0].bv_page);
                    frag_len = info->frags[0].bv_len;
                    frag_offset = info->frags[0].bv_offset;
                    printk("frag_len %u, frag_offset %u", frag_len, frag_offset);
                    data_checksum = csum_partial(page + frag_offset, frag_len, 0);
                }
            }
            /* printk("datalen %08x\ndata_checksum %08x", datalen, data_checksum); */
            tcpHeader->check = tcp_v4_check(tcp_len, ipHeader->saddr, ipHeader->daddr,
                    csum_partial(tcpHeader, tcp_len, data_checksum));
            skb->ip_summed = CHECKSUM_UNNECESSARY;
            skb->csum = offsetof(struct tcphdr, check);
            return 1;
        }
    }

    return 0;
}

static uint32_t check_icmp_status(const struct sk_buff *skb, bool isIn) {
    bool isRequest;
    StateTableItem* retItemptr;
    struct hlist_node* exist_pos;
    struct iphdr* ipHeader = ip_hdr(skb);
    struct icmphdr* icmpHeader = icmp_hdr(skb);
    StateTableItem temp;
    memset(&temp, 0, sizeof(temp));

    isRequest = (icmpHeader->type == ICMP_REQUEST);
    temp.proto = ICMP, temp.state = icmpHeader->type;
    temp.core.foren_ip = ntohl(ipHeader->daddr);
    temp.core.local_ip = ntohl(ipHeader->saddr);
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
    } else if(check_firewall_rules(&temp, isIn)) {
        if (temp.state == ICMP_REQUEST) {
            temp.expire = nowBysec() + ICMP_DELAY;
            printk("ICMP EXPIRED TIME %u", temp.expire);
            statehashTable_add(&temp);
        }
        return NF_ACCEPT;
    } else {
        LOG_WARN("FIREWALL DENY A ICMP PKT", NULL);
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
    temp.core.foren_ip = ntohl(ipHeader->daddr);
    temp.core.local_ip = ntohl(ipHeader->saddr);
    temp.core.fport    = ntohs(udpHeader->dest);
    temp.core.lport    = ntohs(udpHeader->source);

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
    } else if(check_firewall_rules(&temp, isIn)) {
        printk("PASS FIREWALL");
        temp.expire = nowBysec() + UDP_DELAY;
        statehashTable_add(&temp);
        return NF_ACCEPT;
    } else {
        LOG_WARN("FIREWALL DENY A UDP PKT", NULL);
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
    temp.core.foren_ip = ntohl(ipHeader->daddr);
    temp.core.local_ip = ntohl(ipHeader->saddr);
    temp.core.fport    = ntohs(tcpHeader->dest);
    temp.core.lport    = ntohs(tcpHeader->source);

    if (isIn) { 
        SWAP_VALUE(temp.core.foren_ip, temp.core.local_ip);
        SWAP_VALUE(temp.core.fport,    temp.core.lport);
    }

    /* log_write("TCP\n", 4); */
    exist_pos = statehashTable_exist(&temp);
    if (exist_pos) {
        retItemptr = &stateTable_entry(exist_pos)->st_item;
        stateTemp = trans_buf[retItemptr->state][temp.state];
        // -1 means maintain old state
        if (stateTemp != -1) {
            if (stateTemp == CLOSED) {
                statetable_node_del(exist_pos);
            } else {
                temp.expire = nowBysec() + TCP_DELAY;
                if (retItemptr->state != stateTemp)
                    printk("STATE CHANGE from %d to %d", retItemptr->state, stateTemp);
                retItemptr->state = stateTemp;
            }
        } else {
            LOG_WARN("Wrong TCP State %d Recv %d isIn: %d", retItemptr->state, temp.state, isIn);
            return NF_DROP;
        }
        return NF_ACCEPT;
    } else if(check_firewall_rules(&temp, isIn)) {
        printk("PASS FIREWALL");
        temp.state = trans_buf[0][temp.state];
        printk("FIRST CATCH STATE : %d", temp.state);
        temp.expire = nowBysec() + TCP_DELAY;
        printk("A TCP CONNETION EXPIRED %u", temp.expire);
        statehashTable_add(&temp);
        return NF_ACCEPT;
    } else {
        LOG_WARN("FIREWALL DENY A TCP PKT", NULL);
        return NF_DROP;
    }
    
    return NF_ACCEPT;
}



static uint32_t test_nf_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *ipheader = ip_hdr(skb);
    /* const struct tcphdr* tcpheader = tcp_hdr(skb); */
    /* printk("out name : %s", state->out->name); */
    /* printk("in  name : %s", state->in->name); */
    /* printk("Protocol %d", ipheader->protocol); */
    switch (ipheader->protocol) {
        case ICMP:
            return check_icmp_status(skb, true);
        case TCP:
            (check_nat_tranform_in(skb));
            return check_tcp_status(skb, in_tcp_state_tranform_buf, true);
        case UDP:
            (check_nat_tranform_in(skb));
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
    uint32_t ret;
    const struct iphdr *ipheader = ip_hdr(skb);
    switch (ipheader->protocol) {
        case ICMP:
            return check_icmp_status(skb, false);
        case TCP:
            ret = check_tcp_status(skb, out_tcp_state_tranform_buf, false);
            (check_nat_tranform_out(skb));
            return ret;
        case UDP:
            ret = check_udp_status(skb, false);
            (check_nat_tranform_out(skb));
            return ret;
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
    .priority = NF_IP_PRI_LAST,
  },
};

static int __net_init test_netfilter_init(void) {

    logfile_init_name();

    logfile = filp_open(logfilename, O_WRONLY|O_CREAT|O_APPEND, S_IROTH|S_IRGRP|S_IRUSR|S_IWUSR);
    if (IS_ERR(logfile)) printk("create file error");

    nlsock = netlink_kernel_create(&init_net, USER_MSG, &cfg);
    if (NULL == nlsock) {
        printk("SOCK CREATE ERROR");
        LOG_ERROR("NETLINK SOCK CREATE FAILED", NULL);
        return -1;
    }
    printk("SOCK CREATE SUCCESS");
    statehashTable_init();

    spin_lock_init(&stateHashTable_lock);
    spin_lock_init(&natList_lock);
    spin_lock_init(&ruleList_lock);
    sema_init(&log_sem, 0);
    log_task = kthread_run(log_func, NULL, "LOG");
    startTimeStamp = nowBysec();

    mutex_init(&mtx);

    return nf_register_net_hooks(&init_net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}

static void __net_exit test_netfilter_exit(void) {

    if (logfile != NULL) {
        filp_close(logfile, NULL);
    }
    sock_release(nlsock->sk_socket);
    statehashTable_destory();
    ruleList_destory();
    natList_destory();
    logmsgList_destory();

    isStop = true;
    up(&log_sem);
    kthread_stop(log_task);
    nf_unregister_net_hooks(&init_net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}


module_init(test_netfilter_init);
module_exit(test_netfilter_exit);

MODULE_LICENSE("GPL");
