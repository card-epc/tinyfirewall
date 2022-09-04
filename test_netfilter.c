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
#include <uapi/linux/netlink.h>
#include <linux/in_route.h>
#include <net/ip.h>

#define USER_MSG  24
#define USER_PORT 50

static struct sock* nlsock = NULL;

static int sendtouser(const char* buf, uint32_t len) {

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

void printIPaddr(uint32_t ipaddr) {
    printk("%d.%d.%d.%d", *((uint8_t*)(&ipaddr) + 0), *((uint8_t*)(&ipaddr) + 1),
                          *((uint8_t*)(&ipaddr) + 2), *((uint8_t*)(&ipaddr) + 3));
}


static unsigned int test_nf_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    const struct iphdr *ipheader = ip_hdr(skb);
    printk("this is test_nf_pre_routing 111");
    printk("out name : %s", state->out->name);
    printk("in  name : %s", state->in->name);
    uint32_t sip = ipheader->saddr;
    uint32_t dip = ipheader->daddr;
    printIPaddr(sip);
    printIPaddr(dip);
    printk("Protocol %d", ipheader->protocol);
    /* return NF_DROP; */
    return NF_ACCEPT;
}


static unsigned int test_nf_post_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    printk("this is test_nf_local_output 666");
    printk("out name : %s", state->out->name);
    printk("in  name : %s", state->in->name);
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

static int __net_init test_netfilter_init(struct net *net) {
    nlsock = netlink_kernel_create(&init_net, USER_MSG, &cfg);
    if (NULL == nlsock) {
        printk("SOCK CREATE ERROR");
        return -1;
    }
    return nf_register_net_hooks(net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}

static void __net_exit test_netfilter_exit(struct net *net) {
    sock_release(nlsock->sk_socket);
    nf_unregister_net_hooks(net, test_nf_ops, ARRAY_SIZE(test_nf_ops));
}

static struct pernet_operations test_netfilter_ops = {
    .init = test_netfilter_init,
    .exit = test_netfilter_exit,
};

static int __init test_module_init(void) {
    return register_pernet_subsys(&test_netfilter_ops);  
}

static void __exit test_module_exit(void) {
    unregister_pernet_subsys(&test_netfilter_ops);  
}

module_init(test_module_init);
module_exit(test_module_exit);

MODULE_LICENSE("GPL");
