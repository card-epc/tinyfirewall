#ifndef __MESSAGE_H
#define __MESSAGE_H

#include <linux/printk.h>
#include <linux/xxhash.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/ktime.h>


extern uint32_t startTimeStamp;

#define ICMP  1
#define TCP   6
#define UDP  17

#define ICMP_REPLY   0
#define ICMP_REQUEST 8

#define ICMP_DELAY 20
#define  UDP_DELAY 30
#define  TCP_DELAY 60


#define GETMASK(cidr) (((cidr) >= 32) ? (0xffffffff) : ( (1<<(cidr)) - 1))
#define SWAP_VALUE(a, b) \
    { static_assert(__same_type(a, b), "Different Type");typeof(a) _tempc_ = (a); (a) = (b); (b) = _tempc_; }


typedef struct {
    uint32_t foren_ip;
    uint32_t local_ip;
    uint16_t fport;
    uint16_t lport;
} coreMsg;

typedef struct {
    uint8_t  proto;
    uint8_t  state;
    coreMsg  core;
    uint32_t expire;
} StateTableItem;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  src_cidr;
    uint8_t  dst_cidr;
    uint8_t  protocol;
    uint8_t  action;
} RuleTableItem;

typedef struct {
    RuleTableItem ruleitem;
    struct list_head listnode;
} rulelistNode;

typedef struct {
    StateTableItem st_item;
    struct hlist_node hlistNode;
} st_hashlistNode;

const uint32_t corelen = sizeof(coreMsg);
const uint32_t itemlen = sizeof(StateTableItem);
const uint32_t hashseed = 0xabcd1234;

enum TCP_STATUS { CLOSED = 1, LISTEN, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT, LAST_ACK  };
enum TCP_SIGN { SYN, SYNACK, ACK, RST, FIN, FINACK, UNDEFINED };
enum UDP_STATE { PREBUILD, BUILD };

// static int8_t first_in_tcp_state[6] = { LISTEN, SYN_SENT, ESTABLISHED, CLOSED, ESTABLISHED, FIN_WAIT2 };

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










inline uint32_t nowBysec(void) {
    ktime_t t = ktime_to_us(ktime_get());
    return t / USEC_PER_SEC - startTimeStamp;
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
