#ifndef __MESSAGE_H
#define __MESSAGE_H

#include <linux/printk.h>
#include <linux/xxhash.h>
#include <linux/ip.h>
#include <net/ip.h>

typedef struct coreMsg {
    uint32_t foren_ip;
    uint32_t local_ip;
    uint16_t fport;
    uint16_t lport;
} coreMsg;

typedef struct StatusTableItem {
    uint8_t  proto;
    uint8_t  state;
    coreMsg  iport;
} StatusTableItem;

typedef struct {
    StatusTableItem st_item;
    struct hlist_node hlistNode;
} st_hashlistNode;

const uint32_t corelen = sizeof(coreMsg);
const uint32_t itemlen = sizeof(StatusTableItem);
const uint32_t hashseed = 0xabcd1234;

enum TCP_STATUS { CLOSED = 1, LISTEN, SYN_SENT, SYN_RECV, ESTABLISHED, FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT, LAST_ACK  };
enum TCP_SIGN { SYN, SYNACK, ACK, RST, FIN, FINACK, UNDEFINED };

// static int8_t first_in_tcp_state[6] = { LISTEN, SYN_SENT, ESTABLISHED, CLOSED, ESTABLISHED, FIN_WAIT2 };

static int8_t in_tcp_state_tranform_buf[10][6] = {
    { LISTEN, SYN_SENT, ESTABLISHED, CLOSED, ESTABLISHED, FIN_WAIT2 }, // FIRST RECV IN PKT, CHOOSE A STATE
    { -1, -1, -1, -1, -1, -1 },                     // CLOSED
    { -1, -1, -1, CLOSED, -1, -1 },                 // LISTEN
    { -1, -1, -1, CLOSED, -1, -1 },                 // SYN_SENT
    { -1, -1, ESTABLISHED, CLOSED, -1, -1 },        // SYN_RECV
    { -1, -1, -1, CLOSED, CLOSE_WAIT, CLOSE_WAIT }, // ESTABLISHE
    { -1, -1, FIN_WAIT2, CLOSED, -1, CLOSED },      // FIN_WAIT1
    { -1, -1, -1, CLOSED, -1, -1 },                 // FIN_WAIT2
    { -1, -1, -1, CLOSED, -1, -1 },                 // CLOSE_WAIT
    { -1, -1, CLOSED, CLOSED, -1, -1 }              // LAST_ACK
};

static int8_t out_tcp_state_tranform_buf[10][6] = {
    { SYN_SENT, SYN_RECV, ESTABLISHED, CLOSED, FIN_WAIT1, LAST_ACK }, // FIRST SEND OUT PKT, CHOOSE A STATE
    { -1, SYN_SENT, -1, -1, -1, -1 },                       // CLOSED
    { -1, SYN_RECV, -1, CLOSED, -1, -1 },                   // LISTEN
    { -1, -1, ESTABLISHED, CLOSED, -1, -1 },                // SYN_SENT
    { -1, -1, ESTABLISHED, CLOSED, -1, -1 },                // SYN_RECV
    { -1, -1, -1, CLOSED, FIN_WAIT1, FIN_WAIT1},            // ESTABLISHE
    { -1, -1, -1, CLOSED, -1, -1 },                         // FIN_WAIT1
    { -1, -1, CLOSED, CLOSED, -1, -1 },                     // FIN_WAIT2
    { -1, -1, -1, CLOSED, LAST_ACK, LAST_ACK },             // CLOSE_WAIT
    { -1, -1, -1, CLOSED, -1, -1 }                          // LAST_ACK
};

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

void printCoreMsg(const StatusTableItem* citem) {
    uint32_t fipaddr = citem->iport.foren_ip;
    uint32_t lipaddr = citem->iport.local_ip;
    printk("forei IP: %d.%d.%d.%d", *((uint8_t*)(&fipaddr) + 0), *((uint8_t*)(&fipaddr) + 1),
                          *((uint8_t*)(&fipaddr) + 2), *((uint8_t*)(&fipaddr) + 3));
    printk("local IP: %d.%d.%d.%d", *((uint8_t*)(&lipaddr) + 0), *((uint8_t*)(&lipaddr) + 1),
                          *((uint8_t*)(&lipaddr) + 2), *((uint8_t*)(&lipaddr) + 3));
    printk("forei Port: %hu", (citem->iport.fport));
    printk("local Port: %hu", (citem->iport.lport));
    printk("proto: %u, state: %u", citem->proto, citem->state);
}

// uint32_t murMurHash(const void *key, uint32_t len)
// {
//         const unsigned int m = 0x5bd1e995;
//         const int r = 24;
//         const int seed = 97;
//         unsigned int h = seed ^ len;
//         // Mix 4 bytes at a time into the hash
//         const unsigned char *data = (const unsigned char *)key;
//         while(len >= 4)
//         {
//             unsigned int k = *(unsigned int *)data;
//             k *= m;
//             k ^= k >> r;
//             k *= m;
//             h *= m;
//             h ^= k;
//             data += 4;
//             len -= 4;
//         }
//         // Handle the last few bytes of the input array
//         switch(len)
//         {
//             case 3: h ^= data[2] << 16;
//             case 2: h ^= data[1] << 8;
//             case 1: h ^= data[0];
//             h *= m;
//         };
//         // Do a few final mixes of the hash to ensure the last few
//         // bytes are well-incorporated.
//         h ^= h >> 13;
//         h *= m;
//         h ^= h >> 15;
//         return (h);
// }

#endif
