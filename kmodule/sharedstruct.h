#ifndef COMMON_H
#define COMMON_H

#define USER_MSG     24
#define NETLINK_USER 24
#define STATIC_PORT  50

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

enum MSG_TYPE 
{ 
    RULE_ADD = 1, 
    RULE_SHOW, 
    RULE_DEL, 
    NAT_ADD, 
    NAT_SHOW, 
    NAT_DEL,
    CONNETION_SHOW, 
    LOG,
    RULE_INIT
};

typedef struct {
    uint32_t foren_ip;
    uint32_t local_ip;
    uint16_t fport;
    uint16_t lport;
} coreMsg;

typedef struct {
    uint32_t internal_ip;
    uint32_t external_ip;
    uint16_t internal_port;
    uint16_t external_port;
} NatTableItem;

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

const uint32_t corelen = sizeof(coreMsg);
const uint32_t natItemlen = sizeof(NatTableItem);
const uint32_t ruleItemlen = sizeof(RuleTableItem);
const uint32_t stateItemlen = sizeof(StateTableItem);

const char* proto_str[20] = { "ANY", "ICMP", "","","","","TCP","","","","","","","","","","","UDP"};
const char* rule_str[2] = { "DENY", "ACCEPT" };

#endif /* ifndef COMMON_H */
