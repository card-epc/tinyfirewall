#ifndef COMMON_H
#define COMMON_H

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


#endif /* ifndef COMMON_H */
