#ifndef PARSER_HPP
#define PARSER_HPP

#include <iostream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <sys/types.h>
#include <cstring>
#include "../kmodule/sharedstruct.h"

class Parser {
    public:
        virtual void ParseMsg(const void* data, uint32_t len) = 0;
        virtual ~Parser() {  }

    protected:
        std::string ip2str(uint32_t ip) {
            char msg[18] = { 0 };
            int tot = sprintf(msg, "%u.%u.%u.%u",
                    (ip>>24), ((ip>>16)&0xff), (ip>>8)&0xff, (ip&0xff));
            return std::string(msg, tot);
        }
};

class NoParser: public Parser {
    public:
        virtual void ParseMsg(const void *data, uint32_t len) override {  }
};

class TextParser : public Parser {
    public:
        virtual void ParseMsg(const void *data, uint32_t len) override {
            write(1, data, len);
        }
};

class NatItemParser: public Parser {
    public:
        virtual void ParseMsg(const void *data, uint32_t len) override {
            NatTableItem item;
            uint32_t nums = len / natItemlen;
            if (nums == 0) { printf("No nats\n");return; }
            printf("ALL Nats: %u\n", nums);
            for (uint32_t idx = 0; idx < len; idx+=natItemlen) {
                memcpy(&item, ((uint8_t*)data) + idx, natItemlen);
                printf("num: %u\n", idx/natItemlen);
                printf("Internal: %s:%u <--> External: %s:%u\n", ip2str(item.internal_ip).c_str(), item.internal_port, 
                                ip2str(item.external_ip).c_str(), item.external_port);
            }
        }
};

class RuleItemParser : public Parser {
    public:
        virtual void ParseMsg(const void *data, uint32_t len) override {
            RuleTableItem item;
            uint32_t nums = len / ruleItemlen;
            if (nums == 0) { printf("No Rules\n");return; }
            printf("ALL Rules: %u\n", nums);
            for (uint32_t idx = 0; idx < len; idx+=ruleItemlen) {
                memcpy(&item, ((uint8_t*)data) + idx, ruleItemlen);
                printf("num: %u\n", idx/ruleItemlen);
                printf("Src: %s/%d:%u, Dst: %s/%d:%u ", ip2str(item.src_ip).c_str(), item.src_cidr, item.src_port,
                                                    ip2str(item.dst_ip).c_str(), item.dst_cidr, item.dst_port);
                printf("Protocol: %s, Action: %s\n", proto_str[item.protocol], rule_str[item.action]);
            }
        }
};

class ConnectionParser: public Parser {
    public:
        virtual void ParseMsg(const void *data, uint32_t len) override {
            StateTableItem item;
            uint32_t nums = len / stateItemlen;
            if (nums == 0) { printf("No Connections\n");return; }
            printf("ALL Conns: %u\n", nums);
            for (uint32_t idx = 0; idx < len; idx+=stateItemlen) {
                memcpy(&item, ((uint8_t*)data) + idx, stateItemlen);
                if (item.expire == 0) { continue; }
                printf("num: %u\n", idx / stateItemlen);
                printf("Foreign: %s:%u, Local: %s:%u ", ip2str(item.core.foren_ip).c_str(), item.core.fport,
                        ip2str(item.core.local_ip).c_str(), item.core.lport);
                printf("Protocol: %s, Expired: %u\n", proto_str[item.proto], item.expire);
            }
        }
};

#endif
