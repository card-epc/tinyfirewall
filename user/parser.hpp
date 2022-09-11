#ifndef PARSER_HPP
#define PARSER_HPP

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <cstring>
#include "../kmodule/sharedstruct.h"

class Parser {
    public:
        virtual void ParseMsg(const void* data, uint32_t len) = 0;
        virtual ~Parser() {  }
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
                printf("Internal ip: %u, External ip: %u\n", item.internal_ip, item.external_ip);
                printf("Internal port: %u, External port: %u\n", item.intelnal_port, item.external_port);
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
                printf("Src ip: %u, Dst ip: %u\n", item.src_ip, item.dst_ip);
                printf("Src port: %u, Dst port: %u\n", item.src_port, item.dst_port);
                printf("src cidr: %u, Dst cidr: %u\n", item.src_cidr, item.dst_cidr);
                printf("protocol: %u, Action: %u\n", item.protocol, item.action);
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
                printf("num: %u\n", idx / stateItemlen);
                printf("Foreign ip: %u, Local ip: %u\n", item.core.foren_ip, item.core.local_ip);
                printf("Foreign port: %u, Local port: %u\n", item.core.fport, item.core.lport);
                printf("Protocol: %u, Expired: %u\n", item.proto, item.expire);
            }
        }
};

#endif
