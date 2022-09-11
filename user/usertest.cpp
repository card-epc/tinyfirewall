#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <cassert>
#include "message.hpp"
 
#define MSG_LEN 100
#define MAX_PLOAD 100
 
 
int main(int argc, char **argv)
{
    const char *data = "\0hello This is User NoAlign";
    msg_send_format<ruleItemlen> n_rule;
    n_rule.type = RULE_ADD;
    RuleTableItem temp = {
        .src_ip = 0,
        .dst_ip = 0,
        .src_port = 1234,
        .dst_port = 5678,
        .src_cidr = 0,
        .dst_cidr = 0,
        .protocol = 0,
        .action = 1,
    };
    memcpy(n_rule.data, &temp, ruleItemlen);
    KernelLink k(new ConnectionParser);
    k.sendMsgtoKernel(&n_rule, sizeof(n_rule));
    n_rule.type = CONNETION_SHOW;
    k.sendMsgtoKernel(&n_rule, 1);
    k.recvMsgfromKernel();
    return 0;

}
