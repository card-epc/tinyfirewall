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
    KernelLink k(new NoParser);
    msg_send_format<ruleItemlen> n_rule;
    msg_send_format<natItemlen>  n_nat;
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
    NatTableItem tmp = {
        .internal_ip = 11111111,
        .external_ip = 22222222,
        .intelnal_port = 3333,
        .external_port = 4444
    };
    memcpy(n_rule.data, &temp, ruleItemlen);
    memcpy(n_nat.data, &tmp, natItemlen);

    assert(argc == 2);
    int param = atoi(argv[1]);
    switch (param) {
        case RULE_ADD:
            printf("ADD RULE\n");
            n_rule.type = RULE_ADD;
            k.sendMsgtoKernel(&n_rule, sizeof(n_rule));
            break;
        case RULE_SHOW:
            printf("RULE_SHOW\n");
            k.changeParser(new RuleItemParser);
            n_rule.type = RULE_SHOW;
            k.sendMsgtoKernel(&n_rule, 1);
            k.recvMsgfromKernel();
            break;
        case RULE_DEL:
            printf("RULE DEL\n");
            n_rule.type = RULE_DEL;
            n_rule.data[0] = 0;
            k.sendMsgtoKernel(&n_rule, 2);
            break;
        case NAT_ADD:
            printf("NAT ADD\n");
            n_nat.type = NAT_ADD;
            k.sendMsgtoKernel(&n_nat, sizeof(n_nat));
            break;
        case NAT_SHOW:
            printf("NAT_SHOW\n");
            k.changeParser(new NatItemParser);
            n_nat.type = NAT_SHOW;
            k.sendMsgtoKernel(&n_nat, 1);
            k.recvMsgfromKernel();
            break;
        case NAT_DEL:
            printf("NAT_DEL\n");
            n_nat.type = NAT_DEL;
            n_nat.data[0] = 0;
            k.sendMsgtoKernel(&n_nat, 2);
            break;
        case CONNETION_SHOW:
            printf("CONNETION_SHOW\n");
            k.changeParser(new ConnectionParser);
            n_nat.type = CONNETION_SHOW;
            k.sendMsgtoKernel(&n_nat, 1);
            k.recvMsgfromKernel();
            break;
        case LOG:
            printf("LOG\n");
            break;
        default:
            printf("DEFAULT\n");
            break;
            
    }
    // KernelLink k(new ConnectionParser);
    // k.sendMsgtoKernel(&n_rule, sizeof(n_rule));
    // n_rule.type = CONNETION_SHOW;
    // k.sendMsgtoKernel(&n_rule, 1);
    // k.recvMsgfromKernel();
    return 0;

}
