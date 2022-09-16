#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <cassert>
#include "message.hpp"
 
#define MSG_LEN 100
#define MAX_PLOAD 100
 
 
int main(int argc, char *argv[])
{
    const char *data = "\0hello This is User NoAlign";
    KernelLink k(new NoParser);
    CmdManager cmgr;
    msg_send_format<std::max(ruleItemlen, natItemlen)> send_data;
    cmgr.parseUserOptions(argc, argv);
    send_data.type = cmgr.getOptType();
    // std::cout << cmgr.getOptType() << std::endl;
    // RuleTableItem temp = {
    //     .src_ip = 0,
    //     .dst_ip = 0,
    //     .src_port = 1234,
    //     .dst_port = 5678,
    //     .src_cidr = 0,
    //     .dst_cidr = 0,
    //     .protocol = 0,
    //     .action = 1,
    // };
    // NatTableItem tmp = {
    //     .internal_ip = 3232274579,
    //     .external_ip = 3232274579,
    //     .internal_port = 8888,
    //     .external_port = 4444
    // };

    if (send_data.type == RULE_ADD) {
        RuleTableItem temp = cmgr.generateRuleItem();
        memcpy(send_data.data, &temp, ruleItemlen);
    } else if (send_data.type == NAT_ADD) {
        NatTableItem temp = cmgr.generateNatItem();
        memcpy(send_data.data, &temp, natItemlen);
    }

    switch (send_data.type) {
        case RULE_ADD:
            printf("ADD RULE\n");
            k.sendMsgtoKernel(&send_data, ruleItemlen + 1);
            break;
        case RULE_SHOW:
            printf("RULE_SHOW\n");
            k.changeParser(new RuleItemParser);
            k.sendMsgtoKernel(&send_data, 1);
            k.recvMsgfromKernel();
            break;
        case RULE_DEL:
            printf("RULE DEL\n");
            send_data.data[0] = cmgr.getIdnum();
            k.sendMsgtoKernel(&send_data, 2);
            break;
        case NAT_ADD:
            printf("NAT ADD\n");
            k.sendMsgtoKernel(&send_data, natItemlen + 1);
            break;
        case NAT_SHOW:
            printf("NAT_SHOW\n");
            k.changeParser(new NatItemParser);
            k.sendMsgtoKernel(&send_data, 1);
            k.recvMsgfromKernel();
            break;
        case NAT_DEL:
            printf("NAT_DEL\n");
            send_data.data[0] = cmgr.getIdnum();
            k.sendMsgtoKernel(&send_data, 2);
            break;
        case CONNETION_SHOW:
            printf("CONNETION_SHOW\n");
            k.changeParser(new ConnectionParser);
            k.sendMsgtoKernel(&send_data, 1);
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
