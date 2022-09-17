#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <cassert>
#include "config.h"
#include "message.h"
 
#define MSG_LEN 100
#define MAX_PLOAD 100
 
 
int main(int argc, char *argv[])
{
    RuleFile rf;

    KernelLink k(new NoParser);
    CmdManager cmgr;
    msg_send_format<std::max(ruleItemlen, natItemlen)> send_data;
    cmgr.parseUserOptions(argc, argv);
    send_data.type = cmgr.getOptType();

    RuleTableItem rtemp;
    NatTableItem  ntemp;
    if (send_data.type == RULE_ADD) {
        rtemp = cmgr.generateRuleItem();
        memcpy(send_data.data, &rtemp, ruleItemlen);
    } else if (send_data.type == NAT_ADD) {
        ntemp = cmgr.generateNatItem();
        memcpy(send_data.data, &ntemp, natItemlen);
    }

    switch (send_data.type) {
        case RULE_ADD:
            printf("ADD RULE\n");
            k.sendMsgtoKernel(&send_data, ruleItemlen + 1);
            printf("If append to this rule to file [Y/N]\n");
            if (getchar() == 'Y') rf.writeRuletoFile(rtemp);
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
        case RULE_INIT:
            send_data.type = RULE_ADD;
            for (auto&& item : rf.parseFile()) {
                memcpy(send_data.data, &item, ruleItemlen);
                k.sendMsgtoKernel(&send_data, ruleItemlen + 1);
            }
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
