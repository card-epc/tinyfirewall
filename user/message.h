#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <cassert>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <charconv>
#include <getopt.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "parser.h"
#include "kmodule/sharedstruct.h"

template<uint32_t datalen>
struct msg_send_format {
    uint8_t  type;
    uint8_t  data[datalen];
};
 
template<uint32_t datalen = 4096>
struct msg_recv_format {
    struct nlmsghdr nlh;
    uint8_t data[datalen];
};

const char *single_option = "l:d:a:p:hi";
static struct option long_options[] =
{  
    {"list",     required_argument, NULL, 'l'},
    {"delete",   required_argument, NULL, 'd'},
    {"append",   required_argument, NULL, 'a'},
    {"protocol", required_argument, NULL, 'p'},
    {"help",     no_argument,       NULL, 'h'},
    {"action",   required_argument, NULL, '0'},
    {"sip",      required_argument, NULL, '1'},
    {"dip",      required_argument, NULL, '2'},
    {"sport",    required_argument, NULL, '3'},
    {"dport",    required_argument, NULL, '4'},
    {"scidr",    required_argument, NULL, '5'},
    {"dcidr",    required_argument, NULL, '6'},
    {"id",       required_argument, NULL, '7'},
    {"init",     no_argument,       NULL, 'i'},
    {NULL,       no_argument,       NULL,  0 },
}; 

class KernelLink {
    public:

        explicit KernelLink(Parser* parser_ptr) : parser_(parser_ptr) { init(); }
        virtual ~KernelLink() { close(skfd_); }
        KernelLink(const KernelLink& k) = delete;
        KernelLink(const KernelLink&& k) = delete;
        KernelLink& operator=(const KernelLink& k) = delete;

        void changeParser(Parser* newparser);
        void sendMsgtoKernel(const void *data, uint32_t len);
        void recvMsgfromKernel();

    private:
        void init ();
        int skfd_;
        struct sockaddr_nl  localaddr_;
        struct sockaddr_nl kerneladdr_;
        std::unique_ptr<Parser> parser_;
};

class CmdManager final {

    public:

        void parseUserOptions(int argc, char *argv[]);
        void printUsage();
        RuleTableItem generateRuleItem();
        NatTableItem  generateNatItem();
        uint8_t getIdnum() { return idnum_; }
        uint8_t getOptType() { 
            if (type_ == 0) {
                std::cerr << "\033[32mDON'T GET OPT TYPE\033[0m" << std::endl;
                exit(0); 
            } else {
                return type_;
            }
        }
    private:
        bool checkIfIpSet();
        bool checkIfPortSet();
        uint32_t str2ip(const char* str);

        void setIdnum(const char* str) { idnum_ = atoi(str); }
        void setScidr(const char* str) { scidr_ = atoi(str); }
        void setDcidr(const char* str) { dcidr_ = atoi(str); }
        void setSport(const char* str) { sport_ = atoi(str); }
        void setDport(const char* str) { dport_ = atoi(str); }
        void setSrcip(const char* str) { srcip_ = str2ip(str); }
        void setDstip(const char* str) { dstip_ = str2ip(str); }
        void setAction(const char* str) { action_ = atoi(str); }
        void setProtocol(const char* str) { protocol_ = atoi(str); }
        void setOptType(int opt, const char* str);

        int     type_ = 0;
        bool  action_ = 0;
        uint8_t  scidr_ = 32, dcidr_ = 32, protocol_ = 0;
        uint16_t sport_ =  0, dport_ =  0;
        uint32_t srcip_ = -1, dstip_ = -1, idnum_ = -1;
};

void KernelLink::init() {

    skfd_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (skfd_ == -1) {
        printf("Create Socket Error %s\n", strerror(errno));
        exit(-1);
    }

    memset(&localaddr_, 0, sizeof(localaddr_));
    memset(&kerneladdr_, 0, sizeof(kerneladdr_));

    localaddr_.nl_family = kerneladdr_.nl_family = AF_NETLINK;
    localaddr_.nl_groups = kerneladdr_.nl_groups = 0;
    localaddr_.nl_pid  = STATIC_PORT;
    kerneladdr_.nl_pid = 0;

    if (bind(skfd_, (struct sockaddr*)&localaddr_, sizeof(localaddr_)) != 0) {
        printf("bind Error %s\n", strerror(errno));
        close(skfd_);
        exit(-1);
    }

}

void KernelLink::changeParser(Parser *newparser) {
    this->parser_.reset(newparser);
}

void KernelLink::sendMsgtoKernel(const void *data, uint32_t len) {

    struct nlmsghdr* nlh;
    // const char *data = "Hello This is User";
    nlh = (struct nlmsghdr *)malloc(NLMSG_LENGTH(len));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_LENGTH(len);
    printf("len %u and nlmsg_len %u\n", len, nlh->nlmsg_len);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = localaddr_.nl_pid; //self port
 
    memcpy(NLMSG_DATA(nlh), data, len);

    int ret = sendto(skfd_, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&kerneladdr_, sizeof(struct sockaddr_nl));
    if(!ret) {
        perror("sendto error1\n");
        close(skfd_);
        exit(-1);
    }

    free(nlh);
}

void KernelLink::recvMsgfromKernel() {
    uint32_t ret, var;
    msg_recv_format<> info;
    ret = recvfrom(skfd_, &info, sizeof(info), 0, (struct sockaddr *)&kerneladdr_, &var);
    printf("Recv %d bytes\n", ret - NLMSG_HDRLEN);
    parser_->ParseMsg(info.data, ret - NLMSG_HDRLEN);
    // printf("RecvMsg %u\n", *info.data);
}

bool CmdManager::checkIfIpSet() {
    bool ret = true;
    if (srcip_ == -1) {
        std::cerr << "src ip is not set, exit" << std::endl;
        ret = false;
    }
    if (dstip_ == -1) {
        std::cerr << "dst ip is not set, exit" << std::endl;
        ret = false;
    }
    return ret;
}

bool CmdManager::checkIfPortSet() {
    bool ret = true;
    if (sport_ == 0) {
        std::cerr << "src port is not set, exit" << std::endl;
        ret = false;
    }
    if (dport_ == 0) {
        std::cerr << "dst port is not set, exit" << std::endl;
        ret = false;
    }
    return ret;
}
void CmdManager::setOptType(int opt, const char* str) {
    std::string_view args(str);
    if (args == "nat" || args == "NAT") {
        type_ = opt + 3;
    } else if (args == "RULE" || args == "rule") {
        type_ = opt;
    } else if (args == "CONN" || args == "conn") {
        type_ = (opt == 2) ? CONNETION_SHOW : 0;
    } else if (args == "i") {
        type_ = RULE_INIT;
    }
}

uint32_t CmdManager::str2ip(const char* ip_str) {
    std::string_view ipview(ip_str);
    int p1 = ipview.find_first_of('.') + 1;
	int p2 = ipview.find_first_of('.', p1) + 1;
	int p3 = ipview.find_first_of('.', p2) + 1;
	assert( p1 && p2 && p3 );
	uint8_t val1, val2, val3, val4;
    if (std::from_chars(ipview.data(), ipview.data() + 3, val1).ec == std::errc() &&
        std::from_chars(ipview.data()+p1, ipview.data()+p1 + 3, val2).ec == std::errc() &&
        std::from_chars(ipview.data()+p2, ipview.data()+p2 + 3, val3).ec == std::errc() &&
        std::from_chars(ipview.data()+p3, ipview.data()+p3 + 3, val4).ec == std::errc()) {
        // auto change to uint32_t
        return ((val1<<24) | (val2<<16) | (val3<<8) | val4);
    } else {
        std::cerr << "str2ip Error" << std::endl;
        return 0;
    }
}

void CmdManager::parseUserOptions(int argc, char *argv[]) {

    int opt, option_index;
    while((opt = getopt_long_only(argc, argv, single_option, long_options, &option_index))!= -1)
    {  
        switch (opt) {
            case 'a':
                printf("addarg = %s\n",optarg);
                setOptType(1, optarg);
                break;
            case 'l':
                printf("listarg = %s\n",optarg);
                setOptType(2, optarg);
                break;
            case 'd':
                printf("delarg = %s\n",optarg);
                setOptType(3, optarg);
                break;
            case 'p':
                printf("protocol = %s\n",optarg);
                setProtocol(optarg);
                break;
            case '0':
                printf("action = %s\n",optarg);
                setAction(optarg);
                break;
            case '1':
                printf("srcip = %s\n",optarg);
                setSrcip(optarg);
                break;
            case '2':
                printf("dstip = %s\n",optarg);
                setDstip(optarg);
                break;
            case '3':
                printf("sport = %s\n",optarg);
                setSport(optarg);
                break;
            case '4':
                printf("dport = %s\n",optarg);
                setDport(optarg);
                break;
            case '5':
                printf("scidr = %s\n",optarg);
                setScidr(optarg);
                break;
            case '6':
                printf("dcidr = %s\n",optarg);
                setDcidr(optarg);
                break;
            case '7':
                printf("id = %s\n", optarg);
                setIdnum(optarg);
                break;
            case 'h':
                printUsage();
                _exit(0);
            case 'i':
                setOptType(0, "i");
                break;
            case '?':
                printUsage();
                _exit(0);
            default:
                break;
                
        }
    }  
}

RuleTableItem CmdManager::generateRuleItem() {
    RuleTableItem item;
    item.protocol = protocol_;
    item.src_cidr = scidr_;
    item.dst_cidr = dcidr_;
    item.action = action_;
    item.src_port = sport_;
    item.dst_port = dport_;
    if (checkIfIpSet()) {
        item.src_ip = srcip_;
        item.dst_ip = dstip_;
    } else {
        exit(0);
    }
    return item;
}

NatTableItem CmdManager::generateNatItem() {
    NatTableItem item;
    if (checkIfIpSet() && checkIfPortSet()) {
        item.internal_ip = srcip_;
        item.external_ip = dstip_;
        item.internal_port = sport_;
        item.external_port = dport_;
    } else {
        exit(0);
    }
    return item;
}

void CmdManager::printUsage() {

    printf( "USAGE: name -l TABLENAME\n"
            "       name -d TABLENAME --id IDNUM\n"
            "       name -a TABLENAME --sip SRCIP --dip DSTIP --sport SPORT --dport DPORT --[protocol|scidr|action]\n"
            "\nOptions:\n"
            "  --list      -l  list table messages\n"
            "  --delete    -d  delete a table item\n"
            "  --append    -a  append a table item\n"
            "  --help      -h  show this message\n"
            "  --sip           set src ip\n"
            "  --dip           set dst ip\n"
            "  --sport         set src port\n"
            "  --dport         set dst port\n"
            "\nBELOW OPTIONS ARE ONLY FOR FIREWALL RULE ADD\n"
            "  --scidr         set src cidr (DEFAULT 32)\n"
            "  --dcidr         set dst cidr (DEFAULT 32)\n"
            "  --action        set action   (DEFAULT DENY)\n"
            "  --protocol  -p  set protocol (DEFAULT ANY)\n"
    );
}

#endif
