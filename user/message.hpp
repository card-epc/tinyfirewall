#ifndef MESSAGE_HPP
#define MESSAGE_HPP

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cerrno>
#include <memory>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "parser.hpp"
#include "../kmodule/sharedstruct.h"

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


class KernelLink {
    public:

        explicit KernelLink(Parser* parser_ptr) : parser(parser_ptr) { init(); }
        virtual ~KernelLink() { close(skfd); }
        KernelLink(const KernelLink& k) = delete;
        KernelLink(const KernelLink&& k) = delete;
        KernelLink& operator=(const KernelLink& k) = delete;

        void changeParser(Parser* newparser);
        void sendMsgtoKernel(const void *data, uint32_t len);
        void recvMsgfromKernel();

    private:
        void init ();
        int skfd;
        struct sockaddr_nl  local_addr;
        struct sockaddr_nl kernel_addr;
        std::unique_ptr<Parser> parser;
};

void KernelLink::init() {

    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (skfd == -1) {
        printf("Create Socket Error %s\n", strerror(errno));
        exit(-1);
    }

    memset(&local_addr, 0, sizeof(local_addr));
    memset(&kernel_addr, 0, sizeof(kernel_addr));

    local_addr.nl_family = kernel_addr.nl_family = AF_NETLINK;
    local_addr.nl_groups = kernel_addr.nl_groups = 0;
    local_addr.nl_pid  = STATIC_PORT;
    kernel_addr.nl_pid = 0;

    if (bind(skfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) != 0) {
        printf("bind Error %s\n", strerror(errno));
        close(skfd);
        exit(-1);
    }

}

void KernelLink::changeParser(Parser *newparser) {
    this->parser.reset(newparser);
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
    nlh->nlmsg_pid = local_addr.nl_pid; //self port
 
    memcpy(NLMSG_DATA(nlh), data, len);

    int ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&kernel_addr, sizeof(struct sockaddr_nl));
    if(!ret) {
        perror("sendto error1\n");
        close(skfd);
        exit(-1);
    }

    free(nlh);
}

void KernelLink::recvMsgfromKernel() {
    uint32_t ret, var;
    msg_recv_format<> info;
    ret = recvfrom(skfd, &info, sizeof(info), 0, (struct sockaddr *)&kernel_addr, &var);
    printf("Recv %d bytes\n", ret - NLMSG_HDRLEN);
    parser->ParseMsg(info.data, ret - NLMSG_HDRLEN);
    // printf("RecvMsg %u\n", *info.data);
}

#endif
