#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <cassert>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include "../kmodule/structures.h"
 
#define NETLINK_USER 24
#define USER_PORT 50
#define MSG_LEN 100
#define MAX_PLOAD 100
 
template<uint32_t datalen>
struct msg_format {
    struct   nlmsghdr hdr;
    uint8_t  data[datalen];
};
 

class k_netlink {
    public:

        k_netlink() {
            init();
        }

        virtual ~k_netlink() { close(skfd);printf("Destructor Implement"); }

        void sendMsgtoKernel(const void *data, uint32_t len) {
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

        void recvMsgfromKernel() {

            uint32_t ret, var;
            msg_format<128> info;
            ret = recvfrom(skfd, &info, sizeof(info), 0, (struct sockaddr *)&kernel_addr, &var);
            printf("Recv %d bytes\n", ret - NLMSG_HDRLEN);
            printf("RecvMsg %s\n", info.data);
        }

    private:
        void init () {
            skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
            if (skfd == -1) {
                printf("Create Socket Error %s\n", strerror(errno));
                exit(-1);
            }

            memset(&local_addr, 0, sizeof(local_addr));
            memset(&kernel_addr, 0, sizeof(kernel_addr));

            local_addr.nl_family = kernel_addr.nl_family = AF_NETLINK;
            local_addr.nl_groups = kernel_addr.nl_groups = 0;
            local_addr.nl_pid = USER_PORT;
            kernel_addr.nl_pid = 0;

            if (bind(skfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) != 0) {
                printf("bind Error %s\n", strerror(errno));
                close(skfd);
                exit(-1);
            }

        }
        int skfd;
        struct sockaddr_nl  local_addr;
        struct sockaddr_nl kernel_addr;
};

 
int main(int argc, char **argv)
{
    const char *data = "hello This is User NoAlign";
    k_netlink k;
    // k.sendMsgtoKernel(data, strlen(data));
    // k.recvMsgfromKernel();
    // struct sockaddr_nl  local, dest_addr;
    //
    // int skfd;
    // struct nlmsghdr *nlh = NULL;
    // struct msg_format<MSG_LEN> info;
    // int ret;
    //
    // skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    // if(skfd == -1) {
    //     printf("create socket error...%s\n", strerror(errno));
    //     return -1;
    // }
    //
    // memset(&local, 0, sizeof(local));
    // local.nl_family = AF_NETLINK;
    // local.nl_pid = getpid();
    // local.nl_groups = 0;
    // if(bind(skfd, (struct sockaddr *)&local, sizeof(local)) != 0) {
    //     printf("bind() error\n");
    //     close(skfd);
    //     return -1;
    // }
    //
    // memset(&dest_addr, 0, sizeof(dest_addr));
    // dest_addr.nl_family = AF_NETLINK;
    // dest_addr.nl_pid = 0; // to kernel
    // dest_addr.nl_groups = 0;
    //
    // nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    // memset(nlh, 0, sizeof(struct nlmsghdr));
    // nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    // nlh->nlmsg_flags = 0;
    // nlh->nlmsg_type = 0;
    // nlh->nlmsg_seq = 0;
    // nlh->nlmsg_pid = local.nl_pid; //self port
    //
    // memcpy(NLMSG_DATA(nlh), data, strlen(data));
    // ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_nl));
    //
    // if(!ret) {
    //     perror("sendto error1\n");
    //     close(skfd);
    //     exit(-1);
    // }
    //
    // printf("wait kernel msg!\n");
    // memset(&info, 0, sizeof(info));
    // uint32_t var = sizeof(dest_addr);
    // printf("DEST ADDR LEN: %u\n", var);
    // ret = recvfrom(skfd, &info, sizeof(info), 0, (struct sockaddr *)&dest_addr, &var);
    // ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_nl));
    // if(!ret) {
    //     perror("recv form kernel error\n");
    //     close(skfd);
    //     exit(-1);
    // }
    //
    // printf("DEST ADDR LEN: %u\n", var);
    // printf("msg receive from kernel:%s\n", info.data);
    // close(skfd);

    // free((void *)nlh);
    return 0;

}
