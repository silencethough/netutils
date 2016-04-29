/*
 * A minimal version of ping
 *
 * Some of the options of the original ping program aren't included in this
 * piece of code, like the record route option.
 */

#define _GNU_SOURCE

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <signal.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include "common.h"

uint8_t s_buff[1500];
uint8_t r_buff[1500];

uint8_t s_cntl[CMSG_SPACE(sizeof(struct in_pktinfo))];
uint8_t r_cntl[CMSG_SPACE(sizeof(struct in_pktinfo)) +\
               CMSG_SPACE(sizeof(struct timeval)) +\
               CMSG_SPACE(sizeof(uint8_t))];

int rawfd;
int user_ttl;

/* number of ping requests without reply */
int foo;

uint8_t ttl;
uint16_t ourpid, id;
long max_rrt, min_rrt, sum_rrt;
uint32_t received, transferred;
uint64_t pattern;
size_t extra = 24;
size_t icmplen = sizeof(struct icmphdr);
size_t hdrlen = sizeof(struct iphdr) + sizeof(struct icmphdr);
size_t valen = sizeof(struct timeval);
ssize_t s_num, r_num;
char canon[NI_MAXHOST];

static uint16_t sequence;

struct timeval s_stamp, r_stamp;
struct icmphdr s_icp, r_icp;
struct msghdr s_msg, r_msg;
struct cmsghdr *s_cmsg, *r_cmsg;
struct in_pktinfo s_pkt, r_pkt;

const struct option long_options[] = {
        {"count", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {"interval", required_argument, NULL, 'i'},
        {"pattern", required_argument, NULL, 'p'},
        {"packetsize", required_argument, NULL, 's'},
        {"ttl", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0}
};
const char *optstring = ":c:hi:p:s:t:";

static void sockopt(void);
static void sdpacket(void);
static void clean_up(void);
static ssize_t rvpacket(void);
static void usage(void);

int main(int argc, char *argv[])
{
        struct itimerspec itv;
        struct signalfd_siginfo fdsi;
        struct timeval arrive;
        struct timespec timeout;
        struct sockaddr_in target;
        struct in_addr bar;
        struct addrinfo hints, *res, *rp;
        struct iovec s_iov, r_iov;
        struct pollfd monitored[3];
        sigset_t mask;
        int sfd = 0, sigfd = 0, timfd = 0;
        int s = 0, ch = 0, temp = 0, i = 0;
        int frequency = 2;
        nfds_t nfds = 3;
        size_t len = icmplen + valen;
        uint32_t count = 0;
        ssize_t rvnum = 0, tinum = 0, itnum = 0;
        long rrt;
        uint64_t occured;
        char peername[INET_ADDRSTRLEN];
        void *s_cdata;

        /* create a raw socket */
        modifycap(CAP_SET);
        rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        modifycap(CAP_CLEAR);

        if (rawfd == -1)
                error(fail, errno, "unable to open a raw socket");

        /* parsing command line options */
        while ((ch = getopt_long(argc, argv, optstring,
                                 long_options, NULL)) != -1) {
                switch (ch) {
                case 'c':
                        /* maybe it's unsuitable to send so many icmp packets */
                        temp = atoi(optarg);
                        if (temp <= 0 || temp > 20) {
                                fprintf(stderr, "option c failed.");
                                usage();
                                exit(EXIT_FAILURE);
                        }

                        count = (uint32_t)temp;
                        break;
                case 'h':
                        usage();
                        exit(EXIT_SUCCESS);
                        break;
                case 'i':
                        /*
                         * maybe it's better to set the interval to be more than
                         * one second, I prefer to set the interval to two
                         * seconds, of course, you could set it to a smaller
                         * value, however, that's your choice.
                         *
                         * temp = atoi(optarg);
                         * if (temp > 0)
                         *       frequency = temp;
                         */
                        break;
                case 'p':
                        errno = 0;
                        pattern = strtoul(optarg, NULL, 16);
                        if (errno != 0) {
                                fprintf(stderr, "we need a valid hex number\n");
                                usage();
                                exit(EXIT_FAILURE);
                        }
                        break;
                case 's':
                        /* minimal size of a packet should be
                         * 44(20 + 24) + extra
                         *
                         * this value is the extra bytes added to the packet.
                         *
                         * here we're not interested in the path mtu, we must
                         * make sure that our packets will not be fragmented.
                         */
                        temp = atoi(optarg);
                        if (temp < 0 || temp > (576 - 28 - 16 - 24)) {
                                fprintf(stderr, "wrong packet size\n");
                                usage();
                                exit(EXIT_FAILURE);
                        }

                        extra += (size_t)temp;
                        break;
                case 't':
                        /*
                         * maybe it's better to let kernel to choose the ttl
                         * 48 is an arbitrary number, it doesn't have
                         * any special meaning.
                         */
                        temp = atoi(optarg);
                        if (temp <= 48 || temp >= 64) {
                                fprintf(stderr, "recommended ttl is 64.\n");
                                usage();
                                exit(EXIT_FAILURE);
                        }

                        user_ttl = temp;
                        break;
                default:
                        usage();
                        exit(EXIT_FAILURE);
                }
        }

        if ((argc - optind) != 1) {
                fprintf(stderr, "please specify one host to ping\n");
                usage();
        }

        /* to detect whether the target is a multicast address */
        if (inet_pton(AF_INET, argv[optind], &bar) == 1) {
                if (IN_CLASSD(ntohl(bar.s_addr)))
                        error(fail, 0, "please don't ping multicast address");
        }

        /* whether the target is a valid address */
        if (!gethostbyname(argv[optind]))
                error(fail, errno, "error: %s", hstrerror(h_errno));

        memset(&fdsi, 0, sizeof(struct signalfd_siginfo));
        memset(&itv, 0, sizeof(struct itimerspec));
        memset(&timeout, 0, sizeof(struct timespec));
        memset(&arrive, 0, sizeof(struct timeval));
        memset(&target, 0, sizeof(struct sockaddr_in));
        memset(peername, 0, sizeof(peername));
        memset(&s_iov, 0, sizeof(struct iovec));
        memset(&r_iov, 0, sizeof(struct iovec));

        for (i = 0; i < 3; i++) {
                memset(&monitored[i], 0, sizeof(struct pollfd));
                monitored[i].events = POLLIN;
        }

        /* setup signal(SIGINT) mask */
        s = sigemptyset(&mask);
        if (s != 0)
                error(fail, errno, "sigemptyset");

        s = sigaddset(&mask, SIGINT);
        if (s != 0)
                error(fail, errno, "sigaddset");

        s = sigprocmask(SIG_BLOCK, &mask, NULL);
        if (s != 0)
                error(fail, errno, "sigprocmask");

        sigfd = signalfd(-1, &mask, 0);
        if (sigfd == -1)
                error(fail, errno, "signalfd");


        /* get sockaddr_in of the target */
        hints.ai_flags = AI_CANONNAME;
        hints.ai_family = AF_INET;
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_socktype = SOCK_DGRAM;

        s = getaddrinfo(argv[optind], NULL, &hints, &res);
        if (s != 0) {
                freeaddrinfo(res);
                error(fail, 0, "getaddrinfo: %s", gai_strerror(s));
        }

        for (rp = res; rp != NULL; rp = rp->ai_next) {
                sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (sfd == -1) {
                        error(warn, errno, "cannot create a udp socket");
                        continue;
                }

                if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
                        /*
                         * if the error is EACCESS or EPERM
                         * then please stop ping broadcast address
                         */
                        close(sfd);
                        if (errno == EACCES || errno == EPERM)
                                error(fail, errno,"connect failed");

                        continue;
                } else {
                        close(sfd);
                        break;
                }
        }

        if (!rp) {
                freeaddrinfo(res);
                error(fail, errno, "target is unreachable");
        }

        memcpy(&target, rp->ai_addr, sizeof(struct sockaddr));
        memcpy(canon, rp->ai_canonname, strlen(rp->ai_canonname));
        freeaddrinfo(res);

        if (!inet_ntop(AF_INET, &target.sin_addr, peername,
                      sizeof(struct sockaddr_in)))
                error(fail, errno, "inet_ntop");

        /* setup socket options */
        sockopt();

        /* get the id part of icmp header */
        ourpid = (uint16_t)(getpid() & 0xFFFF);
        id = htons(ourpid);

        /* struct msghdr s_msg */
        s_iov.iov_base = s_buff;
        s_iov.iov_len = icmplen + valen + extra;

        /* fill packet with the pattern (8 == sizeof(pattern)) */
        if (pattern) {
                for (; len < icmplen + valen + extra - 8; len += 8)
                        memcpy(s_buff + len, &pattern, 8);
        }

        s_cmsg = (struct cmsghdr *)s_cntl;
        s_cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        s_cmsg->cmsg_level = IPPROTO_IP;
        s_cmsg->cmsg_type = IP_PKTINFO;
        s_cdata = CMSG_DATA(s_cmsg);
        memcpy(s_cdata, &s_pkt, sizeof(struct in_pktinfo));

        s_msg.msg_control = s_cmsg;
        s_msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
        s_msg.msg_name = &target;
        s_msg.msg_namelen = sizeof(struct sockaddr_in);
        s_msg.msg_iov = &s_iov;
        s_msg.msg_iovlen = 1;

        /* struct msghdr r_msg */
        r_iov.iov_base = r_buff;
        r_iov.iov_len = sizeof(r_buff);

        r_cmsg = (struct cmsghdr *)r_cntl;

        r_msg.msg_control = r_cmsg;
        r_msg.msg_controllen = sizeof(r_cntl);
        r_msg.msg_iov = &r_iov;
        r_msg.msg_iovlen = 1;

        /* we need a timer file descriptor */
        itv.it_interval.tv_sec = frequency;
        itv.it_value.tv_nsec = 10000;

        timfd = timerfd_create(CLOCK_REALTIME, 0);
        if (timfd == -1)
                error(fail, errno, "timerfd_create");

        s = timerfd_settime(timfd, 0, &itv, NULL);
        if (s != 0)
                error(fail, errno, "timerfd_setime");

        /* file descriptors to monitor */
        monitored[0].fd = rawfd;
        monitored[1].fd = timfd;
        monitored[2].fd = sigfd;

        /* timeout for ppoll */
        timeout.tv_nsec = 0;
        timeout.tv_sec = 2;

        /* the loop */
        for (;;) {
                s = ppoll(monitored, nfds, &timeout, NULL);
                if (s == -1) {
                        error(fail, errno, "poll");
                }

                if (s == 0)
                        continue;

                if (monitored[0].revents == POLLIN) {
                        rvnum = rvpacket();
                        if (rvnum == 0) {
                                continue;
                        } else if (rvnum == -1) {
                                clean_up();
                                exit(EXIT_FAILURE);
                        }

                        foo--;

                        /* a normal packet sent for us */
                        s = gettimeofday(&arrive, NULL);
                        if (s != 0)
                                error(fail, errno, "gettimeofday");

                        rrt = (r_stamp.tv_sec - s_stamp.tv_sec) * 1000 +
                                (r_stamp.tv_usec - s_stamp.tv_usec) / 1000;
                        printf("%ld bytes from %s(%s) seq=%u ttl=%u rrt=%ldms\n",
                               r_num, canon, peername, r_icp.un.echo.sequence,
                               ttl, rrt);

                        received++;
                        sum_rrt += rrt;

                        /* max and min rrt */
                        if (received == 1)
                                min_rrt = rrt;

                        if (max_rrt < rrt)
                                max_rrt = rrt;

                        if (min_rrt > rrt)
                                min_rrt = rrt;

                        if (count) {
                                if (count == transferred)
                                        break;
                        }

                        monitored[0].revents = 0;
                }

                if (monitored[1].revents == POLLIN) {
                        tinum = read(timfd, &occured, sizeof(uint64_t));
                        if (tinum != sizeof(uint64_t))
                                error(fail, errno, "cannot read timer");

                        if (count) {
                                if (s_icp.un.echo.sequence < count + 1)
                                        sdpacket();
                        } else {
                                sdpacket();
                        }

                        foo++;
                        transferred++;

                        monitored[1].revents = 0;
                }

                if (monitored[2].revents == POLLIN) {
                        itnum = read(sigfd,&fdsi,sizeof(struct signalfd_siginfo));
                        if (itnum != sizeof(struct signalfd_siginfo))
                                error(fail, errno, "cannot read SIGINT");
                        break;

                        monitored[2].revents = 0;
                }

                /*
                 * If we have sent 5 packets without getting a reply,
                 * then we should quit.
                 */
                if (foo >= 5) {
                        fprintf(stderr, "host unreachable: %s\n", argv[optind]);
                        break;
                }

                if (count) {
                        if (count == transferred)
                                continue;
                }
        }

        clean_up();
        return 0;
}

void clean_up()
{
        printf("\n\n--- ping statistics ---\n");
        printf("%u packets transferred, %u packets received\n",
               transferred, received);

        if (received) {
                printf("rrt: max/mean/min = %ld %ld %ld ms\n",
                       max_rrt, sum_rrt /received, min_rrt);
        }

        fflush(NULL);
        close(rawfd);
}

void sdpacket(void)
{
        uint16_t csum = 0;
        int s = 0;

        s = gettimeofday(&s_stamp, NULL);
        if (s == -1)
                error(fail, errno, "gettimeofday");

        /* struct icmphdr s_icp */
        s_icp.type = ICMP_ECHO;
        s_icp.code = 0;
        s_icp.checksum = 0;
        s_icp.un.echo.id = id;
        s_icp.un.echo.sequence = sequence;

        memcpy(&s_buff, &s_icp, sizeof(struct icmphdr));
        memcpy(s_buff + sizeof(struct icmphdr), &s_stamp, sizeof(struct timeval));

        csum = chksum(s_buff,  icmplen + valen + extra);
        s_icp.checksum = csum;
        memcpy(&s_buff, &s_icp, sizeof(struct icmphdr));

        /* send the packet */
        s_num = sendmsg(rawfd, &s_msg, 0);
        if (s_num == -1)
                error(fail, errno, "sendmsg");

        sequence++;
}

ssize_t rvpacket(void)
{
        struct iphdr iph;

        r_num =recvmsg(rawfd, &r_msg, 0);
        if (r_num < s_num) {
                if (r_num == -1) {
                        error(fail, errno, "recvmsg");
                } else {
                        return 0;
                }
        }

        /* a packet that is sent for us? */
        memcpy(&iph, r_buff, sizeof(struct iphdr));
        memcpy(&r_icp, r_buff + (iph.ihl * 4), sizeof(struct icmphdr));

        if (ntohs(r_icp.un.echo.id) != ourpid)
                return 0;

        /* is it an echo reply? */
        if (r_icp.type != ICMP_ECHOREPLY) {
                switch (r_icp.type) {
                case ICMP_DEST_UNREACH:
                        if (r_icp.code == ICMP_NET_UNREACH) {
                                printf("network unreachable\n");
                        } else if (r_icp.code == ICMP_HOST_UNREACH) {
                                printf("host unreachable\n");
                        } else {
                                printf("icmp code is %u\n", r_icp.code);
                        }
                        break;
                case ICMP_REDIRECT:
                        if (r_icp.code == ICMP_REDIRECT_NET) {
                                printf("redirect datagram for the network\n");
                        } else if (r_icp.code == ICMP_REDIRECT_HOST) {
                                printf("redirect datagram for host\n");
                        } else if (r_icp.code == ICMP_REDIRECT_TOSNET) {
                                printf("redirect for network and tos\n");
                        } else {
                                printf("icmp redirect code: %u\n", r_icp.code);
                        }
                        break;
                case ICMP_TIME_EXCEEDED:
                        if (r_icp.code == ICMP_EXC_TTL) {
                                printf("time to live exceeded\n");
                        } else {
                                printf("icmp time exceeded code: %u\n",r_icp.code);
                        }
                }

                return -1;
        }

        /* finally, we got our echo reply */
        for (r_cmsg = CMSG_FIRSTHDR(&r_msg); r_cmsg != NULL;
             r_cmsg = CMSG_NXTHDR(&r_msg, r_cmsg)) {
                if (r_cmsg->cmsg_level == IPPROTO_IP) {
                        switch (r_cmsg->cmsg_type) {
                        case IP_PKTINFO:
                                memcpy(&r_pkt, CMSG_DATA(r_cmsg),
                                       sizeof(struct in_pktinfo));
                                break;
                        case IP_TTL:
                                memcpy(&ttl, CMSG_DATA(r_cmsg), sizeof(uint8_t));
                                break;
                        }
                }

                if (r_cmsg->cmsg_level == SOL_SOCKET) {
                        if (r_cmsg->cmsg_type == SO_TIMESTAMP) {
                                memcpy(&r_stamp, CMSG_DATA(r_cmsg),
                                       sizeof(struct timeval));
                        }
                }
        }

        return r_num;
}

void sockopt(void)
{
        int s = 0;
        int on = 1;

        /* socket options must be enabled */
        s = setsockopt(rawfd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
        if (s != 0)
                error(fail, errno, "cannot set IP_PKTINFO option");

        s = setsockopt(rawfd, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
        if (s != 0)
                error(fail, errno, "cannot set IP_RECVTTL option");

        s = setsockopt(rawfd, IPPROTO_IP, IP_RECVERR, &on, sizeof(on));
        if (s != 0)
                error(fail, errno, "cannot set IP_RECVERR option");

        s = setsockopt(rawfd, SOL_SOCKET, SO_TIMESTAMP, &on, sizeof(on));
        if (s != 0)
                error(fail, errno, "cannot set SO_TIMESTAMP option");

        /* optional user specified options */
        if (user_ttl) {
                s = setsockopt(rawfd, IPPROTO_IP, IP_TTL, &user_ttl,
                               sizeof(user_ttl));
                if (s != 0)
                        error(fail, errno, "cannot set IP_TTL option");
        }
}

void usage(void)
{
        fprintf(stderr, "Usage: ping [option] target.\n"
                "-c, --count number of packets to send, maximum number is 20\n"
                "-h, --help show help\n"
                "-i --interval the frequency of sending packets\n"
                "-p --pattern which must be a valid unsigned long hex number\n"
                "-s --packetsize extra bytes to send\n"
                "-t --ttl ttl of the packet\n");
}
