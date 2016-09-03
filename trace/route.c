/*
 * This is a simplified version of traceroute.
 *
 * The reason that we don't use udp socket to detect the routers is that it
 * seems that some of the firewalls would filter out udp packets with
 * "bad(unlikely)" ports(at least this is true for me).
 *
 * Even with tcp sockets, if we tried to connect to a port which the server had
 * not been listening to, some of the servers would not send us a TCP RST reply,
 * and if we turned on a flag other than the SYN flag while setting ttl to zero,
 * according to the experiments(by just simply deleting a few lines in the
 * section which entitled "parsing command line options", maybe I did something
 * wrong)I had done, it seemed that the behaviors of routers would be partially
 * determined by the content of tcp segment(or the tcp flags combined with ttl),
 * all the routers would not send us any ICMP messages indicating that our ttl
 * exceeded in transit, therefore, I disabled the options which were used
 * to set the TCP flag and destination port number.
 *
 * NOTE: This piece of code needs CAP_NET_RAW ability to run, to give it the
 * appropriate capabilities, just run:
 *           $ cd directory_of_this_file
 *           $ su
 *           # *********(enter your password)
 *           # setcap cap_net_raw=p name_of_this_file
 *           # exit
 *           $ ./name_of_this_file target
 *
 * I've tested this program on Debian 8.5.
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <error.h>
#include <errno.h>
#include "common.h"
#include "tcp_pseudo_hdr.h"


struct iphdr ip;
struct pseudo_tcphdr pse_tcp;
struct tcphdr tcp;

/* tcp_datalen is "zero", as we have no data to send */
uint16_t tcp_totlen, tcp_optlen, tcp_datalen;
size_t tcp_hdrlen = sizeof(struct tcphdr);
size_t tcp_pselen = sizeof(struct pseudo_tcphdr);
size_t ip_hdrlen = sizeof(struct iphdr);
uint16_t ip_totlen;

struct sockaddr_in src, dest;
struct msghdr s_msg, r_msg;
struct cmsghdr *s_cmsg, *r_cmsg;
struct iovec s_iov, r_iov;

struct in_pktinfo s_pkt;
struct in_pktinfo r_pkt;

/* our send, receive buffer */
uint8_t s_buff[1500];
/* this seems to be a reasonably receive buffer size */
uint8_t r_buff[65535];

/* our source port */
uint16_t srcport = 12660;
/* tcp options */
uint8_t tcp_opt[40];
/* buffer used to calculate tcp, ip checksum */
uint8_t tcp_seg[1440];
uint8_t ip_hdr[60];

/* ancillary data */
uint8_t s_cntl[CMSG_SPACE(sizeof(struct in_pktinfo))];
uint8_t r_cntl[CMSG_SPACE(sizeof(struct in_pktinfo))];

uint16_t our_pid;
/* length of struct sockaddr_in */
socklen_t in_len = sizeof(struct sockaddr_in);

/* we need two raw sockets */
int probefd, icmpfd;

/* if "answ(0)", then we set the RST flag, else, we set the SYN flag */
int answ, probe = 1;
/* array of file descriptor */
int allfds[4];
/* number of router */
int num_router;

const struct option long_options[] = {
        {"flag", required_argument, NULL, 'f'},
        {"help", no_argument, NULL, 'h'},
        {"port", required_argument, NULL, 'p'},
        {"ttl", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0}
};

const char *optstring = ":f:hp:t:";

/* tcp flags */
const char *flagnames[] = {
        "ACK",
        "FIN",
        "PSH",
        "RST",
        "SYN",
        "URG"
};

/* values of command line options */
uint16_t user_port = 80;
uint8_t user_ttl = 1;
/* default flag is SYN */
int user_flag = 4;

static void sdpacket(int probe_or_answ);
static int rvicmp(void);
static int rvtcp(void);
static void tcpheader(int probe_or_answ);
static int msgflag(struct msghdr *msg);
static int testcpflag(char *str);
static void setcpflag(int uflag);
static void tcpoptions(void);
static void sockopts(void);
static void clean_up(void);
static void usage(void);

int main(int argc, char *argv[])
{
        struct addrinfo hints, *res, *rp;
        struct itimerspec itv;
        struct timespec tv;
        struct signalfd_siginfo fdsi;
        struct epoll_event monitored[4], events[4];
        struct in_addr bar;
        sigset_t mask;
        uint64_t occured;
        ssize_t num_bytes = 0;
        int sfd = 0, sigfd = 0, timfd = 0, epollfd = -1;
        int maxevents = 4;
        int timeout;
        int s = 0, i = 0, ch = 0, temp = 0, foo = 0;
        void *s_cdata;

        /* the two raw sockets, probefd, icmpfd */
        modifycap(CAP_SET);
        probefd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        icmpfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        modifycap(CAP_CLEAR);

        if (probefd == -1 || icmpfd == -1)
                error(fail, errno, "unable to open a raw socket");

        /*
         * "parsing command line options"
         * in fact, there is only one available option,
         * the initial time to live option.
         */
        while ((ch = getopt_long(argc, argv, optstring,
                                 long_options, NULL)) != -1) {
                switch (ch) {
                case 'f':
                        /* this is the tcp flag option */
                        if (strlen(optarg) != 3) {
                                usage();
                                exit(EXIT_FAILURE);
                        }

                        if (testcpflag(optarg) != 0) {
                                usage();
                                exit(EXIT_FAILURE);
                        }

                        /*
                         * it seems that most routers will not send an ICMP
                         * message indicating that our ttl exceeded in
                         * transit if we turned on flags other than SYN,
                         * therefore, we just turn on the SYN flag to get
                         * better results.
                         */
                        user_flag = 4;
                        break;
                        /* display help */
                case 'h':
                        usage();
                        exit(EXIT_FAILURE);
                        break;
                case 'p':
                        /* this option sets the destination port */
                        temp = atoi(optarg);
                        if (temp <= 0 || temp >= 65535) {
                                fprintf(stderr, "invalid port number");
                                usage();
                                exit(EXIT_FAILURE);
                        }

                        /* little endian */
                        memcpy(&user_port, &temp, sizeof(uint16_t));

                        /*
                         * sadly, most of the servers today would "NOT"
                         * send us a TCP RST reply if we ever tried to connect
                         * to the port they had not been listening to, therefore
                         * in order to get better results, we should set the
                         * port number to 80, of course, if we were to connect
                         * to a mail server, we could set the port number to 25.
                         */
                        user_port = 80;
                        break;
                case 't':
                        /* this options sets the initial ttl */
                        temp = atoi(optarg);
                        if (temp <=0 || temp > 64) {
                                fprintf(stderr, "invalid ttl");
                                usage();
                                exit(EXIT_FAILURE);
                        }

                        /* little endian */
                        memcpy(&user_ttl, &temp, sizeof(uint8_t));
                        break;
                default:
                        usage();
                        exit(EXIT_FAILURE);
                }
        }

        if ((argc - optind) != 1) {
                fprintf(stderr, "please specify one target\n");
                usage();
        }

        /* to detect whether the target is a multicast address */
        if (inet_pton(AF_INET, argv[optind], &bar) == 1) {
                if (IN_CLASSD(ntohl(bar.s_addr)))
                        error(fail, 0, "multicast address isn't supported");
        }

        /*
         * whether the target is a valid address
         * although this function is marked as obsolete, it is quite
         * useful here.
         */
        if (!gethostbyname(argv[optind]))
                error(fail, errno, "error: %s", hstrerror(h_errno));

        /* socket options */
        sockopts();

        memset(&hints, 0, sizeof(struct addrinfo));
        memset(&itv, 0, sizeof(struct itimerspec));
        memset(&tv, 0, sizeof(struct timespec));
        memset(allfds, 0, sizeof(allfds));

        allfds[0] = probefd;
        allfds[1] = icmpfd;

        for (i = 0; i < 4; i++) {
                /* fourth argument in epoll_ctl */
                memset(&monitored[i], 0, sizeof(struct epoll_event));

                /* second argument in epoll_wait */
                memset(&events[i], 0, sizeof(struct epoll_event));
        }

        /* setup signal(SIGINT) mask, (other signals may be added)  */
        s = sigemptyset(&mask);
        if (s != 0)
                error(fail, errno, "sigemptyset");

        s = sigaddset(&mask, SIGINT);
        if (s != 0)
                error(fail, errno, "sigaddset");

        s = sigprocmask(SIG_BLOCK, &mask, NULL);
        if (s != 0)
                error(fail, errno, "sigprocmask");

        /* signal file descriptor for SIGINT */
        sigfd = signalfd(-1, &mask, 0);
        if (sigfd == -1)
                error(fail, errno, "signalfd");

        allfds[2] = sigfd;

        /* get sockaddr_in of the dest */
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
                        error(warn, errno, "can't create a udp socket");
                        continue;
                }

                if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == -1) {
                        /*
                         * if the error is EACCESS or EPERM
                         * then it means that the destination is a broadcast
                         * address, we should quit.
                         */
                        close(sfd);
                        if (errno == EACCES || errno == EPERM)
                                error(fail, errno, "connect failed");

                        continue;
                } else {
                        s = getsockname(sfd, (struct sockaddr *)&src, &in_len);
                        if (s != 0)
                                error(fail, errno, "getsockname");

                        close(sfd);
                        break;
                }
        }

        if (!rp) {
                freeaddrinfo(res);
                error(fail, errno, "destin unreachable");
        }

        memcpy(&dest, rp->ai_addr, sizeof(struct sockaddr));
        /* change the destination port */
        dest.sin_port = htons(user_port);
        freeaddrinfo(res);


        /* the ip header part */
        our_pid = (uint16_t)(getpid() & 0xFFFF);
        ip.version = IPVERSION;
        ip.ihl = 5;
        ip.ttl = user_ttl;
        ip.id = htons(our_pid);
        ip.protocol = IPPROTO_TCP;
        ip.saddr = src.sin_addr.s_addr;
        ip.daddr = dest.sin_addr.s_addr;

        /* the msghdr s_msg part */
        s_iov.iov_base = s_buff;
        s_iov.iov_len = sizeof(s_buff);

        s_cmsg = (struct cmsghdr *)s_cntl;
        s_cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        s_cmsg->cmsg_level = IPPROTO_IP;
        s_cmsg->cmsg_type = IP_PKTINFO;
        s_cdata = CMSG_DATA(s_cmsg);
        memcpy(s_cdata, &s_pkt, sizeof(struct in_pktinfo));

        s_msg.msg_name = &dest;
        s_msg.msg_namelen = sizeof(struct sockaddr_in);
        s_msg.msg_iov = &s_iov;
        s_msg.msg_iovlen = 1;
        s_msg.msg_control = s_cmsg;
        s_msg.msg_controllen = sizeof(s_cntl);

        /* the msghdr r_msg part */
        r_iov.iov_base = r_buff;
        r_iov.iov_len = sizeof(r_buff);

        r_msg.msg_iov = &r_iov;
        r_msg.msg_iovlen = 1;
        r_msg.msg_control = r_cntl;
        r_msg.msg_controllen = sizeof(r_cntl);

        /*
         * create a timer file descriptor, tv_sec and tv_nsec are arbitrary
         * numbers, they don't have any special meanings.
         */
        itv.it_interval.tv_sec = 2;
        itv.it_value.tv_nsec = 10000;

        timfd = timerfd_create(CLOCK_REALTIME, 0);
        if (timfd == -1)
                error(fail, 0, "timerfd_create");

        s = timerfd_settime(timfd, 0, &itv, NULL);
        if (s != 0)
                error(fail, 0, "timerfd_settime");

        allfds[3] = timfd;

        /* timeout for pselect */
        tv.tv_sec = 2;

        /* event poll setup */
        timeout = 2;

        epollfd = epoll_create1(0);
        if (epollfd == -1)
                error(fail, errno, "epoll_create1");

        for (i = 0; i < 4; i++) {
                monitored[i].events = EPOLLIN;
                monitored[i].data.fd = allfds[i];

                errno = 0;
                s = epoll_ctl(epollfd, EPOLL_CTL_ADD, allfds[i], &monitored[i]);
                if (s != 0)
                        error(fail, errno, "epoll_ctl i is %d", i);
        }

        /* the loop */
        for (;;) {
                s = epoll_pwait(epollfd, events, maxevents, timeout, NULL);
                if (s == -1)
                        error(fail, errno, "epoll_pwait");

                if (s == 0)
                        continue;

                for (i = 0; i < 4; i++) {
                        if (events[i].data.fd == probefd) {
                                if (rvtcp() == 0) {
                                        /*
                                         * "turn on the RST flag"
                                         * it seems that we don't need to send
                                         * a RST flag to our target, the kernel
                                         * will automatically send a RST flag
                                         * when we receive a packet with
                                         * "ACK + SYN" flag turned on.
                                         */
                                        sdpacket(answ);
                                        clean_up();

                                        /* break the outer loop */
                                        goto out_loop;
                                }
                        }

                        if (events[i].data.fd == timfd) {
                                /* read the timerfd */
                                num_bytes = read(timfd, &occured,
                                                 sizeof(uint64_t));
                                if (num_bytes != sizeof(uint64_t))
                                        error(fail, errno, "cannot read timer");

                                /*
                                 * if we have sent 10 tcp packets without an
                                 * icmp reply, then, we should quit.
                                 */
                                if (foo > 10) {
                                        clean_up();
                                        printf("%d packets sent without reply\n",
                                               foo);
                                        exit(EXIT_FAILURE);
                                } else {
                                        /* turn on the syn flag */
                                        sdpacket(probe);
                                        num_router++;
                                        foo++;
                                }
                        }

                        if (events[i].data.fd == icmpfd) {
                                if (rvicmp() == 1) {
                                        /* break the inner loop */
                                        break;
                                } else {
                                        foo--;
                                }

                        }

                        if (events[i].data.fd == sigfd) {
                                /* read the signalfd */
                                num_bytes = read(sigfd, &fdsi,
                                                 sizeof(struct signalfd_siginfo));

                                if (num_bytes != sizeof(struct signalfd_siginfo))
                                        error(fail, errno, "cannot read SIGINT");

                                printf("\n\n");
                                clean_up();
                                exit(EXIT_FAILURE);

                        }
                }
        }

out_loop:
        return 0;
}

int msgflag(struct msghdr *msg)
{
        if (msg->msg_flags) {
                /*
                 * an error occurred
                 * MSG_ERRQUEUE | MSG_CTRUNC | MSG_TRUNC
                 */
                return 1;
        }

        return 0;
}

int testcpflag(char *str)
{
        int i = 0;

        for (; i < 6; i++)
                if (memcmp(flagnames[i], str, 3) == 0) {
                        user_flag = i;
                        return 0;
                }

        return 1;
}

void setcpflag(int uflag)
{
        /* this is not necessary */
        if (uflag < 0 || uflag > 5)
                error(fail, errno, "invalid flag");

        /*
         * this is a rather stupid method.
         */
        switch (uflag) {
        case 0:
                tcp.ack = 1;
                break;
        case 1:
                tcp.fin = 1;
                break;
        case 2:
                tcp.psh = 1;
                break;
        case 3:
                tcp.rst = 1;
                break;
        case 4:
                tcp.syn = 1;
                break;
        case 5:
                tcp.urg = 1;
                break;
        }
}

/* commonly used tcp options */
void tcpoptions(void)
{
        struct timespec ts;
        uint16_t mss = htons(1460);
        uint32_t n_secs = 0;
        int s = 0;

        memset(&ts, 0, sizeof(struct timespec));

        /* tcp options, MSS option */
        tcp_opt[0] = TCPOPT_MAXSEG;
        tcp_opt[1] = TCPOLEN_MAXSEG;
        memcpy(tcp_opt + 2, &mss, sizeof(uint16_t));

        /* selective acknowledge option */
        tcp_opt[4] = TCPOPT_SACK_PERMITTED;
        tcp_opt[5] = TCPOLEN_SACK_PERMITTED;

        /* timestamp option */
        tcp_opt[6] = TCPOPT_TIMESTAMP;
        tcp_opt[7] = TCPOLEN_TIMESTAMP;

        s = clock_gettime(CLOCK_REALTIME, &ts);
        if (s != 0)
                error(fail, errno, "clock_gettime");
        /* little endian */
        memcpy(&n_secs, &ts.tv_nsec, 4);
        /* this is a fake TSval */
        memcpy(tcp_opt + 8, &n_secs, sizeof(uint32_t));

        /* window scale option */
        tcp_opt[16] = TCPOPT_NOP;
        tcp_opt[17] = TCPOPT_WINDOW;
        tcp_opt[18] = TCPOLEN_WINDOW;
        /* the window scaling factor */
        tcp_opt[19] = 7;

        tcp_optlen = 20;
}

/* tcp header(including pseudo header) */
void tcpheader(int probe_or_answ)
{

        memset(&tcp, 0, tcp_hdrlen);
        memset(tcp_seg, 0, sizeof(tcp_seg));

        tcp.dest = htons(user_port);
        tcp.source = htons(srcport);
        /* we could set an arbitrary sequence number */
        tcp.seq = htonl(0x32fff3);

        /* the pseudo tcp header */
        pse_tcp.saddr = src.sin_addr.s_addr;
        pse_tcp.daddr = dest.sin_addr.s_addr;
        pse_tcp.protocol = IPPROTO_TCP;

        if (probe_or_answ == 1 && user_flag == 4) {
                tcp.doff = 10;
                tcp.syn = 1;
                /* windows size is somewhat an arbitrary number */
                tcp.window = htons(29200);
                tcp_totlen = (uint16_t)(tcp_hdrlen + tcp_optlen + tcp_datalen);

                pse_tcp.len = htons(tcp_totlen);

                memcpy(tcp_seg, &pse_tcp, tcp_pselen);
                memcpy(tcp_seg + tcp_pselen, &tcp, tcp_hdrlen);
                memcpy(tcp_seg + tcp_pselen + tcp_hdrlen, tcp_opt, tcp_optlen);

                /*
                 * as we have zero data in tcp segment, therefore the following
                 * step is omitted
                 * memcpy(tcp_seg + tcp_pselen + tcp_hdrlen + tcp_optlen,
                 * (*)DATA, sizeof(DATA)).
                 */


                /* TCP checksum */
                tcp.check = chksum(tcp_seg, tcp_pselen + tcp_totlen);

        } else {
                /*
                 * if we got here, it means that we need flags other than SYN
                 * and the length of tcp option is zero.
                 *
                 * the timestamp option is not set here.
                 */
                tcp.doff = 5;
                if (probe_or_answ == 1) {
                        /*
                         * we use flags other than SYN
                         */
                        setcpflag(user_flag);
                } else {
                        tcp.rst = 1;
                }
                tcp.window = htons(1460);
                tcp_totlen = (uint16_t)(tcp_hdrlen + tcp_datalen);

                pse_tcp.len = htons(tcp_totlen);

                memcpy(tcp_seg, &pse_tcp, tcp_pselen);
                memcpy(tcp_seg + tcp_pselen, &tcp, tcp_hdrlen);

                /* TCP checksum */
                tcp.check = chksum(tcp_seg, tcp_pselen + tcp_totlen);
        }
}

void sdpacket(int probe_or_answ)
{
        ssize_t num = 0;
        uint16_t packet_len = 0;

        /* ip header checksum */
        memcpy(ip_hdr, &ip, ip_hdrlen);
        ip.check = chksum(ip_hdr, ip_hdrlen);
        ip.ttl = user_ttl++;

        /* copy ip header to sent buffer */
        memcpy(s_buff, &ip, ip_hdrlen);

        /* test whether this is a probe or answer packet */
        if (probe_or_answ == 1 && user_flag == 4) {
                tcpoptions();
                tcpheader(probe);
                memcpy(s_buff + ip_hdrlen, &tcp, tcp_hdrlen);
                memcpy(s_buff + ip_hdrlen + tcp_hdrlen, tcp_opt, tcp_optlen);
        } else {
                if (probe_or_answ == 1) {
                        tcpheader(probe);
                } else {
                        tcpheader(answ);
                }
                memcpy(s_buff + ip_hdrlen, &tcp, tcp_hdrlen);
        }

        /* send probe or answer */
        packet_len = (uint16_t)(ip_hdrlen + tcp_totlen);
        s_iov.iov_len = (size_t)packet_len;
        num = sendmsg(probefd, &s_msg, 0);
        if ((size_t)num != packet_len) {
                error(fail, errno, "sendmsg");
        }
}

int rvicmp(void)
{
        struct iphdr pathip, ourip;
        struct icmphdr icmp;
        struct in_addr hop;
        struct msghdr icmpmsg;
        struct iovec icmpiov;
        uint8_t icmpbuff[1500];
        char hopname[INET_ADDRSTRLEN];
        size_t icmp_hdrlen = sizeof(struct icmphdr);
        ssize_t num = 0;
        int s = 0;

        memset(&pathip, 0, ip_hdrlen);
        memset(&ourip, 0, ip_hdrlen);
        memset(&hop, 0, sizeof(struct in_addr));
        memset(&icmpmsg, 0, sizeof(struct msghdr));
        memset(&icmpiov, 0, sizeof(struct iovec));
        memset(&icmp, 0, icmp_hdrlen);
        memset(hopname, 0, sizeof(hopname));

        icmpiov.iov_base = icmpbuff;
        icmpiov.iov_len = sizeof(icmpbuff);
        icmpmsg.msg_iov = &icmpiov;
        icmpmsg.msg_iovlen = 1;

        num = recvmsg(icmpfd, &icmpmsg, 0);
        s = msgflag(&icmpmsg);
        if (num != -1 && s == 0) {
                memcpy(&pathip, icmpbuff, ip_hdrlen);
                memcpy(&icmp, icmpbuff + pathip.ihl * 4, icmp_hdrlen);

                /* 40 + 8 = ip + icmp + ip */
                if (num < 40 + 8)
                        return 1;
                memcpy(&ourip, icmpbuff + pathip.ihl * 4 + icmp_hdrlen, ip_hdrlen);

                if (ntohs(ourip.id) == our_pid) {
                        /* we got a icmp message for our pid */
                        switch (icmp.type) {
                        case ICMP_TIME_EXCEEDED:
                                if (icmp.code == ICMP_EXC_TTL) {
                                        /* we got it */
                                        goto got_it;
                                } else if (icmp.code == ICMP_EXC_FRAGTIME) {
                                        /* unlikely would this happen */
                                        error(fail, errno, "fragment reass");
                                }
                                /* unlikely would this happen */
                        case ICMP_DEST_UNREACH:
                                if (icmp.code == ICMP_NET_UNREACH) {
                                        error(fail, 0, "network unreachable");
                                } else if (icmp.code == ICMP_HOST_UNKNOWN) {
                                        error(fail, 0, "host unreachable");
                                } else if (icmp.code == ICMP_PORT_UNREACH) {
                                        error(fail, 0, "port unreachable");
                                } else {
                                        error(fail, 0,"icmp code %u",icmp.code);
                                }

                                /* maybe other types of errors, unlikely */
                        default:
                                error(fail, 0, "icmp type %u", icmp.type);
                        }
                } else {
                        return 1;
                }
        } else {
                if (num == -1)
                        error(fail, errno, "recvmsg on icmpfd");
                if (s != 0)
                        error(fail, errno, "maybe buffer size is too small");
        }

got_it:
        /* we got a ICMP_EXC_TTL message */
        hop.s_addr = pathip.saddr;
        /* unlikely */
        if(!inet_ntop(AF_INET, &hop.s_addr, hopname, sizeof(hopname)))
                error(fail, errno, "inet_ntop");

        printf("%d:\t%s\n", num_router, hopname);
        /* if we came to here, then we did not get the time exceeded reply */
        return 0;
}

int rvtcp(void)
{
        struct iphdr peerip;
        struct tcphdr peertcp;
        struct in_addr peer;
        char peername[INET_ADDRSTRLEN];
        ssize_t num = 0;
        int s = 0;

        memset(&peerip, 0, ip_hdrlen);
        memset(&peertcp, 0, tcp_hdrlen);
        memset(&peer, 0, sizeof(struct in_addr));
        memset(peername, 0, sizeof(peername));

        num = recvmsg(probefd, &r_msg, 0);
        s = msgflag(&r_msg);
        if (num != -1 && s == 0) {
                memcpy(&peerip, r_buff, ip_hdrlen);
                if (peerip.saddr == dest.sin_addr.s_addr) {
                        memcpy(&peertcp, r_buff + peerip.ihl * 4, tcp_hdrlen);
                        if (htons(srcport) == peertcp.dest) {
                                goto final;
                        } else {
                                return 1;
                        }
                } else {
                        return 1;
                }
        } else {
                if (num == -1)
                        error(fail, errno, "recvmsg on probefd");
                /* unlikely would this happen */
                if (s != 0) {
                        if (r_msg.msg_flags == MSG_TRUNC) {
                                printf("our receive buffer is too small\n");
                        } else if (r_msg.msg_flags == MSG_CTRUNC) {
                                printf("ancillary data was discarded\n");
                        } else if (r_msg.msg_flags == MSG_ERRQUEUE) {
                                printf("we received a error queue\n");
                        }
                }
                return 1;
        }

final:
        peer.s_addr = peerip.saddr;
        if (!inet_ntop(AF_INET, &peer, peername, sizeof(peername)))
                error(fail, errno, "inet_ntop");
        printf("%d:\t%s\n", num_router, peername);

        printf("\n");
        if (peertcp.ack) {
                printf("ACK flag is on\n");
        }

        if (peertcp.fin) {
                printf("FIN flag is on\n");
        }

        if (peertcp.psh) {
                printf("PSH flag is on\n");
        }

        if (peertcp.syn) {
                printf("SYN flag is on\n");
        }

        if (peertcp.rst) {
                printf("RST flag is on\n, maybe the port is not open\n");
        }

        /* unlikely would this happen */
        if (peertcp.urg) {
                printf("URG flag is on\n");
        }

        /* we got the reply from the target */
        return 0;
}

void sockopts(void)
{
        int s = 0;
        int on = 1;

        /* socket options, the first option must be enabled */
        s = setsockopt(probefd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
        if (s != 0)
                error(fail, errno, "cannot set IP_HDRINCL option");

        s = setsockopt(probefd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
        if (s != 0)
                error(fail, errno, "cannot set IP_PKTINFO option");

        /* and possibly other options */
}

void clean_up(void)
{
        int i = 0;

        for (; i < 4; i++)
                close(allfds[i]);
        fflush(NULL);
}

void usage(void)
{
        fprintf(stderr, "Usage: second [option] target.\n"
                "-f --flag tcp flag(SYN, ACK, RST, etc)\n"
                "-h --help show help\n"
                "-p --port port number of the target\n"
                "-t --ttl initial ttl of the packet\n");
}
