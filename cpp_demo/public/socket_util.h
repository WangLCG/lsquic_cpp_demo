////////////////////////////////////////////////////////////////////////
/// @file       socket_util.h
/// @brief      socket设置公共函数声明
/// @details    socket设置公共函数声明
/// @author     王超
/// @version    1.0
/// @date       2021/11/19
/// @copyright  (c) 2021-2031 。保留所有权利
////////////////////////////////////////////////////////////////////////
#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <string.h>
#include <error.h>
#include <stdio.h>

#if defined(IP_RECVORIGDSTADDR)
#   define DST_MSG_SZ sizeof(struct sockaddr_in)
#else
#   define DST_MSG_SZ sizeof(struct in_pktinfo)
#endif
                            
#define ECN_SZ CMSG_SPACE(sizeof(int))

#define MAX(a, b) ((a) > (b) ? (a) : (b))
/* Amount of space required for incoming ancillary data */
#define CTL_SZ (CMSG_SPACE(MAX(DST_MSG_SZ, \
                sizeof(struct in6_pktinfo))) + ECN_SZ)


/* 设置文件描述符为非阻塞 */
int set_fd_nonblocking (int fd);

void tut_proc_ancillary (struct msghdr *msg, struct sockaddr_storage *storage, int *ecn);

int tut_set_origdst (int fd, const struct sockaddr *sa);

int tut_set_ecn (int fd, const struct sockaddr *sa);
