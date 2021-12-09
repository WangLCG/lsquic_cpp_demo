////////////////////////////////////////////////////////////////////////
/// @file       quic_com.h
/// @brief      quic通信公共类声明
/// @details    quic通信公共类声明
/// @author     王超
/// @version    1.0
/// @date       2021/11/10
/// @copyright  (c) 2021-2031 。保留所有权利
////////////////////////////////////////////////////////////////////////
#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include "lsquic.h"
#include "ev.h"
#ifdef __cplusplus
}
#endif

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

using namespace std;

/* So that largest allocation in PBA fits in 4KB */
#define PBA_SIZE_MAX 0x1000
#define PBA_SIZE_THRESH (PBA_SIZE_MAX - sizeof(uintptr_t))

struct BasicState;

struct lsquic_conn_ctx {
    lsquic_conn_t       *conn;
    void* quic_core_handle;
};

struct lsquic_stream_ctx {
    lsquic_stream_t     *stream = NULL;

    // msg to send or read
    char                 buf[4096];
    size_t               buf_used = 0;   /* 已使用的buffer大小 */

    void* quic_core_handle;
};

/* 初始化类似@see LSQUIC_GLOBAL_CLIENT LSQUIC_GLOBAL_SERVER */
typedef enum LIVE_QUCI_TYPE
{
    LIVE_QUCI_TYPE_CLIENT = 1 << 0,
    LIVE_QUCI_TYPE_SERVER = 1 << 1
}LIVE_QUCI_TYPE;

typedef struct quic_infos
{
    LIVE_QUCI_TYPE type;
    int local_port;
    string local_ip;

    int peer_port;  /* 对端端口 */
    string peer_ip; /* 对端IP */

    string cert_file;  /* 证书路径 */
    string key_file;  /* 公钥路径 */
}quic_infos;

typedef struct BasicState
{
    // event loop
    struct ev_loop *loop;
    ev_io sock_watcher;
    ev_timer conn_watcher;

    // lsquic
    int sockfd;
    struct sockaddr_storage local_sas;
    lsquic_engine_t *engine = NULL;

    // msg to send or read
    char *buf   = nullptr;
    size_t size    = 0;
    size_t buf_total_size = 0;

    int StateType;  //@see LIVE_QUCI_TYPE

    void* quic_core_handle = nullptr;

    struct lsquic_engine_settings   engine_settings;
    SSL_CTX              *ssl_ctx = nullptr;
}BasicState;

typedef struct ServerState : public BasicState
{
    //TAILQ_HEAD( , lsquic_conn_ctx)   conn_ctxs;
    int n_conn;

    // SSL
    SSL_CTX *ssl_ctx = NULL;

} ServerState;

typedef struct ClientState : public BasicState
{
    lsquic_stream_t *stream = NULL;
    //struct lsquic_conn_ctx  *conn_h;
    lsquic_conn_t       *conn = NULL;
    ev_io   read_local_data_ev;
} ClientState;
