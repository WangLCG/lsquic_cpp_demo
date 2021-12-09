////////////////////////////////////////////////////////////////////////
/// @file       quic_server_core.h
/// @brief      quic客户端通信核心声明
/// @details    quic客户端通信核心声明
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
#include "quic_com.h"
#include <string>
#include <thread>
#include <memory>
#include <unistd.h>
#include <fcntl.h>
#include <map>
#include <vector>
#include <algorithm>
#include "log.h"

using namespace std;

/* So that largest allocation in PBA fits in 4KB */
#define PBA_SIZE_MAX 0x1000
#define PBA_SIZE_THRESH (PBA_SIZE_MAX - sizeof(uintptr_t))

class quic_server_core
{
public:
    quic_server_core(const quic_infos &infos);

    ~quic_server_core();

    bool init();

private:

    int create_sock(char *ip, unsigned int port, struct sockaddr_storage *local_sas);
    struct sockaddr_in new_addr(char *ip, unsigned int port);

    /* quic客户端的回调函数 */
    static lsquic_conn_ctx_t *server_on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn);
    static void server_on_conn_closed_cb(lsquic_conn_t *conn);
    static void server_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status);
    
    static lsquic_stream_ctx_t *server_on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream);
    static void server_on_close_cb (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h);   /* stream close 是调用的回调函数 */
    static void server_on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
    static void server_on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h);
    /* quic客户端的回调函数结束 */

    void create_event_loop();

    int init_ssl_ctx ();
    int init_ssl_ctx_map ();

    static SSL_CTX * get_ssl_ctx (void * ctx, const struct sockaddr *);
    static struct ssl_ctx_st *no_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni);
    static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                    const unsigned char *in, unsigned int inlen, void *arg);
    static struct ssl_ctx_st *lookup_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni);

    
    void server_process_conns(BasicState *state);
    static void server_process_conns_cb(EV_P_ ev_timer *conn_watcher, int revents);

    static void server_read_net_data(EV_P_ ev_io *w, int revents);

    static int send_packets_out(void *ctx, const struct lsquic_out_spec *specs, unsigned n_specs);

    struct lsquic_engine_api m_engine_api;
    BasicState *m_State;
    struct lsquic_packout_mem_if m_pmi;

    struct lsquic_stream_if m_stream_if;

    quic_infos m_quci_infos;

    shared_ptr<thread> m_event_thread = nullptr;   /* libev loop线程 */
    volatile bool m_event_thread_running; /* m_event_thread是否运行标志，true--运行 */

    char m_alpn[256] = {0};  /* lsquic设置alpn的字符串 */

    map <string, SSL_CTX *> m_certs_map;  /* server端使用, first--唯一标志 */
    vector<lsquic_conn_ctx_t *> m_connect_queue;  /* server端使用，维护的客户端链接 */
};

