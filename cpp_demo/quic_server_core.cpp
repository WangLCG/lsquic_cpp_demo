////////////////////////////////////////////////////////////////////////
/// @file       quic_server_core.cpp
/// @brief      quic客户端通信核心定义
/// @details    quic客户端通信核心定义
/// @author     王超
/// @version    1.0
/// @date       2021/11/10
/// @copyright  (c) 2021-2031 。保留所有权利
////////////////////////////////////////////////////////////////////////
#include "quic_server_core.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "lsquic.h"
#include "ev.h"
#ifdef __cplusplus
}
#endif

#include "socket_util.h"

static int tut_log_buf (void *ctx, const char *buf, size_t len)
{
    FILE *out = (FILE *)ctx;
    fwrite(buf, 1, len, out);
    fflush(out);
    return 0;
}

static const struct lsquic_logger_if logger_if = { tut_log_buf, };

quic_server_core::quic_server_core(const quic_infos &infos) : m_quci_infos(infos)
{

}

quic_server_core::~quic_server_core()
{
    if(m_State)
    {
        if (m_State->ssl_ctx)
        {
            SSL_CTX_free(m_State->ssl_ctx);
            m_State->ssl_ctx = NULL;
        }
        
        delete m_State;
        m_State = nullptr;
    }

    lsquic_engine_destroy(m_State->engine);
    lsquic_global_cleanup();
}

int quic_server_core::select_alpn(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                    const unsigned char *in, unsigned int inlen, void *arg)
{
    int r = 0;
    quic_server_core* handle = (quic_server_core*)arg;

    LOG_DEBUG("in [{}] inlen {} m_alpn [{}] m_alpn_size {}", in, inlen, handle->m_alpn, strlen(handle->m_alpn));
    
    r = SSL_select_next_proto((unsigned char **) out, outlen, in, inlen,
                                    (unsigned char *)handle->m_alpn, strlen(handle->m_alpn));
    if (r == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    else
    {
        LOG_ERROR("no supported protocol can be selected  {}", (char *) in);
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

struct ssl_ctx_st* quic_server_core::lookup_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni)
{
    if(sni)
    {
        LOG_DEBUG("In sni {}", sni);
    }
    else
    {
        LOG_DEBUG("In sni is null");
    }
    
    quic_server_core* handle = (quic_server_core*)cert_lu_ctx;
    ssl_ctx_st* ret = nullptr;
    
    if(sni)
    {
        string sni_str = sni;
        auto iter = handle->m_certs_map.find(sni_str);
        if(iter != handle->m_certs_map.end())
        {
            ret = iter->second;
        }
        else
        {
            LOG_ERROR("1 Not found cert");
        }
    }
    else
    {
        if(handle->m_certs_map.size() > 0)
        {
            auto iter = handle->m_certs_map.begin();
            ret = iter->second;
        }
        else
        {
            LOG_ERROR("2 Not found cert");
        }
    }

    if(ret)
    {
        LOG_INFO("Get ssl_ctx {}", (void*)ret);
    }
    
    return ret;
}

bool quic_server_core::init()
{
    m_State = (BasicState*)new ServerState;

    const char* alpn = "echo";
    size_t alpn_len = 0, all_len = 0;
    alpn_len  = strlen(alpn);
    m_alpn[all_len] = strlen(alpn);
    memcpy(&m_alpn[all_len + 1], alpn, strlen(alpn));
    m_alpn[all_len + 1 + alpn_len] = '\0';
    
    if(!m_quci_infos.cert_file.empty() && !m_quci_infos.key_file.empty())
    {
        if (0 != init_ssl_ctx_map())
        {
            LOG_ERROR("init_ssl_ctx_map faile \n");
            return false;
        }
        
        if (0 != init_ssl_ctx())
        {
            LOG_ERROR("init_ssl_ctx faile \n");
            return false;
        }
    }
    else
    {
        LOG_ERROR("Init server fail with missing cert or key file ");
        return false;
    }

    m_State->quic_core_handle = (void *)this;

    //m_State->buf_total_size = 4096;
    //m_State->buf  = new char[m_State->buf_total_size];
    //memset(m_State->buf, 0, m_State->buf_total_size);
    
    struct sockaddr_in peer_addr = new_addr((char*)m_quci_infos.local_ip.c_str(), m_quci_infos.local_port);

    m_State->sockfd =  socket(AF_INET, SOCK_DGRAM, 0);//create_sock((char*)m_quci_infos.local_ip.c_str(), m_quci_infos.local_port, &m_State->local_sas);
    if(-1 == m_State->sockfd)
    {
        printf("create_sock faile \n");
        return false;
    }

    if(0 != set_fd_nonblocking(m_State->sockfd) )
    {
        perror("fcntl");
        return false;
    }

    if (0 != tut_set_ecn(m_State->sockfd, (struct sockaddr*)&peer_addr))
    {
         LOG_ERROR("tut_set_ecn FAILE");
        return false;
    }

    if (0 != tut_set_origdst(m_State->sockfd, (struct sockaddr*)&peer_addr))
    {
        LOG_ERROR("tut_set_origdst FAILE");
        return false;
    }

    socklen_t socklen;
    socklen = sizeof(peer_addr);
    if (0 != bind(m_State->sockfd,  (struct sockaddr *) &peer_addr, socklen))
    {
        perror("bind");
        return false;
    }
    
    memcpy(&m_State->local_sas, &peer_addr, sizeof(peer_addr));
    
    create_event_loop();

    //lsquic_logger_init(&logger_if, stderr, LLTS_HHMMSSUS);
    //lsquic_set_log_level("debug");

    if (0 != lsquic_global_init(LSQUIC_GLOBAL_SERVER|LSQUIC_GLOBAL_CLIENT))
    {
        LOG_ERROR("lsquic_global_init Fail");
        return false;
    }

    /* At the time of this writing, using the loss bits extension causes
     * decryption failures in Wireshark.  For the purposes of the demo, we
     * override the default.
     */
    m_State->engine_settings.es_ql_bits = 0;
    
    lsquic_engine_init_settings(&m_State->engine_settings, LSENG_SERVER);
    m_State->engine_settings.es_ecn      = LSQUIC_DF_ECN;

    char err_buf[100] = {0};
    if (0 != lsquic_engine_check_settings(&m_State->engine_settings, LSENG_SERVER, err_buf, sizeof(err_buf)))
    {
        LOG_ERROR("###### Error in settings: { }", err_buf);
        return false;
    }

    memset(&m_stream_if, 0, sizeof(m_stream_if));
    m_stream_if.on_new_conn            = quic_server_core::server_on_new_conn_cb;
    m_stream_if.on_conn_closed         = quic_server_core::server_on_conn_closed_cb;
    m_stream_if.on_new_stream          = quic_server_core::server_on_new_stream_cb;
    m_stream_if.on_read                = quic_server_core::server_on_read_cb;
    m_stream_if.on_write               = quic_server_core::server_on_write_cb;
    m_stream_if.on_close               = quic_server_core::server_on_close_cb;
    
    memset(&m_engine_api, 0, sizeof(m_engine_api));
    m_engine_api.ea_settings        = &m_State->engine_settings;
    m_engine_api.ea_packets_out     = quic_server_core::send_packets_out;
    m_engine_api.ea_packets_out_ctx = (void *) this;
    m_engine_api.ea_stream_if       = &m_stream_if;
    m_engine_api.ea_stream_if_ctx   = (void *) this;
    
    m_engine_api.ea_get_ssl_ctx  = quic_server_core::get_ssl_ctx;
    m_engine_api.ea_lookup_cert  = quic_server_core::lookup_cert;
    m_engine_api.ea_cert_lu_ctx  = this;
    
    //m_engine_api.ea_lookup_cert     = quic_server_core::no_cert;
    m_engine_api.ea_alpn = alpn;
    
    m_State->engine = lsquic_engine_new(LSENG_SERVER, &m_engine_api);
    if (!m_State->engine)
    {
        LOG_ERROR("cannot create engine");
        return false;
    }

    m_event_thread = std::make_shared<thread> ([this]()
    {
        m_event_thread_running = true;
        while(m_event_thread_running)
        {
            ev_run (this->m_State->loop, 0);
            //usleep(10);
        }
    }
    );
     
    return true;
}

void quic_server_core::create_event_loop()
{
    m_State->loop = ev_loop_new(EVFLAG_AUTO);
    
    ev_io_init (&m_State->sock_watcher, quic_server_core::server_read_net_data, m_State->sockfd, EV_READ);
    ev_io_start (m_State->loop, &m_State->sock_watcher);

    //ev_init(&m_State->conn_watcher, quic_server_core::server_process_conns_cb);

    m_State->sock_watcher.data  = this;
    m_State->conn_watcher.data  = this;
}


struct ssl_ctx_st * quic_server_core::no_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni)
{
    return NULL;
}

int quic_server_core::init_ssl_ctx_map ()
{
    struct ssl_ctx_st   *ce_ssl_ctx;
    ce_ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ce_ssl_ctx)
    {
        LOG_ERROR("Cannot allocate SSL context");
        return -1;
    }

    int was = 0;
    string key (m_alpn);
    SSL_CTX_set_min_proto_version(ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ce_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(ce_ssl_ctx, quic_server_core::select_alpn, this);
    SSL_CTX_set_default_verify_paths(ce_ssl_ctx);

    {
        const char *const s = getenv("LSQUIC_ENABLE_EARLY_DATA");
        if (!s || atoi(s))
            SSL_CTX_set_early_data_enabled(ce_ssl_ctx, 1);    /* XXX */
    }

   if ( 1 != SSL_CTX_use_certificate_chain_file(ce_ssl_ctx, m_quci_infos.cert_file.c_str()) )
    {
        LOG_ERROR("SSL_CTX_use_certificate_chain_file failed");
        goto err_end;
    }

    if (1 != SSL_CTX_use_PrivateKey_file(ce_ssl_ctx, m_quci_infos.key_file.c_str(), SSL_FILETYPE_PEM))
    {
        LOG_ERROR("SSL_CTX_use_PrivateKey_file failed");
        goto err_end;
    }

    was = SSL_CTX_set_session_cache_mode(ce_ssl_ctx, 1);
    LOG_INFO("set SSL session cache mode to 1 (was:{})", was);

   
    m_certs_map.emplace(key, ce_ssl_ctx);
    LOG_INFO("init_ssl_ctx_map SUCCESS");
    
    return 0;

err_end:
    if (ce_ssl_ctx)
    {
        SSL_CTX_free(ce_ssl_ctx);
        ce_ssl_ctx = NULL;
    }
    return -1;
    
}


int quic_server_core::init_ssl_ctx ()
{
    unsigned char ticket_keys[48] = {0};
    m_State->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!m_State->ssl_ctx)
    {
        LOG_ERROR("Cannot allocate SSL context");
        goto err_end;
    }

    SSL_CTX_set_min_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(m_State->ssl_ctx);

    if (1 != SSL_CTX_set_tlsext_ticket_keys(m_State->ssl_ctx, ticket_keys, sizeof(ticket_keys)))
    {
        LOG_ERROR("SSL_CTX_set_tlsext_ticket_keys failed");
        goto err_end;
    }

    LOG_INFO("init_ssl_ctx SUCCESS");
    return 0;

err_end:
    if (m_State->ssl_ctx)
    {
        SSL_CTX_free(m_State->ssl_ctx);
        m_State->ssl_ctx = NULL;
    }
    return -1;
}

SSL_CTX * quic_server_core::get_ssl_ctx (void * ctx, const struct sockaddr *)
{
    //LOG_DEBUG("CTX {}", ctx);
    quic_server_core* handle = (quic_server_core*) ctx;
    return handle->m_State->ssl_ctx;
}

int quic_server_core::send_packets_out(void *ctx, const struct lsquic_out_spec *specs, unsigned n_specs)
{
    struct msghdr msg;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    quic_server_core *handle = (quic_server_core *)ctx;

    for (n = 0; n < n_specs; ++n)
    {
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = sizeof(struct sockaddr_in);
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        if (sendmsg(handle->m_State->sockfd, &msg, 0) < 0)
        {
            perror("cannot send\n");
            break;
        }
    }

    return (int) n;
}

void quic_server_core::server_read_net_data(EV_P_ ev_io *w, int revents)
{
    quic_server_core* handle = (quic_server_core*)w->data;
    BasicState *state    = handle->m_State;
    
    ssize_t nread;
    struct sockaddr_storage peer_sas, local_sas;
    unsigned char buf[4096];
    unsigned char ctl_buf[CTL_SZ];
    struct iovec vec[1] = {{ buf, sizeof(buf) }};

    struct msghdr msg = {
            .msg_name       = &peer_sas,
            .msg_namelen    = sizeof(peer_sas),
            .msg_iov        = vec,
            .msg_iovlen     = 1,
            .msg_control    = ctl_buf,
            .msg_controllen = sizeof(ctl_buf),
    };
    nread = recvmsg(w->fd, &msg, 0);
    if (-1 == nread)
    {
        if (!(EAGAIN == errno || EWOULDBLOCK == errno))
            LOG_ERROR("recvmsg: %s", strerror(errno));
        
        return;
    }

    LOG_INFO("socket receive_size {}", nread);
    
    local_sas = state->local_sas;
    // TODO handle ECN properly
    int ecn = 0;

    tut_proc_ancillary(&msg, &local_sas, &ecn);

    (void) lsquic_engine_packet_in(state->engine, buf, nread,
                                   (struct sockaddr *) &local_sas,
                                   (struct sockaddr *) &peer_sas,
                                   (void *) handle, ecn);


    handle->server_process_conns(state);

}


struct sockaddr_in quic_server_core::new_addr(char *ip, unsigned int port)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    return addr;
}

int quic_server_core::create_sock(char *ip, unsigned int port, struct sockaddr_storage *local_sas)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        LOG_ERROR("Error creating socket");
        return -1;
    }

    /* 非阻塞模式 */
    int flags = fcntl(sockfd, F_GETFL);
    if (-1 == flags)
        return -1;
    flags |= O_NONBLOCK;
    if (0 != fcntl(sockfd, F_SETFL, flags))
        return -1;

    struct sockaddr_in local_addr = new_addr(ip, port);

    /* ToS is used to get ECN value */
    int on, s;
    on = 1;
    //if (AF_INET == local_addr.sa_family)
    s = setsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on));
    //else
    //    s = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof(on));
    if (s != 0)
    {
        perror("setsockopt(ecn)");
        return -1;
    }

    if(bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0) {
        printf("Cannot bind");
        fflush(stdout);
        return -1;
    }

    if(!memcpy(local_sas, &local_addr, sizeof(struct sockaddr_storage))) {
        printf("memcpy local_sas error\n");
        fflush(stdout);
        return -1;
    }
    return sockfd;
}

lsquic_conn_ctx_t * quic_server_core::server_on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn)
{
    LOG_INFO("On new connection");
    lsquic_conn_ctx_t *conn_h = new lsquic_conn_ctx_t;
    memset(conn_h, 0, sizeof(lsquic_conn_ctx_t));

    conn_h->quic_core_handle = ea_stream_if_ctx;
    conn_h->conn = conn;

    quic_server_core* handle = (quic_server_core*)ea_stream_if_ctx;
    handle->m_connect_queue.push_back(conn_h);
    
    return conn_h;
}

void quic_server_core::server_on_conn_closed_cb(lsquic_conn_t *conn)
{
    LOG_INFO("On connection close");
    char errbuf[2048] = {0};
    enum LSQUIC_CONN_STATUS status = lsquic_conn_status(conn, errbuf, 2048);
    LOG_INFO("status {} errbuf {}", status, errbuf);

    lsquic_conn_ctx_t *conn_h = lsquic_conn_get_ctx(conn);
    if(conn_h)
    {
        quic_server_core* handle = (quic_server_core*)conn_h->quic_core_handle;
        auto iter = find(handle->m_connect_queue.begin(), handle->m_connect_queue.end(), handle->m_connect_queue.size());
        if(iter != handle->m_connect_queue.end())
        {
            handle->m_connect_queue.erase(iter);
        }
        
        delete conn_h;
    }

    //quic_server_core *handle = (quic_server_core *) lsquic_conn_get_ctx(conn);
    LOG_INFO("client connection closed -- stop reading from socket");
}


lsquic_stream_ctx_t* quic_server_core::server_on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream)
{
    LOG_INFO("On new stream");

    lsquic_stream_ctx *st_h = new lsquic_stream_ctx;
    memset(st_h, 0, sizeof(lsquic_stream_ctx));

    st_h->quic_core_handle = ea_stream_if_ctx;
    st_h->stream = stream;
    
    lsquic_stream_wantread(stream, 1);
    //tmpServerState->stream = stream;
    return st_h;
}

void quic_server_core::server_on_close_cb (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    LOG_DEBUG("ON CLOSE");
    delete st_h;
}

void quic_server_core::server_on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    unsigned char buf[4096] = {0};

    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));
    if (nr > 0)
    {
        //fwrite(buf, 1, nread, stdout);
        snprintf(h->buf + h->buf_used, sizeof(h->buf), "%s", buf);
        h->buf_used += nr;

        if(h->buf[h->buf_used - 1] == '\n' || h->buf_used == sizeof(h->buf))
        {
            lsquic_stream_wantread(stream, 0);
            lsquic_stream_wantwrite(stream, 1);
        }
        LOG_INFO("Read {} frome server: {} ", nr, buf);
        //fflush(stdout);
    }
    else if (nr == 0)
    {
        /* EOF */
        LOG_INFO(" read to end-of-stream: close and read from stdin again ");
        lsquic_stream_shutdown(stream, 0);

        if (h->buf_used)
            lsquic_stream_wantwrite(stream, 1);
    }
    else
    {
        LOG_ERROR(" read to end-of-stream: close and read from stdin again ");
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
}

void quic_server_core::server_on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    ssize_t nw = 0;
    nw = lsquic_stream_write(stream, h->buf, h->buf_used);
    if(nw > 0)
    {
        h->buf_used -= (size_t)nw;
        if(0 == h->buf_used)
        {
            LOG_INFO("wrote all {} bytes to stream, switch to reading", nw);
            
            lsquic_stream_flush(stream);
            lsquic_stream_wantwrite(stream, 0);
            lsquic_stream_wantread(stream, 1);
        }
        else
        {
            memmove(h->buf, h->buf + nw, h->buf_used);
            LOG_INFO("wrote  {} bytes to stream, still have {} bytes to write", (size_t) nw, h->buf_used);
        }
    }
    else
    {
        printf("stream_write() returned %ld, abort connection\n", (long) nw);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
    
}

void quic_server_core::server_process_conns_cb(EV_P_ ev_timer *conn_watcher, int revents)
{
    quic_server_core* handle = (quic_server_core*)conn_watcher->data;
    handle->server_process_conns(handle->m_State);
}

void quic_server_core::server_process_conns(BasicState *state)
{
    int diff;
    ev_tstamp timeout;

    ev_timer_stop(state->loop, &state->conn_watcher);
    lsquic_engine_process_conns(state->engine);
    if (lsquic_engine_earliest_adv_tick(state->engine, &diff))
    {
        if (diff >= LSQUIC_DF_CLOCK_GRANULARITY)
        {
            timeout = (ev_tstamp) diff / 1000000;
        }
        else if (diff <= 0)
        {
            timeout = 0;
        }
        else
        {
             /* Round up to granularity */
            timeout = (ev_tstamp) LSQUIC_DF_CLOCK_GRANULARITY / 1000000;
        }

        //printf("FUN[%s]-time[%lld]: \n", __FUNCTION__, timeout);
        ev_timer_init(&state->conn_watcher, quic_server_core::server_process_conns_cb, timeout, 0.);
        ev_timer_start(state->loop, &state->conn_watcher);
    }
    else
    {
        //printf("FUN[%s]- adv_tick  return abnormal\n", __FUNCTION__);
        LOG_ERROR("adv_tick  return abnormal");
    }
}


