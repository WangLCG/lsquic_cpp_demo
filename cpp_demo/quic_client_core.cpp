////////////////////////////////////////////////////////////////////////
/// @file       quic_client_core.cpp
/// @brief      quic客户端通信核心定义
/// @details    quic客户端通信核心定义
/// @author     王超
/// @version    1.0
/// @date       2021/11/10
/// @copyright  (c) 2021-2031 。保留所有权利
////////////////////////////////////////////////////////////////////////
#include "quic_client_core.h"

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

quic_client_core::quic_client_core(const quic_infos &infos) : m_quci_infos(infos)
{
    m_type = m_quci_infos.type;
}

quic_client_core::~quic_client_core()
{
    if(m_State)
    {
        delete m_State;
        m_State = nullptr;
    }

    lsquic_engine_destroy(m_State->engine);
    lsquic_global_cleanup();
}

bool quic_client_core::init()
{
    if(m_quci_infos.type == LIVE_QUCI_TYPE_CLIENT )
    {
        m_State = (BasicState*)new ClientState;
    }
    
    m_State->quic_core_handle = (void *)this;

    m_State->buf_total_size = 4096;
    m_State->buf  = new char[m_State->buf_total_size];
    memset(m_State->buf, 0, m_State->buf_total_size);
    
    struct sockaddr_in peer_addr = new_addr((char*)m_quci_infos.peer_ip.c_str(), m_quci_infos.peer_port);

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

    int on = 1;
    if( 0 != setsockopt(m_State->sockfd, IPPROTO_IP, IP_RECVTOS, &on, sizeof(on) ) )
    {
        perror("fcntl");
        return false;
    }

    socklen_t socklen;
    m_State->local_sas.ss_family = AF_INET;
    socklen = sizeof(m_State->local_sas);
    if (0 != bind(m_State->sockfd,  (struct sockaddr *) &m_State->local_sas, socklen))
    {
        perror("bind");
        return false;
    }

    if(0 != set_fd_nonblocking(STDIN_FILENO) )
    {
        perror("fcntl");
        return false;
    }
    
    create_event_loop();

    //lsquic_logger_init(&logger_if, stderr, LLTS_HHMMSSUS);
    //lsquic_set_log_level("debug");

    int flags = 0;
    lsquic_engine_init_settings(&m_State->engine_settings, flags);
    m_State->engine_settings.es_ecn      = LSQUIC_DF_ECN;

    init_ssl_ctx();

    if (0 != lsquic_global_init(m_quci_infos.type))
    {
        printf("Cannot init\n");
        fflush(stdout);
        return false;
    }

    memset(&m_stream_if, 0, sizeof(m_stream_if));
    if(m_quci_infos.type == LIVE_QUCI_TYPE_CLIENT)
    {
        m_stream_if.on_new_conn            = quic_client_core::client_on_new_conn_cb;
        m_stream_if.on_conn_closed         = quic_client_core::client_on_conn_closed_cb;
        m_stream_if.on_new_stream          = quic_client_core::client_on_new_stream_cb;
        m_stream_if.on_read                = quic_client_core::client_on_read_cb;
        m_stream_if.on_write               = quic_client_core::client_on_write_cb;
        m_stream_if.on_hsk_done            = quic_client_core::client_on_hsk_done;
        m_stream_if.on_close               = quic_client_core::client_on_close_cb;
    }

    memset(&m_engine_api, 0, sizeof(m_engine_api));
    m_engine_api.ea_pmi             = NULL;
    m_engine_api.ea_pmi_ctx         = NULL;

    m_engine_api.ea_settings        = &m_State->engine_settings;

    m_engine_api.ea_packets_out     = quic_client_core::send_packets_out;
    m_engine_api.ea_packets_out_ctx = (void *) m_State;
    m_engine_api.ea_stream_if       = &m_stream_if;
    m_engine_api.ea_stream_if_ctx   = (void *) m_State;


    //m_engine_api.ea_get_ssl_ctx     = quic_client_core::get_ssl_ctx;
    //m_engine_api.ea_lookup_cert     = quic_client_core::no_cert;

    m_engine_api.ea_alpn = "echo";

    char err_buf[100] = {0};
    if (0 != lsquic_engine_check_settings(&m_State->engine_settings, 0, err_buf, sizeof(err_buf)))
    {
        printf("###### Error in settings: %s", err_buf);
        return -1;
    }

    m_State->engine = lsquic_engine_new(0, &m_engine_api);
    
    if(m_quci_infos.type == LIVE_QUCI_TYPE_CLIENT )
    {
        if( NULL == lsquic_engine_connect(m_State->engine, N_LSQVER,
                                                (struct sockaddr *) &m_State->local_sas,
                                                (struct sockaddr *) &peer_addr, (void *) &m_State->sockfd, NULL,
                                                NULL, 0, NULL, 0, NULL, 0))
        {
            printf("Cannot create connection\n");
            fflush(stdout);
            return false;
        }
    }

    client_process_conns(m_State);
    //lsquic_engine_process_conns(m_State->engine);

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

void quic_client_core::create_event_loop()
{
    m_State->loop = ev_loop_new(EVFLAG_AUTO);
    
    ev_io_init (&m_State->sock_watcher, quic_client_core::client_read_net_data, m_State->sockfd, EV_READ);
    ev_io_start (m_State->loop, &m_State->sock_watcher);

    if(m_quci_infos.type == LIVE_QUCI_TYPE_CLIENT)
    {
        ClientState* client= (ClientState*)m_State;
        ev_io_init (&client->read_local_data_ev, quic_client_core::client_read_local_data, STDIN_FILENO, EV_READ);
        
        ev_init(&m_State->conn_watcher, quic_client_core::client_process_conns_cb);

        client->read_local_data_ev.data = this;
    }

    m_State->sock_watcher.data  = this;
    m_State->conn_watcher.data  = this;
}


struct ssl_ctx_st * quic_client_core::no_cert (void *cert_lu_ctx, const struct sockaddr *sa_UNUSED, const char *sni)
{
    return NULL;
}

int quic_client_core::init_ssl_ctx ()
{
    unsigned char ticket_keys[48];

    m_State->ssl_ctx = SSL_CTX_new(TLS_method());
    if (!m_State->ssl_ctx)
    {
        printf("cannot allocate SSL context\n");
        return -1;
    }

    SSL_CTX_set_min_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(m_State->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_default_verify_paths(m_State->ssl_ctx);

    /* This is obviously test code: the key is just an array of NUL bytes */
    memset(ticket_keys, 0, sizeof(ticket_keys));
    if (1 != SSL_CTX_set_tlsext_ticket_keys(m_State->ssl_ctx,
                                        ticket_keys, sizeof(ticket_keys)))
    {
        printf("SSL_CTX_set_tlsext_ticket_keys failed \n");
        return -1;
    }

    return 0;
}

SSL_CTX * quic_client_core::get_ssl_ctx (void * ctx, const struct sockaddr *)
{
    quic_client_core* handle = (quic_client_core*) ctx;
    return handle->m_State->ssl_ctx;
}

int quic_client_core::send_packets_out(void *ctx, const struct lsquic_out_spec *specs, unsigned n_specs)
{
    struct msghdr msg;
    unsigned n;

    memset(&msg, 0, sizeof(msg));
    BasicState *State = (BasicState *)ctx;

    for (n = 0; n < n_specs; ++n)
    {
        msg.msg_name       = (void *) specs[n].dest_sa;
        msg.msg_namelen    = sizeof(struct sockaddr_in);
        msg.msg_iov        = specs[n].iov;
        msg.msg_iovlen     = specs[n].iovlen;
        if (sendmsg(State->sockfd, &msg, 0) < 0)
        {
            perror("cannot send\n");
            break;
        }
    }

    return (int) n;
}

struct sockaddr_in quic_client_core::new_addr(char *ip, unsigned int port)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    return addr;
}

int quic_client_core::create_sock(char *ip, unsigned int port, struct sockaddr_storage *local_sas)
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

    if(!memcpy((void*)local_sas, (void*)&local_addr, sizeof(struct sockaddr_storage))) {
        printf("memcpy local_sas error\n");
        fflush(stdout);
        return -1;
    }
    return sockfd;
}

lsquic_conn_ctx_t * quic_client_core::client_on_new_conn_cb(void *ea_stream_if_ctx, lsquic_conn_t *conn)
{
    LOG_INFO("On new connection");
    
    lsquic_conn_make_stream(conn);
    return (lsquic_conn_ctx_t *)ea_stream_if_ctx;
}

lsquic_stream_ctx_t* quic_client_core::client_on_new_stream_cb(void *ea_stream_if_ctx, lsquic_stream_t *stream)
{
    LOG_INFO("On new stream");
    ClientState *tmpClientState = (ClientState *) ea_stream_if_ctx;
    tmpClientState->stream = stream;
    return (lsquic_stream_ctx_t*)ea_stream_if_ctx;
}

void quic_client_core::client_on_conn_closed_cb(lsquic_conn_t *conn)
{
    LOG_INFO("On connection close");
    char errbuf[2048] = {0};
    enum LSQUIC_CONN_STATUS status = lsquic_conn_status(conn, errbuf, 2048);
    LOG_INFO("status {} errbuf {} ", status, errbuf);

    ClientState *tmpClientState = (ClientState *) lsquic_conn_get_ctx(conn);
    LOG_INFO("client connection closed -- stop reading from socket");
    ev_io_stop(tmpClientState->loop, &tmpClientState->read_local_data_ev);
}

void quic_client_core::client_on_close_cb (lsquic_stream_t *stream, lsquic_stream_ctx_t *st_h)
{
    LOG_INFO("on client_on_close_cb");
}

void quic_client_core::client_on_hsk_done(lsquic_conn_t *conn, enum lsquic_hsk_status status)
{
    ClientState *tmpClientState = (ClientState *) lsquic_conn_get_ctx(conn);

    switch (status)
    {
        case LSQ_HSK_OK:
        case LSQ_HSK_RESUMED_OK:
            LOG_INFO("handshake successful, start stdin watcher");
            ev_io_start(tmpClientState->loop, &tmpClientState->read_local_data_ev);
            //lsquic_conn_make_stream(tmpClientState->conn);
            break;
        default:
            LOG_INFO("handshake failed");
            break;
    }
}

void quic_client_core::client_on_read_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    ClientState *tmpClientState = (ClientState *) h;

    unsigned char buf[1500] = {0};

    ssize_t nr = lsquic_stream_read(stream, buf, sizeof(buf));

    if (nr > 0)
    {
        //fwrite(buf, 1, nread, stdout);
        LOG_INFO("Read {} frome server: {} ", nr, buf);
        //fflush(stdout);
    }
    else if (nr == 0)
    {
        /* EOF */
        LOG_INFO(" read to end-of-stream: close and read from stdin again ");
        lsquic_stream_shutdown(tmpClientState->stream, 0);

        //lsquic_stream_wantread(stream, 0);
        ev_io_start(tmpClientState->loop, &tmpClientState->read_local_data_ev);

        /* 重新开始一个stream */
        lsquic_conn_make_stream(tmpClientState->conn);
    }
    else
    {
        LOG_ERROR(" read to end-of-stream: close and read from stdin again ");
        ev_break(tmpClientState->loop, EVBREAK_ONE);
    }
}

void quic_client_core::client_on_write_cb(lsquic_stream_t *stream, lsquic_stream_ctx_t *h)
{
    ClientState *tmpClientState = (ClientState *) h;

    ssize_t nw = 0;
    //LOG_DEBUG("To write byte {} ", tmpClientState->size);
    nw = lsquic_stream_write(stream, tmpClientState->buf, tmpClientState->size);
    if(nw > 0)
    {
        tmpClientState->size -= (size_t)nw;
        if(0 == tmpClientState->size)
        {
            LOG_INFO("wrote all {} bytes to stream, switch to reading", nw);
            
            lsquic_stream_flush(stream);
            lsquic_stream_wantwrite(stream, 0);
            ev_io_start(tmpClientState->loop, &tmpClientState->read_local_data_ev);
            lsquic_stream_wantread(stream, 1);
        }
        else
        {
            memmove(tmpClientState->buf, tmpClientState->buf + nw, tmpClientState->size);
            LOG_INFO("wrote  {} bytes to stream, still have {} bytes to write", (size_t) nw, tmpClientState->size);
        }
    }
    else
    {
        printf("stream_write() returned %ld, abort connection\n", (long) nw);
        lsquic_conn_abort(lsquic_stream_conn(stream));
    }
    
}

void quic_client_core::client_read_net_data(EV_P_ ev_io *w, int revents)
{
    quic_client_core* handle = (quic_client_core*)w->data;
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
    if (-1 == nread) {
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


    handle->client_process_conns(state);

}


void quic_client_core::client_read_local_data (EV_P_ ev_io *w, int revents)
{
    quic_client_core* handle = (quic_client_core*)w->data;
    ClientState *state   = (ClientState*)handle->m_State;

    assert(state->size < state->buf_total_size);
    ssize_t read_bytes = read(w->fd, state->buf + state->size, state->buf_total_size);
    if(read_bytes > 0)
    {
        state->size += read_bytes;
        if (state->buf[state->size - 1] == '\n'
            || state->size == state->buf_total_size)
        {
            LOG_INFO("read up to newline (or filled buffer): to write stream");
            lsquic_stream_wantwrite(state->stream, 1);
            ev_io_stop(state->loop, w);
            handle->client_process_conns(state);
        }
    }
    else if (read_bytes == 0)
    {
        LOG_INFO("read EOF: stop reading from stdin, close connection");
        ev_io_stop(state->loop, w);
        ev_io_stop(state->loop, &state->read_local_data_ev);
        lsquic_conn_close(state->conn);
        handle->client_process_conns(state);
    }
    else
    {
        LOG_INFO("error reading from stdin: {}", strerror(errno));
        ev_break(state->loop, EVBREAK_ONE);
    }
    
}


void quic_client_core::client_process_conns_cb(EV_P_ ev_timer *conn_watcher, int revents)
{
    quic_client_core* handle = (quic_client_core*)conn_watcher->data;
    handle->client_process_conns(handle->m_State);
}

void quic_client_core::client_process_conns(BasicState *state)
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
        ev_timer_init(&state->conn_watcher, quic_client_core::client_process_conns_cb, timeout, 0.);
        ev_timer_start(state->loop, &state->conn_watcher);
    }
    else
    {
        printf("FUN[%s]- adv_tick  return abnormal\n", __FUNCTION__);
    }
}


