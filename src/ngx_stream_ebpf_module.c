#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_ebpf_module.h>
#include <ngx_ebpf.h>
typedef struct {
    struct ngx_stream_ebpf_obj_ctx *global_ctx;
    ngx_flag_t                      ebpf_enable;
    ngx_stream_content_handler_pt   handler;
    ngx_resolver_handler_pt         resolver_handler;
    ngx_uint_t                      timeout;
    ngx_uint_t                      buffer_size;
    ngx_uint_t                      timer_period;
    ngx_str_t                       addr;
} ngx_stream_ebpf_srv_conf_t;


static ngx_int_t
ngx_stream_ebpf_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ebpf_add_variables(ngx_conf_t *cf);
static void *ngx_stream_ebpf_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ebpf_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_stream_ebpf_init(ngx_conf_t *cf);
static char *ngx_stream_ebpf_status_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_stream_ebpf_proxy_downstream_handler(ngx_event_t *ev);
static void ngx_stream_ebpf_proxy_upstream_handler(ngx_event_t *ev);
static void ngx_stream_ebpf_proxy_upstream_connect_handler(ngx_event_t *ev);
static void ngx_stream_ebpf_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc);
static void ngx_stream_ebpf_proxy_process(ngx_event_t *ev, ngx_int_t from_upstream);
static void ngx_stream_ebpf_timer_handler(ngx_event_t *ev);


ngx_int_t ngx_stream_ebpf_init_process(ngx_cycle_t *cycle);
static ngx_command_t  ngx_stream_ebpf_commands[] = {

    // show debug info
    { ngx_string("ebpf_status_return"),
      NGX_STREAM_SRV_CONF|NGX_CONF_NOARGS,
      ngx_stream_ebpf_status_return,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("ebpf_enable"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ebpf_srv_conf_t, ebpf_enable),
      NULL },

    { ngx_string("ebpf_proxy_timeout"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ebpf_srv_conf_t, timeout),
      NULL },

    { ngx_string("ebpf_proxy_buffer_size"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ebpf_srv_conf_t, buffer_size),
      NULL },

     { ngx_string("ebpf_timer_period"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ebpf_srv_conf_t, timer_period),
      NULL },
      ngx_null_command
};

static ngx_stream_module_t  ngx_stream_ebpf_module_ctx = {
    ngx_stream_ebpf_add_variables,     /* preconfiguration */
    ngx_stream_ebpf_init,              /* postconfiguration */
    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */
    ngx_stream_ebpf_create_srv_conf,   /* create server configuration */
    ngx_stream_ebpf_merge_srv_conf     /* merge server configuration */
};

ngx_module_t  ngx_stream_ebpf_module = {
    NGX_MODULE_V1,
    &ngx_stream_ebpf_module_ctx,              /* module context */
    ngx_stream_ebpf_commands,                 /* module directives */
    NGX_STREAM_MODULE,                        /* module type */
    NULL,                                     /* init master */
    NULL,                                     /* init module */
    ngx_stream_ebpf_init_process,             /* init process */
    NULL,                                     /* init thread */
    NULL,                                     /* exit thread */
    NULL,                                     /* exit process */
    NULL,                                     /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_stream_variable_t  ngx_stream_ebpf_vars[] = {

    { ngx_string("ebpf_var"), NULL,
      ngx_stream_ebpf_variable, 0, 0, 0 },

      ngx_stream_null_variable
};

static ngx_int_t
ngx_stream_ebpf_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data)
{
    //ngx_stream_ebpf_ctx_t  *ctx;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_ebpf_add_variables(ngx_conf_t *cf)
{
    ngx_stream_variable_t  *var, *v;

    for (v = ngx_stream_ebpf_vars; v->name.len; v++) {
        var = ngx_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_stream_ebpf_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_ebpf_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_ebpf_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->ebpf_enable = NGX_CONF_UNSET;
    conf->global_ctx = NGX_CONF_UNSET_PTR;
    conf->timeout = NGX_CONF_UNSET;
    conf->timer_period = NGX_CONF_UNSET;
    conf->buffer_size = NGX_CONF_UNSET;
    return conf;
}


static char *
ngx_stream_ebpf_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_stream_ebpf_srv_conf_t  *prev = parent;
    ngx_stream_ebpf_srv_conf_t  *conf = child;

    ngx_conf_merge_value(conf->ebpf_enable, prev->ebpf_enable, 0);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 10 * 60000);
    ngx_conf_merge_msec_value(conf->timer_period, prev->timer_period, 2000);
    ngx_conf_merge_msec_value(conf->buffer_size, prev->buffer_size, 16384);

    return NGX_CONF_OK;
}


static void
ngx_stream_ebpf_status_return_handler(ngx_stream_session_t *s)
{
    ngx_str_t                      text;
    ngx_buf_t                     *b;
    ngx_connection_t              *c;
    ngx_chain_t                   *chain;
    c = s->connection;
    b = ngx_calloc_buf(c->pool);
    if (b == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    text.data = (u_char*)"aaa";
    text.len = 3;
    b->memory = 1;
    b->pos = text.data;
    b->last = text.data + text.len;
    b->last_buf = 1;

    chain = ngx_alloc_chain_link(c->pool);
    if (chain == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    chain->buf = b;
    chain->next = NULL;

    if (ngx_stream_top_filter(s, chain, 1) == NGX_ERROR) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
}


static char *
ngx_stream_ebpf_status_return(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_core_srv_conf_t          *cscf;
    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_ebpf_status_return_handler;
    return NGX_CONF_OK;
}

static void
ngx_stream_ebpf_proxy_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_connection_t             *c, *pc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;

    s = ctx->data;
    u = s->upstream;
    c = s->connection;
    ngx_log_error(NGX_LOG_INFO, c->log, 0, NGX_STREAM_LOG_PREFIX"resolve handler");

    ngx_stream_ebpf_srv_conf_t *escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);
    escf->resolver_handler(ctx);

    c->read->handler = ngx_stream_ebpf_proxy_downstream_handler;
    c->write->handler = ngx_stream_ebpf_proxy_downstream_handler;

    u = s->upstream;
    pc = u->peer.connection;
    pc->read->handler = ngx_stream_ebpf_proxy_upstream_connect_handler;
    pc->write->handler = ngx_stream_ebpf_proxy_upstream_connect_handler;

    return;
}

static void
ngx_stream_ebpf_timer_handler(ngx_event_t *ev) {
    ngx_connection_t             *c, *pc;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_ebpf_srv_conf_t   *escf;
    ngx_uint_t                    traffic;
    struct ngx_sock_meta          meta;

    c = ev->data;
    s = c->data;
    u = s->upstream;
    pc = u->peer.connection;

    escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);
    ngx_log_debug(NGX_LOG_ERR, c->log, 0, "ngx_stream_ebpf_timer_handler");

    traffic = 0;
    // fixme:
    // the traffic info forwarded by userspace is erased by meta
    if (!ngx_ebpf_get_meta_fd(c->log, escf->global_ctx, c, &meta)) {
        if (c->sent != (off_t)meta.forward
            || u->received != (off_t)meta.forward) {
            traffic = 1;
        }
        c->sent = meta.forward;
        u->received = meta.forward;
    }

    if (!ngx_ebpf_get_meta_fd(c->log, escf->global_ctx, pc, &meta)) {
        if (pc->sent != (off_t)meta.forward
            || s->received != (off_t)meta.forward) {
                traffic = 1;
        }
        pc->sent = meta.forward;
        s->received = meta.forward;
    }
    
    if (traffic) {
        ngx_event_add_timer(pc->write, escf->timeout);
    }
    ngx_add_timer(c->write, escf->timer_period);
}

static void
ngx_stream_ebpf_proxy_downstream_handler(ngx_event_t *ev)
{
    ngx_connection_t             *c, *pc;
    ngx_stream_session_t         *s;
    ngx_buf_t                    *b;
    ngx_stream_upstream_t        *u;
    ngx_stream_ebpf_ctx_t        *ctx;
    ssize_t                       n;
    size_t                        size;
    ngx_int_t                     readed;
    c = ev->data;
    s = c->data;
    u = s->upstream;
    b = &u->downstream_buf;
    pc = u->peer.connection;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
        NGX_STREAM_LOG_PREFIX
        "downstream handler");
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ebpf_module);
    readed = ctx->client_read;
    for(;;) {
        b = &u->downstream_buf;
        size = b->last - b->pos;
        if (size == 0) {
            b->pos = b->start;
            b->last = b->start;
        }
        size = b->end - b->last;
        n = c->recv(c, b->last, size);
        if (n == NGX_AGAIN) {
            break;
        }

        if (n <= 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, n, "downstream closed");
            ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
            return;
        }
        b->last += n;
        ctx->client_read += n;
    }

    // readed == 0 means client
    if (readed == 0 && u->connected && pc) {
        ngx_stream_ebpf_proxy_process(pc->read, 0);
    }

    return;
}


static ngx_int_t
ngx_stream_proxy_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void
ngx_stream_ebpf_proxy_upstream_handler(ngx_event_t *ev)
{
    ngx_stream_ebpf_proxy_process(ev, 1);
}

// from_upstream means it's from downstream handler
// ev always the pc's ev
static void
ngx_stream_ebpf_proxy_process(ngx_event_t *ev, ngx_int_t from_upstream)
{
    //ngx_stream_ebpf_srv_conf_t   *escf;
    ngx_connection_t             *pc, *c;
    ngx_stream_session_t         *s;
    ngx_stream_upstream_t        *u;
    ngx_stream_ebpf_ctx_t        *ctx;
    ngx_stream_ebpf_srv_conf_t   *escf;
    ngx_buf_t                    *b;
    ssize_t                       n,size;


    pc = ev->data;
    s = pc->data;
    c = s->connection;
    u = s->upstream;

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0, "ngx_stream_ebpf_proxy_process s %p from_upstream %z", s, from_upstream);

    if (pc->close) {
        ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "shutdown timeout");
        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "timed out");
        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ebpf_module);
    escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);

    // whenerer it read from, just send it to peer, and remain on fly data will be forwarded by ebpf

    // I know it's ugly but it works...
    for(;;) {
        // read from client
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "ngx_stream_ebpf_proxy_process forwarding data from client");

        b = &u->downstream_buf;
        size = b->last - b->pos;
        if (size == 0) {
            b->pos = b->start;
            b->last = b->start;
            size = b->end - b->last;
            n = c->recv(c, b->last, size);
            if (n == NGX_AGAIN) {
                // no data, or typically s->connection has not been added to ep yet
                if (ctx->client_read == 0) {
                    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                        ngx_log_error(NGX_LOG_NOTICE, c->log, n, "client ngx_handle_read_event fail from_upstream");
                        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
                    }
                    // wait trigger downstream handler
                }
                break;
            }

            if (n <= 0) {
                ngx_log_error(NGX_LOG_NOTICE, c->log, n, "fail to read first packet from client");
                ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
                return;
            }
            b->last += n;
            ctx->client_read += n;
        }
    
        size = b->last - b->pos;
        n = pc->send(pc, b->pos, (ssize_t)size);
        if (n <= 0 || n != size) {
            ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "send first packet fail from client to upstream");
            ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
            return;
        }
        b->pos += n;
    }
    
    for(;;) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "ngx_stream_ebpf_proxy_process forwarding data from upstream");


        if (u->upstream_buf.start == NULL) {
            u_char *p= ngx_pnalloc(c->pool, escf->buffer_size);
            if (p == NULL) {
                ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            u->upstream_buf.start = p;
            u->upstream_buf.end = p + escf->buffer_size;
            u->upstream_buf.pos = p;
            u->upstream_buf.last = p;
        }
        b = &u->upstream_buf;

        size = b->last - b->pos;
        if (size == 0) {
            b->pos = b->start;
            b->last = b->start;
            size = b->end - b->last;
            n = pc->recv(pc, b->last, size);
            if (n == NGX_AGAIN) {
                break;
            }

            if (n <= 0) {
                ngx_log_error(NGX_LOG_NOTICE, c->log, n, "fail to read first packet from upstream, %d", n);
                ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
                return;
            }
            b->last += n;
        }
    
        size = b->last - b->pos;
        n = c->send(c, b->pos, (ssize_t)size);
        if (n <= 0 || n != size) {
            ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, "send first packet fail from upstream to client");
            ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
            return;
        }
        b->pos += n;
    }

    // idle time out, set one side event is enough
    // will be flesh by ngx_stream_ebpf_timer_handler
    ngx_event_add_timer(pc->write, escf->timeout);

    // pc handler used to update meta info like traffic
    if (!c->write->timer_set) {
        (void)ngx_stream_ebpf_timer_handler;
        c->write->handler = ngx_stream_ebpf_timer_handler;
        ngx_add_timer(c->write, escf->timer_period);
    }

    if (ev->pending_eof) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0, "EPOLLRDHUP detected, close it");
        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_OK);
        return;
    }
 
    return;
}

static void
ngx_stream_ebpf_proxy_upstream_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t             *c, *pc;
    ngx_stream_session_t         *s;
    ngx_stream_ebpf_srv_conf_t   *escf;
    ngx_stream_ebpf_ctx_t        *ctx;
    ngx_stream_upstream_t        *u;
    int                           err;
    pc = ev->data;
    s = pc->data;
    c = s->connection;
    u = s->upstream;
    ngx_log_error(NGX_LOG_NOTICE, pc->log, 0, NGX_STREAM_LOG_PREFIX"upstream connect handler");

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, pc->log, NGX_ETIMEDOUT, "upstream timed out");
        //ngx_stream_proxy_next_upstream(s);
        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }
    
    if (ngx_stream_proxy_test_connect(pc) != NGX_OK) {
        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        //ngx_stream_proxy_next_upstream(s);
        return;
    }

    // connect timeout
    if (pc->write->timer_set) {
        ngx_del_timer(pc->write);
    }

    s->upstream->connected = 1;
    pc->read->handler = ngx_stream_ebpf_proxy_upstream_handler;
    pc->write->handler = ngx_stream_ebpf_proxy_upstream_handler;

    escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ebpf_module);

    // sleep can be used to generate race condition
    // sleep(5);
    
    // combine 2 connection. it's like route table, used in 'stream_verdict'
    if ((err = ngx_ebpf_register_proxymap_fd(c->log, escf->global_ctx, ctx, c, pc, u->peer.sockaddr)) < 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, NGX_STREAM_LOG_PREFIX"ngx_ebpf_register_proxymap_fd fail %d", err);
        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    // make ebpf kern function waked on packeted received
    if ((err = ngx_ebpf_register_sockmap_fd(c->log, escf->global_ctx, c, pc)) < 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, NGX_STREAM_LOG_PREFIX"ngx_ebpf_register_sockmap_fd fail %d", err);
        ngx_stream_ebpf_proxy_finalize(s, NGX_STREAM_BAD_GATEWAY);
        return;
    }
    ctx->ebpf_inited = 1;

    
    // race condition here, before we add sockmap before
    // client may already send data and kernel save it to socket receive queue so it must be processed by origin path
    c->log->action = "forward data by userspace";
    ngx_stream_ebpf_proxy_process(ev, 1);
    c->log->action = "forward data by ebpf";
    return;
}

static void
ngx_stream_ebpf_finalize(ngx_stream_session_t *s) {
    ngx_connection_t             *c, *pc;
    ngx_stream_upstream_t        *u;
    ngx_stream_ebpf_ctx_t        *ctx;
    ngx_stream_ebpf_srv_conf_t   *escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);
    
    c = s->connection;

    u = s->upstream;
    if (u == NULL) {
        return;
    }
    pc = u->peer.connection;
    if (pc == NULL) {
        return;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ebpf_module);
    if (ctx->ebpf_inited) {
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "finalize stream ebpf fd");
        ngx_ebpf_unregister_proxymap_fd(c->log, escf->global_ctx, ctx);
        ngx_ebpf_unregister_sockmap_fd(c->log, escf->global_ctx, c, pc);
        ngx_ebpf_unregister_metamap_fd(c->log, escf->global_ctx, c, pc);
    }
}

static void
ngx_stream_ebpf_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream ebpf proxy: %i", rc);

    ngx_stream_ebpf_finalize(s);
    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        if (u->state->response_time == (ngx_msec_t) -1) {
            //u->state->response_time = ngx_current_msec - u->start_time;
        }

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        state = 0;

        if (pc && pc->type == SOCK_DGRAM
            && (pc->read->error || pc->write->error))
        {
            state = NGX_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "close stream proxy upstream connection: %d", pc->fd);

#if (NGX_STREAM_SSL)
        if (pc->ssl) {
            pc->ssl->no_wait_shutdown = 1;
            (void) ngx_ssl_shutdown(pc);
        }
#endif

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

noupstream:

    ngx_stream_finalize_session(s, rc);
}

static void
ngx_stream_ebpf_proxy_handler(ngx_stream_session_t *s)
{
    ngx_connection_t            *c;
    ngx_connection_t            *pc;
    ngx_stream_upstream_t       *u;
    ngx_stream_ebpf_ctx_t       *ctx;
    ngx_stream_ebpf_srv_conf_t  *escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);

    if (escf->global_ctx == NGX_CONF_UNSET_PTR) {
        // not inited before
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0, NGX_STREAM_LOG_PREFIX"ngx_stream_ebpf_proxy_handler without ebpf object");
        escf->handler(s);
        return;
    }


    // handler = ngx_stream_proxy_handler
    // We have this assumption that since the socket is set to non-blocking mode,
    // the 'connect' call will always return EAGAIN, which means there won't be any data read or write operations.
    escf->handler(s);
    if (s->status != 0) {
        // handler call ngx_stream_proxy_finalize
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, NGX_STREAM_LOG_PREFIX"stream proxy process failed and ignore ebpf process, status %d", s->status);
        return;
    }

    if (s->upstream == NULL 
        || s->upstream->peer.connection == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, NGX_STREAM_LOG_PREFIX"stream proxy process not call upstream process");
        return;
    }

    c = s->connection;
    c->read->handler = ngx_stream_ebpf_proxy_downstream_handler;
    c->write->handler = ngx_stream_ebpf_proxy_downstream_handler;

    u = s->upstream;
    pc = u->peer.connection;
    pc->read->handler = ngx_stream_ebpf_proxy_upstream_connect_handler;
    pc->write->handler = ngx_stream_ebpf_proxy_upstream_connect_handler;

    if (u->resolved && u->resolved->ctx) {
        escf->resolver_handler = u->resolved->ctx->handler;
        u->resolved->ctx->handler = ngx_stream_ebpf_proxy_resolve_handler;
    }

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_ebpf_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_ebpf_ctx_t));
        if (ctx == NULL) {
            return;
        }

        ngx_stream_set_ctx(s, ctx, ngx_stream_ebpf_module);
        ctx->client_read = 0;
    }
    return;
}


ngx_int_t ngx_stream_ebpf_init_process(ngx_cycle_t *cycle) {

    ngx_uint_t                      s;
    ngx_stream_core_srv_conf_t     *cscf, **cscfp;
    ngx_stream_ebpf_srv_conf_t     *escf;
    ngx_stream_core_main_conf_t    *cmcf;

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

    ngx_log_debug(NGX_LOG_DEBUG_STREAM, cycle->log, 0, NGX_STREAM_LOG_PREFIX"ngx_stream_ebpf_init_process from_upstream");

    for (s = 0; s < cmcf->servers.nelts; s++) {
        cscf = cscfp[s]->ctx->srv_conf[ngx_stream_core_module.ctx_index];
        escf = cscfp[s]->ctx->srv_conf[ngx_stream_ebpf_module.ctx_index];

        if (!escf->ebpf_enable) {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, cycle->log, 0, NGX_STREAM_LOG_PREFIX"ebpf_enable not enabled, escf %p", escf);
            return NGX_OK;
        }
#if nginx_version >= 1025004
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, NGX_STREAM_LOG_PREFIX"%V server ebpf enabled, now init it", &escf->addr);
#else
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, NGX_STREAM_LOG_PREFIX"finding server ebpf enabled, now init it");
#endif
        escf->global_ctx = ngx_ebpf_init(cycle->log);;
        if (escf->global_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "call 'ngx_ebpf_init' fail");
            // recover
            cscf->handler = escf->handler;
            return NGX_OK;
        }
        ngx_log_debug(NGX_LOG_DEBUG_STREAM, cycle->log, 0, "escf %p global_ctx %p", escf, escf->global_ctx);
    }
    return NGX_OK;
}

/*
// called when session closed
static ngx_int_t
ngx_stream_ebpf_log_handler(ngx_stream_session_t *s)
{
    // clear map on session close
    ngx_connection_t *c;
    ngx_connection_t *pc;
    ngx_stream_upstream_t  *u;
    ngx_stream_ebpf_srv_conf_t *escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);
    
    c = s->connection;
    u = s->upstream;
    pc = u->peer.connection;

    return NGX_OK;
}
*/

#if nginx_version >= 1025004
static ngx_stream_conf_addr_t *
get_srv_conf_addr(ngx_stream_core_main_conf_t *cmcf, ngx_stream_core_srv_conf_t *cscf) {
    ngx_stream_conf_port_t        *port;
    ngx_stream_conf_addr_t        *addr;
    ngx_uint_t                   a, p, s;
    ngx_uint_t                   p_len, s_len, a_len;
    ngx_stream_core_srv_conf_t    **servers;

    port = cmcf->ports->elts;
    p_len = cmcf->ports->nelts;
    for (p = 0; p < p_len; p++) {
        addr = port[p].addrs.elts;
        a_len = port[p].addrs.nelts;
        for (a = 0; a < a_len; a++) {
            servers = addr[a].servers.elts;
            s_len = addr[a].servers.nelts;
            for (s = 0; s < s_len; s++) {
                if (servers[s] == cscf) {
                    return addr;
                }
            }
        }
    }
    
    return NULL;
}
#endif

ngx_int_t ngx_stream_ebpf_init(ngx_conf_t *cf)
{
    ngx_uint_t                     s;
    ngx_stream_core_srv_conf_t    *cscf, **cscfp;
    ngx_stream_ebpf_srv_conf_t    *escf;
    ngx_stream_core_main_conf_t   *cmcf;
#if (NGX_STREAM_SSL)
#if nginx_version >= 1025005
    ngx_stream_ssl_srv_conf_t     *sscf;
#else
     ngx_stream_ssl_conf_t     *sscf;
#endif
#endif
#if nginx_version >= 1025004
    ngx_stream_conf_addr_t        *addr;
#endif
    ngx_uint_t                     ebpf_enabled; 
    
    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;
    
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, NGX_STREAM_LOG_PREFIX"ngx_stream_ebpf_init");
    
    ebpf_enabled = 0;
    for (s = 0; s < cmcf->servers.nelts; s++) {
#if (NGX_STREAM_SSL)
        sscf = cscfp[s]->ctx->srv_conf[ngx_stream_ssl_module.ctx_index];
#endif
        cscf = cscfp[s]->ctx->srv_conf[ngx_stream_core_module.ctx_index];
        escf = cscfp[s]->ctx->srv_conf[ngx_stream_ebpf_module.ctx_index];
        if (!escf->ebpf_enable) {
            ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, NGX_STREAM_LOG_PREFIX"ebpf_enable not enabled");
            continue;
        }
#if (NGX_STREAM_SSL)
        if (sscf->ssl.ctx != NULL) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, NGX_STREAM_LOG_PREFIX"ssl is enabled which conflict with ebpf");
            return NGX_ERROR;
        }
#endif
        /* no content handler found*/
        if (!cscf->handler) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, NGX_STREAM_LOG_PREFIX"proxy_pass should be configured with ebpf_enable");
            return NGX_ERROR;
        }
        escf->handler = cscf->handler;

        ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, NGX_STREAM_LOG_PREFIX"ebpf proxy enable, replace stream proxy process, cscf %p", cscf);
        cscf->handler = ngx_stream_ebpf_proxy_handler;
#if nginx_version >= 1025004
        addr = get_srv_conf_addr(cmcf, cscf);
        escf->addr.data = ngx_pstrdup(cf->pool, &addr->opt.addr_text);
        escf->addr.len = addr->opt.addr_text.len;
#endif
        ebpf_enabled = 1;

    /*
        h = ngx_array_push(&cmcf->phases[NGX_STREAM_LOG_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        // now use ngx_stream_ebpf_proxy_finalize instead
        *h = ngx_stream_ebpf_log_handler;
    */
    }

    // used to test when load config
    if (ebpf_enabled == 1) {
        struct ngx_stream_ebpf_obj_ctx *global_ctx = ngx_ebpf_init(cf->log);
        if (global_ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 0, NGX_STREAM_LOG_PREFIX"init ebpf error");
            return NGX_ERROR;
        }
        ngx_ebpf_obj_free(global_ctx);
    }
    // it's main process, and we do not need such info
    //escf->global_ctx = global_ctx;
    return NGX_OK;
}
