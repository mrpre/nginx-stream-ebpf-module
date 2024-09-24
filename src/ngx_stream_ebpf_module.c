#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_ebpf_module.h>

typedef struct {
    ngx_flag_t   ebpf_enable;
    ngx_stream_content_handler_pt  handler;
    ngx_resolver_handler_pt resolver_handler;
} ngx_stream_ebpf_srv_conf_t;


typedef struct {
    u_char     *pos;
    ngx_str_t   header;
} ngx_stream_ebpf_ctx_t;

static ngx_int_t
ngx_stream_ebpf_variable(ngx_stream_session_t *s,
    ngx_stream_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_stream_ebpf_add_variables(ngx_conf_t *cf);
static void *ngx_stream_ebpf_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_ebpf_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_stream_ebpf_init(ngx_conf_t *cf);

static void
ngx_stream_ebpf_proxy_downstream_handler(ngx_event_t *ev);
static void
ngx_stream_ebpf_proxy_upstream_handler(ngx_event_t *ev);
static ngx_command_t  ngx_stream_ebpf_commands[] = {

    { ngx_string("ebpf_enable"),
      NGX_STREAM_MAIN_CONF|NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_ebpf_srv_conf_t, ebpf_enable),
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
    NULL,                                     /* init process */
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
    return conf;
}


static char *
ngx_stream_ebpf_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_stream_ebpf_srv_conf_t  *prev = parent;
    ngx_stream_ebpf_srv_conf_t  *conf = child;

    ngx_conf_merge_value(conf->ebpf_enable, prev->ebpf_enable, 0);
    return NGX_CONF_OK;
}

/*
static void
ngx_stream_ebpf_proxy_finalize(ngx_stream_session_t *s, ngx_uint_t rc)
{
    ngx_uint_t              state;
    ngx_connection_t       *pc;
    ngx_stream_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "finalize stream proxy: %i", rc);

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
            u->state->response_time = ngx_current_msec - u->start_time;
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
*/
/*
static u_char *
ngx_stream_ebpf_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char                 *p;
    ngx_connection_t       *pc;
    ngx_stream_session_t   *s;
    ngx_stream_upstream_t  *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(p, len,
                     ", bytes from/to client:%O/%O"
                     ", bytes from/to upstream:%O/%O",
                     s->received, s->connection->sent,
                     u->received, pc ? pc->sent : 0);

    return p;
}
*/

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
    pc->read->handler = ngx_stream_ebpf_proxy_upstream_handler;
    pc->write->handler = ngx_stream_ebpf_proxy_upstream_handler;

    return;
}

static void
ngx_stream_ebpf_proxy_downstream_handler(ngx_event_t *ev)
{
    // ignore event handler
    // we process it by ebpf
    ngx_connection_t             *c;
    ngx_stream_session_t         *s;

    c = ev->data;
    s = c->data;
    (void)s;
    ngx_log_error(NGX_LOG_INFO, c->log, 0, NGX_STREAM_LOG_PREFIX"downstream handler");
    return;
}

static void
ngx_stream_ebpf_proxy_upstream_handler(ngx_event_t *ev)
{
    // ignore event handler
    // we process it by ebpf
    ngx_connection_t             *c;
    ngx_stream_session_t         *s;

    c = ev->data;
    s = c->data;
    (void)s;
    ngx_log_error(NGX_LOG_INFO, c->log, 0, NGX_STREAM_LOG_PREFIX"upstream handler");
    return;
}
/*
static ngx_int_t
ngx_stream_ebpf_proxy_eval(ngx_stream_session_t *s,
    ngx_stream_proxy_srv_conf_t *pscf)
{
    ngx_str_t               host;
    ngx_url_t               url;
    ngx_stream_upstream_t  *u;

    if (ngx_stream_complex_value(s, pscf->upstream_value, &host) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u = s->upstream;

    u->resolved = ngx_pcalloc(s->connection->pool,
                              sizeof(ngx_stream_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return NGX_OK;
}
*/
static void
ngx_stream_ebpf_proxy_handler(ngx_stream_session_t *s)
{
    ngx_connection_t *c;
    ngx_connection_t *pc;
    ngx_stream_upstream_t *u;
    ngx_stream_ebpf_srv_conf_t *escf = ngx_stream_get_module_srv_conf(s, ngx_stream_ebpf_module);
    
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
    pc->read->handler = ngx_stream_ebpf_proxy_upstream_handler;
    pc->write->handler = ngx_stream_ebpf_proxy_upstream_handler;

    if (u->resolved && u->resolved->ctx) {
        escf->resolver_handler = u->resolved->ctx->handler;
        u->resolved->ctx->handler = ngx_stream_ebpf_proxy_resolve_handler;
    }
    
    return;
}

static ngx_int_t
ngx_stream_ebpf_init(ngx_conf_t *cf)
{
    ngx_stream_core_srv_conf_t  *cscf;
    ngx_stream_ebpf_srv_conf_t  *escf;
    ngx_stream_ssl_srv_conf_t   *sscf;
    escf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_ebpf_module);
    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    sscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_ssl_module);
    
    if (!escf->ebpf_enable) {
        ngx_log_error(NGX_LOG_INFO, cf->log, 0, NGX_STREAM_LOG_PREFIX"ebpf_enable not enabled");
        return NGX_OK;
    }
    
    if (sscf->ssl.ctx != NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, NGX_STREAM_LOG_PREFIX"ssl is enabled which conflict with ebpf");
        return NGX_ERROR;
    }

    /* no content handler found*/
    if (!cscf->handler) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, NGX_STREAM_LOG_PREFIX"stream_pass should be configured with ebpf_enable");
        return NGX_ERROR;
    }
    escf->handler = cscf->handler;

    ngx_log_error(NGX_LOG_INFO, cf->log, 0, NGX_STREAM_LOG_PREFIX"ebpf proxy enable, replace stream proxy process");
    cscf->handler = ngx_stream_ebpf_proxy_handler;

    return NGX_OK;
}