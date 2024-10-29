struct ngx_stream_ebpf_obj_ctx* ngx_ebpf_init();
void ngx_ebpf_obj_free(struct ngx_stream_ebpf_obj_ctx *global_ctx);
int ngx_ebpf_register_proxymap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_stream_ebpf_ctx_t *ctx, ngx_connection_t *c, ngx_connection_t *pc ,struct sockaddr *upstream_addr);
int ngx_ebpf_register_sockmap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, ngx_connection_t *pc);
int ngx_ebpf_unregister_proxymap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_stream_ebpf_ctx_t *ctx);
int ngx_ebpf_unregister_sockmap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, ngx_connection_t *pc);
int ngx_ebpf_unregister_metamap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, ngx_connection_t *pc);


int ngx_ebpf_get_meta_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, struct ngx_sock_meta *out);