#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <ngx_stream_ebpf_module.h>
#include <bpf_utils.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

NGX_EBPF_KERN_OBJ_DEFINE;
NGX_EBPF_KERN_OBJ_LEN_DEFINE;

// as ngx_cycle->connections are linear memory, we can use address offset as connection index
static int ngx_get_connection_id(ngx_connection_t *c) {
	return c - ngx_cycle->connections;
}

static int ngx_libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	ngx_log_t tmpLog = *ngx_cycle->log;
	char errstr[NGX_MAX_ERROR_STR];
	char *p = errstr;
	// print libbpf log level
	#if (!NGX_DEBUG)
	if (level == LIBBPF_DEBUG) {
		return 0;
	}
	#endif
	int preLen = snprintf(p, NGX_MAX_ERROR_STR, "[%s] ", (level == LIBBPF_WARN)?"WARN":((level == LIBBPF_INFO)?"INFO":"DEBUG"));
	vsnprintf(p + preLen, NGX_MAX_ERROR_STR - preLen, format, args);
	
	// just print to error.log
	tmpLog.log_level = NGX_LOG_NOTICE;
	ngx_log_error(NGX_LOG_NOTICE, &tmpLog, 0, (char*)errstr);
	return 0;
}

void ngx_ebpf_obj_free(struct ngx_stream_ebpf_obj_ctx *global_ctx) {
	struct bpf_object *obj = (struct bpf_object *)global_ctx->bpf_object;
	bpf_object__close(obj);
	ngx_free(global_ctx);
}

int ngx_ebpf_get_meta_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, struct ngx_sock_meta *out) {
	int err;
	int connection_idx = ngx_get_connection_id(c);
	err = bpf_map_lookup_elem(global_ctx->meta_fd, &connection_idx, out);
	if (err < 0) {
		if (errno != ENOENT) {
			ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX"bpf_map_lookup_elem meta failed");
			return 1;
		}
		return 2;
	}
	return 0;
}

int ngx_ebpf_unregister_proxymap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_stream_ebpf_ctx_t *ctx) {
	int err;
	err = bpf_map_delete_elem(global_ctx->proxy_map_fd, ctx->client_key);
	if (err < 0) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX"delete client proxy map failed, %z", err);
	}

	err = bpf_map_delete_elem(global_ctx->proxy_map_fd, ctx->upstream_key);
	if (err < 0) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX"delete upstream proxy map failed, %z", err);
	}
	return 0;
}

int ngx_ebpf_register_proxymap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, 
	ngx_stream_ebpf_ctx_t *ctx, ngx_connection_t *c, ngx_connection_t *pc, struct sockaddr *upstream_addr) {
	struct ngx_sock_tuple tuple_key;
	struct sockaddr 	  addr;
	struct sockaddr 	  addr2;
	__u32 				  connection_id;
	socklen_t 			  socklen = sizeof(struct sockaddr);
	
	// use c->sockaddr instead
	if (getpeername(c->fd, &addr, &socklen)) {
		return NGX_ERROR;
	}

	if (getsockname(c->fd, &addr2, &socklen)) {
		return NGX_ERROR;
	}
	ngx_ebpf_proxy_map_key(&addr, &addr2, &tuple_key);

	memcpy(ctx->client_key, &tuple_key, sizeof(struct ngx_sock_tuple));
		
	// it's also sockmap index
	connection_id = ngx_get_connection_id(pc);
	if (bpf_map_update_elem(global_ctx->proxy_map_fd, &tuple_key, &connection_id, BPF_ANY) < 0) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX" call 'bpf_map_update_elem' fail");
		return NGX_ERROR;
	}
	ngx_log_debug4(NGX_LOG_DEBUG_STREAM, log, 0, NGX_STREAM_LOG_PREFIX"client tuple_key %z %z %z %z",
		tuple_key.laddr,tuple_key.lport, tuple_key.raddr, tuple_key.rport);

	if (getsockname(pc->fd, (struct sockaddr*)&addr, &socklen)) {
		return NGX_ERROR;
	}
	
	ngx_ebpf_proxy_map_key(upstream_addr, &addr, &tuple_key);
	memcpy(ctx->upstream_key, &tuple_key, sizeof(struct ngx_sock_tuple));
	
	// it's also sockmap index
	connection_id = ngx_get_connection_id(c);
	if (bpf_map_update_elem(global_ctx->proxy_map_fd, &tuple_key, &connection_id, BPF_ANY) < 0) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX" call 'bpf_map_update_elem' fail");
		return NGX_ERROR;
	}
	
	ngx_log_debug4(NGX_LOG_DEBUG_STREAM, log, 0, NGX_STREAM_LOG_PREFIX"upstream tuple_key %z %z %z %z",
		tuple_key.laddr,tuple_key.lport, tuple_key.raddr, tuple_key.rport);

	return NGX_OK;
}

/*
Actually kernel will automatically clean socket in sockmap when socket state changed to TCP_CLOSE:
in kernel func tcp_set_state()
  case TCP_CLOSE:
      sk->sk_prot->unhash()

'unhash' handler is set to sock_map_unhash():
  sock_map_unhash
  -- sock_map_remove_links
  ---- sock_map_unlink
       *link_raw = NULL
where link_raw is pointer to sockmap idx addr

kernel return EINVAL if sock already empty
*/
int ngx_ebpf_unregister_sockmap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, ngx_connection_t *pc) {
	
	int err;
	__u32 idx = ngx_get_connection_id(c);
	err = bpf_map_delete_elem(global_ctx->map_fd, &idx);
	if (err < 0 && errno != EINVAL) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX"delete client sock map failed, %d", err);
	}

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   NGX_STREAM_LOG_PREFIX"delete client sock map: %z", idx);

	idx = ngx_get_connection_id(pc);

	err = bpf_map_delete_elem(global_ctx->map_fd, &idx);
	if (err < 0 && errno != EINVAL) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX"delete upstream sock map failed, %d", err);
	}
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   NGX_STREAM_LOG_PREFIX"delete upstream sock map: %z", idx);

	return 0;
}

int ngx_ebpf_unregister_metamap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, ngx_connection_t *pc) {
	
	int err;
	__u32 idx = ngx_get_connection_id(c);

	err = bpf_map_delete_elem(global_ctx->meta_fd, &idx);
	if (err < 0 && errno != ENOENT) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX"delete client meta map failed, %d", err);
	}
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   NGX_STREAM_LOG_PREFIX"delete client meta map: %z", idx);

	idx = ngx_get_connection_id(pc);

	err = bpf_map_delete_elem(global_ctx->meta_fd, &idx);
	if (err < 0 && errno != ENOENT) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX"delete upstream meta map failed, %d", err);
	}
	ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
				NGX_STREAM_LOG_PREFIX"delete upstream ent meta map: %z", idx);

	return 0;
}

int ngx_ebpf_register_sockmap_fd(ngx_log_t *log, struct ngx_stream_ebpf_obj_ctx *global_ctx, ngx_connection_t *c, ngx_connection_t *pc) {
	
	// kernel function `sock_map_update_common` will replace sk's `sk_data_ready` handler with `sk_psock_strp_data_ready`
	__u32 idx = ngx_get_connection_id(c);
	__u32 fd =  c->fd;
	//__u64 target_cpu = 10;
	if (bpf_map_update_elem(global_ctx->map_fd, &idx, &fd, BPF_ANY) < 0) {
	//if (bpf_map_update_elem_cpu(global_ctx->map_fd, &idx, &fd, BPF_ANY, &target_cpu) < 0) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX" call 'bpf_map_update_elem' fail");
		return NGX_ERROR;
	}
	ngx_log_error(NGX_LOG_ERR, log, 0, NGX_STREAM_LOG_PREFIX" update sock map index %z to client fd %z", idx, fd);


	idx = ngx_get_connection_id(pc);
	fd = pc->fd;
	//target_cpu = 11;
	if (bpf_map_update_elem(global_ctx->map_fd, &idx, &fd, BPF_ANY) < 0) {
	//if (bpf_map_update_elem_cpu(global_ctx->map_fd, &idx, &fd, BPF_ANY, &target_cpu) < 0) {
		ngx_log_error(NGX_LOG_ERR, log, errno, NGX_STREAM_LOG_PREFIX" call 'bpf_map_update_elem' fail");
		return NGX_ERROR;
	}
	
	ngx_log_error(NGX_LOG_ERR, log, 0, NGX_STREAM_LOG_PREFIX" update sock map index %z to upstream fd %z", idx, fd);

	return NGX_OK;
}

struct ngx_stream_ebpf_obj_ctx * ngx_ebpf_init(ngx_log_t *log) {
	struct bpf_object *obj;
	struct bpf_program *prog_paser;
	struct bpf_program *prog_redirect;
	struct ngx_stream_ebpf_obj_ctx *global_ctx;

	struct rlimit rlim = {
		.rlim_cur = 1024 * 1024 * 1024,
		.rlim_max = 1024 * 1024 * 1024,
	};
	/* ignore error */
	setrlimit(RLIMIT_MEMLOCK, &rlim);

	libbpf_set_print(ngx_libbpf_print_fn);
    
	if (NGX_EBPF_KERN_OBJ_LEN == 0) {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
                              NGX_STREAM_LOG_PREFIX" ebpf object not exist");
		return NULL;
	}
	errno = 0;
	// it's just parse bpf binary code
	obj = bpf_object__open_mem(NGX_EBPF_KERN_OBJ , NGX_EBPF_KERN_OBJ_LEN , NULL);
	if (libbpf_get_error(obj)) {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
                              NGX_STREAM_LOG_PREFIX" call 'bpf_object__open_mem' fail");
		return NULL;
	}
	ngx_log_error(NGX_LOG_NOTICE, log, 0,
                              NGX_STREAM_LOG_PREFIX"open nginx stream ebpf code success");
	
	// load prog
	int err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		ngx_log_error(NGX_LOG_EMERG, log, errno,
							NGX_STREAM_LOG_PREFIX"call 'bpf_object__load' fail, error code %d", err);
		return NULL;
	}
	
	ngx_log_error(NGX_LOG_INFO, log, 0,
                              NGX_STREAM_LOG_PREFIX"load nginx stream ebpf code success");

	// attach prog
	int sockmap_fd = bpf_object__find_map_fd_by_name(obj, "sock_map");
	int sockhash_fd = bpf_object__find_map_fd_by_name(obj, "sock_hash");
	int proxymap_fd = bpf_object__find_map_fd_by_name(obj, "proxy_map");
	int metamap_fd = bpf_object__find_map_fd_by_name(obj, "meta_map");
	int map_fd;
	prog_paser = bpf_object__find_program_by_name(obj, "stream_parser");
	if (prog_paser == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
							NGX_STREAM_LOG_PREFIX"call 'bpf_object__find_program_by_name' fail, error code %d", err);
		return NULL;
	}

	if (sockmap_fd > 0) {
		map_fd =  sockmap_fd;
	} else if (sockhash_fd > 0) {
		map_fd = sockhash_fd;
	} else {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
							NGX_STREAM_LOG_PREFIX"can not find sockmap or sockhash in ebpf kern code");
		return NULL;
	}

	err = bpf_prog_attach(bpf_program__fd(prog_paser), map_fd , BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
							NGX_STREAM_LOG_PREFIX"call 'bpf_object__find_program_by_name' fail, error code %d", err);
		return NULL;
	}
	prog_redirect = bpf_object__find_program_by_name(obj, "stream_verdict");
	if (prog_redirect == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
							NGX_STREAM_LOG_PREFIX"call 'bpf_object__find_program_by_name' fail, error code %d", err);
		return NULL;
	}
	
	err = bpf_prog_attach(bpf_program__fd(prog_redirect), map_fd , BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
							NGX_STREAM_LOG_PREFIX"call 'bpf_prog_attach' fail, error code %d", err);
		return NULL;
	}
	ngx_log_error(NGX_LOG_INFO, log, 0,
							NGX_STREAM_LOG_PREFIX"attach nginx stream ebpf code success, fd %d/%d %d %d", sockmap_fd, sockhash_fd, proxymap_fd, metamap_fd);

	global_ctx = ngx_alloc(sizeof(*global_ctx), log);
	if (global_ctx == NULL) {
		ngx_log_error(NGX_LOG_EMERG, log, errno,
							NGX_STREAM_LOG_PREFIX"alloc global_ctx fail");
		return NULL;
	}

	global_ctx->bpf_object = obj;
	global_ctx->proxy_map_fd = proxymap_fd;
	global_ctx->sockmap_fd = sockmap_fd;
	global_ctx->sockhash_fd = sockhash_fd;
	global_ctx->map_fd = map_fd;
	global_ctx->meta_fd = metamap_fd;
	global_ctx->prog_parser_fd = bpf_program__fd(prog_paser);
	global_ctx->prog_redirect_fd = bpf_program__fd(prog_redirect);
	return global_ctx;
}
