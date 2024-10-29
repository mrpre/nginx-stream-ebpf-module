#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>
#include <bpf_utils.h>
#define NGX_STREAM_LOG_PREFIX "[stream_ebpf] "

typedef struct {
    unsigned char client_key[sizeof(struct ngx_sock_tuple)];
    unsigned char upstream_key[sizeof(struct ngx_sock_tuple)];
    ngx_int_t  client_read;
    ngx_flag_t ebpf_inited;
} ngx_stream_ebpf_ctx_t;

struct ngx_stream_ebpf_obj_ctx {
    void *bpf_object;
    int proxy_map_fd;
    int sockmap_fd;
    int meta_fd;
    int prog_redirect_fd;
    int prog_parser_fd;
};