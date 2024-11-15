#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_endian.h>
#include "bpf_utils.h"

#define EBPF_MAP_SIZE 100000
#define USE_BPF_MAP 1
//#define EBPF_DEBUG 1 enable by compiler
//#define  EBPF_USE_SOCKHASH 1  enable by compiler
#ifdef USE_BPF_MAP

#if LIBBPF_MAJOR_VERSION > 1
struct bpf_map_def {
        unsigned int type;
        unsigned int key_size;
        unsigned int value_size;
        unsigned int max_entries;
        unsigned int map_flags;
} __attribute__((deprecated("use BTF-defined maps in .maps section")));
#endif

struct bpf_map_def SEC ("maps") proxy_map = {
    . type = BPF_MAP_TYPE_HASH ,
    . key_size = sizeof(struct ngx_sock_tuple),
    . value_size = sizeof(__u32),
    . max_entries = EBPF_MAP_SIZE,
};

struct bpf_map_def SEC ("maps") meta_map = {
    . type = BPF_MAP_TYPE_HASH ,
    . key_size = sizeof(__u32),
    . value_size = sizeof(struct ngx_sock_meta),
    . max_entries = EBPF_MAP_SIZE,
};


#ifdef EBPF_USE_SOCKHASH
//see sock_hash_alloc, key size can be customized
struct bpf_map_def SEC ("maps") sock_hash = {
    . type = BPF_MAP_TYPE_SOCKHASH ,
    . key_size = sizeof(__u32),
    . value_size = sizeof(__u32),
    . max_entries = EBPF_MAP_SIZE,
};
#else
//see sock_map_alloc, key size must be u32 and value_size must be u32 or u64
struct bpf_map_def SEC ("maps") sock_map = {
    . type = BPF_MAP_TYPE_SOCKMAP ,
    . key_size = sizeof(__u32),
    . value_size = sizeof(__u32),
    . max_entries = EBPF_MAP_SIZE,
};
#endif
#elif USE_BTF_MAP

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct sock_tuple);
    __type(value, __u32);
    __uint(max_entries, EBPF_MAP_SIZE);
} proxy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, EBPF_MAP_SIZE);
} sock_map SEC(".maps");
#else
// loader call bpf() to crete map
#endif

// section name:
// libbpf can recognize 'sk_skb' prefix but attach type may not correct
// so we specify the full section name with sk_skb/stream_xxx which hardcoded in libbpf
// more details can be found under function 'sec_def_matches' and definition 'section_defs' in [libbpf]
// function name:
// function name will be referenced in function 'ngx_ebpf_init' and do not change it

// both functions will be called when userspace add 'fd' into map like 'bpf_map_update_elem(sock_map, &idx, &fd, BPF_ANY)'
// log: `cat /sys/kernel/debug/tracing/trace_pipe` 

// strp_data_ready
// - strp_read_sock
// -- strp_recv
// ---- __strp_recv
// ----- sk_psock_strp_read
// ------ cb.parse_msg = sk_psock_strp_parse
// ------ cb.rcv_msg = sk_psock_strp_read
SEC ("sk_skb/stream_parser")
int stream_parser (struct __sk_buff * skb)
{
#ifdef EBPF_DEBUG
    char info_fmt[] = "parse len %d\n" ;
    bpf_trace_printk(info_fmt , sizeof (info_fmt), skb->len);
#endif
    return skb->len;
}

SEC ("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff * skb)
{
    // note that fields in skb/ctx are translated to sk field like:
    // remote_port <-> skc_dport, network byte order 
    // local_port  <-> skc_num, host byte order
    // see `bpf_convert_ctx_access` for more detail 
    __u32 *index = 0;
    __u16 rport = (__u16)bpf_ntohl(skb->remote_port);
    __u32 rip = skb->remote_ip4;
    __u16 lport = (__u16)skb->local_port;
    __u32 lip = skb->local_ip4;
    struct ngx_sock_tuple tuple = {
        .laddr = lip,
        .raddr = rip,
        .lport = lport,
        .rport = rport
    };

    index = bpf_map_lookup_elem(&proxy_map, &tuple);
    if (index == NULL) {
#ifdef EBPF_DEBUG
        char info_fmt[] = "missing val %x %x\n" ;
        bpf_trace_printk(info_fmt , sizeof(info_fmt), lip, lport);
        bpf_trace_printk(info_fmt , sizeof(info_fmt), rip, rport);
#endif

        return SK_PASS;
    }
    // for the received packet, redirect it from a receive queue of some socket
    // to a transmit queue of the socket living in sock_map under *index
#ifdef EBPF_USE_SOCKHASH
    int ret = bpf_sk_redirect_hash(skb, &sock_hash, index , 0);
#else
    int ret = bpf_sk_redirect_map(skb, &sock_map, *index , 0);
#endif
    if (ret == SK_PASS) {
        struct ngx_sock_meta *meta = bpf_map_lookup_elem(&meta_map, index);
        if (meta == NULL) {
            struct ngx_sock_meta new_mata  = {
                .forward = skb->len,
            };
            if (bpf_map_update_elem(&meta_map, index, &new_mata, BPF_ANY)) {
#ifdef EBPF_DEBUG
                char info_fmt[] = "create new meta fail, index %d\n" ;
                bpf_trace_printk(info_fmt , sizeof (info_fmt), *index);
#endif
            }
        } else {
            __sync_fetch_and_add(&meta->forward, skb->len);
            //meta->forward += skb->len;
        }
    }
#ifdef EBPF_DEBUG
    char info_fmt[] = "forward data to index [%d], ret %d\n";
    bpf_trace_printk(info_fmt , sizeof (info_fmt), *index, ret);
#endif
    return ret;
}

char _license [] SEC ( "license" ) = "GPL" ;
