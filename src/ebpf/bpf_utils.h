#ifndef _BPF_UTILS_H_
#define _BPF_UTILS_H_

struct ngx_sock_tuple {
	// network byte order
	__u32 laddr;
	__u32 raddr;
	// port must be host byte order otherwise it exceed the size of 2 bytes
	__u16 lport;
	__u16 rport;
};

struct ngx_sock_meta {
	__u64 forward;
};

static __always_inline __u64 ebpf_proxy_map_key(__u32 addr, __u32 port) {
	__u64 val = addr;
	return (val << 32) | port;
}

#if !defined(__bpf__)
static __always_inline void ngx_ebpf_proxy_map_key(const struct sockaddr *remote_addr, const struct sockaddr *local_addr, struct ngx_sock_tuple *tuple) {
	const struct sockaddr_in *addr = (const struct sockaddr_in *)remote_addr;
	tuple->raddr = addr->sin_addr.s_addr;
	tuple->rport = ntohs(addr->sin_port);
	addr = (const struct sockaddr_in *)local_addr;
	tuple->laddr = addr->sin_addr.s_addr;
	tuple->lport = ntohs(addr->sin_port);
}
#endif
#endif