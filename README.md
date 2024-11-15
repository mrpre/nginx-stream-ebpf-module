# Nginx Stream eBPF module

A module that use ebpf to accelerate nginx stream proxy forward. The usage is at the end of article.  
The main principle is that zero hack for Nginx source code and provide a separated module to accelerate stream proxy.  
Test success from nginx-1.15.0 to latest(nginx-1.27.0) with kernel version >= 4.18.

Note that the latest kernel version (near 6.9) has defect with sockmap, I have send a patch to fix it, do not use
latest kernel before it's merged and released.  

patch: https://git.kernel.org/bpf/bpf/c/2ce9abd6e1e1  

# Performance Test

Nginx configuration is supplied at the end of README.  

## Direct test

First we run iperf client and server on same host without any proxy.  

## start iperf
Run iperf server. We bind server to CPU 6 client  
```
iperf3 -p 20001 -s -A 6
```

Run iperf client as download mode(-R) and bind it to CPU 5  
```
[root]# iperf3 -p 20001 -c 127.0.0.1 -R -A 5 -t 100
Connecting to host 127.0.0.1, port 20001
Reverse mode, remote host 127.0.0.1 is sending
[  5] local 127.0.0.1 port 42726 connected to 127.0.0.1 port 20001
[ ID] Interval           Transfer     Bitrate
[  5]   0.00-1.00   sec  8.49 GBytes  72.9 Gbits/sec
[  5]   1.00-2.00   sec  8.51 GBytes  73.1 Gbits/sec
[  5]   2.00-3.00   sec  8.51 GBytes  73.1 Gbits/sec
[  5]   3.00-4.00   sec  8.52 GBytes  73.2 Gbits/sec
[  5]   4.00-5.00   sec  8.49 GBytes  72.9 Gbits/sec
[  5]   5.00-6.00   sec  8.50 GBytes  73.0 Gbits/sec
```
Speed is up to 73 Gbits/sec.  


## Native Nginx stream proxy test

Now we still run iperf client and server on same host, but proxied by native Nginx stream proxy mode.  


### Nginx config  

Forward all stream between local 0.0.0.0:10001 and remote 127.0.0.1:20001.  
```
# bind worker process to CPU1
worker_processes  1;
worker_cpu_affinity 0001;
...
    # it's iperf server we runned later
    upstream perf_servsers {
        server 127.0.0.1:20001;
    }
    
    server {
        listen 10001;
        ebpf_enable off;
        proxy_pass perf_servsers;
    }
..
```

### start iperf
Run iperf server. We bind server to CPU6 which is different from Nginx worker process and client.  
```
iperf3 -p 20001 -s -A 6
```

Run iperf client as download mode(-R) and bind it to CPU5  
```
[root]# iperf3 -p 10001 -c 127.0.0.1 -R -A 5 -t 100
Connecting to host 127.0.0.1, port 10001
Reverse mode, remote host 127.0.0.1 is sending
[  5] local 127.0.0.1 port 39452 connected to 127.0.0.1 port 10001
[ ID] Interval           Transfer     Bitrate
[  5]   0.00-1.00   sec  3.22 GBytes  27.6 Gbits/sec
[  5]   1.00-2.00   sec  3.24 GBytes  27.8 Gbits/sec
[  5]   2.00-3.00   sec  3.22 GBytes  27.7 Gbits/sec
[  5]   3.00-4.00   sec  3.22 GBytes  27.7 Gbits/sec
[  5]   4.00-5.00   sec  3.25 GBytes  27.9 Gbits/sec
[  5]   5.00-6.00   sec  3.24 GBytes  27.9 Gbits/sec
[  5]   6.00-7.00   sec  3.23 GBytes  27.8 Gbits/sec
[  5]   7.00-8.00   sec  3.22 GBytes  27.6 Gbits/sec
[  5]   8.00-9.00   sec  3.24 GBytes  27.8 Gbits/sec
[  5]   9.00-10.00  sec  3.23 GBytes  27.7 Gbits/sec
[  5]  10.00-11.00  sec  3.23 GBytes  27.7 Gbits/sec
[  5]  11.00-12.00  sec  3.25 GBytes  27.9 Gbits/sec
[  5]  12.00-13.00  sec  3.25 GBytes  27.9 Gbits/sec
```   

The Speed now is up to 27 Gbits/sec only.  


CPU usage detail by `mpstat -P ALL 1`:
```
Average:     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
Average:     all    0.25    0.00    3.30    0.00    0.03    0.97    0.00    0.00    0.00   95.44
Average:       0    4.83    0.00   66.33    0.00    0.33   28.50    0.00    0.00    0.00    0.00
Average:       1    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       2    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       3    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       4    0.00    0.00    0.00    0.00    0.17    0.00    0.00    0.00    0.00   99.83
Average:       5    4.71    0.00   39.22    0.00    0.39    3.53    0.00    0.00    0.00   52.16
Average:       6    0.83    0.00   20.40    0.00    0.17    0.33    0.00    0.00    0.00   78.28
```

## eBPF accelerate for Stream proxy  


Forward all stream between local 0.0.0.0:10000 and remote 127.0.0.1:20001 using ebpf.  
```
# bind worker process to CPU1
worker_processes  1;
worker_cpu_affinity 0001;
...
    # it's iperf server we runned later
    upstream perf_servsers {
        server 127.0.0.1:20001;
    }
    
    server {
        listen 10000;
        ebpf_enable on;
        proxy_pass perf_servsers;
    }
..
```

### start iperf  

Run iperf server. We bind server to CPU6 which is different from Nginx worker process and client.  
```
iperf3 -p 20001 -s -A 6
```  

Run iperf client as download mode(-R) and bind it to CPU 5  
```
[root]# iperf3 -p 10000 -c 127.0.0.1 -R -A 5 -t 10
Connecting to host 127.0.0.1, port 10000
Reverse mode, remote host 127.0.0.1 is sending
[  5] local 127.0.0.1 port 57144 connected to 127.0.0.1 port 10000
[ ID] Interval           Transfer     Bitrate
[  5]   0.00-1.00   sec  3.95 GBytes  33.9 Gbits/sec
[  5]   1.00-2.00   sec  3.95 GBytes  34.0 Gbits/sec
[  5]   2.00-3.00   sec  3.99 GBytes  34.3 Gbits/sec
[  5]   3.00-4.00   sec  3.99 GBytes  34.3 Gbits/sec
[  5]   4.00-5.00   sec  3.99 GBytes  34.3 Gbits/sec
[  5]   5.00-6.00   sec  3.99 GBytes  34.3 Gbits/sec
[  5]   6.00-7.00   sec  4.00 GBytes  34.4 Gbits/sec
[  5]   7.00-8.00   sec  4.00 GBytes  34.4 Gbits/sec
[  5]   8.00-9.00   sec  3.99 GBytes  34.3 Gbits/sec
[  5]   9.00-10.00  sec  4.00 GBytes  34.3 Gbits/sec
```

The Speed is much higher than native Nginx stream proxy mode but still not meeting our expectations. 

CPU usage detail by `mpstat -P ALL 1`:
```
Average:     CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
Average:     all    0.11    0.00    3.95    0.00    0.03    1.25    0.00    0.00    0.00   94.65
Average:       0    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       1    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       2    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       3    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       4    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
Average:       5    3.33    0.00   58.89    0.00    0.56   15.00    0.00    0.00    0.00   22.22
Average:       6    0.50    0.00   73.00    0.00    0.50   26.00    0.00    0.00    0.00    0.00
```

It's weird that only 2 cpu works with high load which both are bounded to iperf client and server. 

`top` command indicate that ebpf code also run on CPU 0
```
 170941 root      20   0       0      0      0 R  30.2   0.0   0:44.01 kworker/6:2+events
```  

It seems if kernel processes a packet on a specific CPU softirq, the eBPF code runs on the corresponding kthread on that CPU.  


I try not to bind iperf to specify cpu so that iperf server can be scheduled to different CPU.  

```
iperf3 -p 20001 -s
```


```
[root]# iperf3 -p 10000 -c 127.0.0.1 -R -t 10
Connecting to host 127.0.0.1, port 10000
Reverse mode, remote host 127.0.0.1 is sending
[  5] local 127.0.0.1 port 20001 connected to 127.0.0.1 port 59914
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  5.49 GBytes  47.1 Gbits/sec    0    639 KBytes
[  5]   1.00-2.00   sec  6.14 GBytes  52.8 Gbits/sec    0    639 KBytes
[  5]   3.00-4.00   sec  6.11 GBytes  52.5 Gbits/sec    0    639 KBytes
[  5]   4.00-5.00   sec  6.12 GBytes  52.6 Gbits/sec    0    639 KBytes
[  5]   5.00-6.00   sec  6.12 GBytes  52.6 Gbits/sec    0    639 KBytes
```  
Now the speed is what we excepted.   

## support ebpf cpu affinity  
Currently, kernel does not support cpu affinity for sockmap. I modify the kernel and rebuild it.  
Still, we bind iperf server to CPU5 and iperf client to CPU6, and then set sockmap to CPU10(should be bound to the cpu as same as the `worker_cpu_affinity` specify, but I just doing the test)  
```
	# both bpf_map_update_elem_opts and bpf_map_update_opts are new feature.
	__u64 target_cpu = 10;
        LIBBPF_OPTS(bpf_map_update_opts, opts);
        opts.target_cpu = &target_cpu;
        //if (bpf_map_update_elem(global_ctx->sockmap_fd, &idx, &fd, BPF_ANY) < 0) {
        if (bpf_map_update_elem_opts(global_ctx->sockmap_fd, &idx, &fd, BPF_ANY, &opts) < 0) {
        ......
```

```
[root@]# iperf3 -p 10000 -c 127.0.0.1 -R  -A 6 -t 10
Connecting to host 127.0.0.1, port 10000
Reverse mode, remote host 127.0.0.1 is sending
[  5] local 127.0.0.1 port 56518 connected to 127.0.0.1 port 10000
[ ID] Interval           Transfer     Bitrate
[  5]   0.00-1.00   sec  7.76 GBytes  66.6 Gbits/sec
[  5]   1.00-2.00   sec  7.76 GBytes  66.7 Gbits/sec
[  5]   2.00-3.00   sec  7.76 GBytes  66.7 Gbits/sec
[  5]   3.00-4.00   sec  7.76 GBytes  66.7 Gbits/sec
[  5]   4.00-5.00   sec  7.76 GBytes  66.7 Gbits/sec
[  5]   5.00-6.00   sec  7.77 GBytes  66.7 Gbits/sec
[  5]   6.00-7.00   sec  7.76 GBytes  66.7 Gbits/sec
[  5]   7.00-8.00   sec  7.77 GBytes  66.7 Gbits/sec
[  5]   8.00-9.00   sec  7.76 GBytes  66.7 Gbits/sec
```
The speed is very near to the direct mode(63 Gbits/sec)  

```
04:14:45 PM  CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
04:14:46 PM  all    0.06    0.00    7.27    0.00    0.00    1.94    0.00    0.00    0.00   90.73
04:14:46 PM    0    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM    1    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM    2    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM    3    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM    4    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM    5    0.00    0.00   73.74    0.00    0.00   26.26    0.00    0.00    0.00    0.00
04:14:46 PM    6    2.06    0.00   93.81    0.00    0.00    4.12    0.00    0.00    0.00    0.00
04:14:46 PM    7    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM    8    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM    9    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00    0.00  100.00
04:14:46 PM   10    0.00    0.00   67.68    0.00    0.00   32.32    0.00    0.00    0.00    0.00
```
and the the CPU affinity works correctly.  


### why eBPF code running on the cpu which process the receive packet  
The stream_verdict process will save received packet into `psock->ingress_skb` and call `schedule_delayed_work` with delay 0  
```
static int sk_psock_skb_redirect(struct sk_psock *from, struct sk_buff *skb) 
{
	...
	skb_queue_tail(&psock_other->ingress_skb, skb);
	schedule_delayed_work(&psock_other->work, 0);
	spin_unlock_bh(&psock_other->ingress_lock);
	return 0;
}
```

Although `queue_delayed_work` set target CPU as `WORK_CPU_UNBOUND` by default, but kernel still prefer to select current CPU to execute work.  
```
*
 * When queueing an unbound work item to a wq, prefer local CPU if allowed
 * by wq_unbound_cpumask.  Otherwise, round robin among the allowed ones to
 * avoid perturbing sensitive tasks.
 */
static int wq_select_unbound_cpu(int cpu)
{
	int new_cpu;

	if (likely(!wq_debug_force_rr_cpu)) {
		if (cpumask_test_cpu(cpu, wq_unbound_cpumask))
			return cpu;
	} else {
		pr_warn_once("workqueue: round-robin CPU selection forced, expect performance impact\n");
	}
......
```
Then I enable `debug_force_rr_cpu` by `echo "Y" > /sys/module/workqueue/parameters/debug_force_rr_cpu` to force kernel randomize target CPU, but find ebpf still run on the same CPU due to iperf just send large response by one stream and kernel thread is stuck in the one loop

```
static void sk_psock_backlog(struct work_struct *work)
{
    ...
	while ((skb = skb_peek(&psock->ingress_skb))) {
        ...
	}
	...
```  

# Usage

## build dependency 
`clang elfutils-libelf-devel`

```
# download current module
git clone --recurse-submodules https://ithub.com/mrpre/nginx-stream-ebpf-module.git

# enter Nginx source tree then use --add-module to add the module you download before.
# eBPF and it's dependency will be compiled at configure time
./configure --add-module=/PATH/nginx-stream-ebpf-module --with-stream --prefix=/root/nginxbuild/

# build & install
make;make install

```

# Note
1. `user` directive must be used with privileged users like `root`,`admin`, etc. Alternatively you can set `/proc/sys/kernel/unprivileged_bpf_disabled` to 0 if your kernel support it to use unprivileged user.  
2. Currently we have no way to install ebpf kern object to nginx install path at build time. We just use `xxd` command to convert object into C array as part of elf segment of `nginx` binary.  
3. `worker_connections` must not greater than macro `EBPF_MAP_SIZE` defined in  `ebpf_kern.c`
4. Because we use a separated module, most native stream proxy command become invalid. Create issue if you want.  

# Nginx test configuration  
```
user  root;
worker_processes  1;
worker_cpu_affinity 0001;

error_log  /root/nginxbuild/logs/error.log debug;

events {
    worker_connections  1024;
}

stream {
    upstream download_servers {
        server 127.0.0.1:8000;
    }
    upstream upload_servers {
        server 127.0.0.1:8001;
    }
    upstream perf_servsers {
        server 127.0.0.1:20001;
    }

    # idle timeout if no data forwarded between downstream and upstream
    ebpf_proxy_timeout 600;
    # enable ebpf in main layer
    ebpf_enable on;

    server {
        listen 8081;
        proxy_pass upload_servers;
    }

    server {
        listen 8080;
        set $my_servers download_servers;
        proxy_pass $my_servers;
    }

    server {
        listen 10000;
        ebpf_enable on;
        proxy_pass perf_servsers;
    }

    server {
        listen 10001;
        ebpf_enable off;
        proxy_pass perf_servsers;
    }

    server {
        listen 30001;
        ebpf_enable off;
        ebpf_status_return;
    }
}
```
