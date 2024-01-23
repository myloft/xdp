#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_UDP_SIZE 1480

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline void ipv4_csum(void *data_start, int data_size, __u32 *csum)
{
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper(*csum);
}

static inline __u16 udp_csum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)udph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += udph->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2)
    {
        if ((void *)(buf + 1) > data_end)
        {
            break;
        }

        csum_buffer += *buf;
        buf++;

        // Handle overflow
        if (csum_buffer > 0xFFFF)
        {
            csum_buffer -= 0xFFFF;
        }
    }

    if ((void *)buf + 1 <= data_end)
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}
