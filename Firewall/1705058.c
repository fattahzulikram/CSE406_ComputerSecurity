#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/inet.h>

#define P 5

static struct nf_hook_ops hook1;

// Mapping:
// 0: 10.9.0.1
// 1: 10.9.0.5
// 2: 192.168.60.6
// 3: 192.168.60.7
int pingCount[10] = {0};

unsigned int blockPPings(void *priv, struct sk_buff *skb,
                         const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct icmphdr *icmph;

    char ip[16] = "192.168.60.5";
    char ip1[16] = "10.9.0.1";
    char ip2[16] = "10.9.0.5";
    char ip3[16] = "192.168.60.6";
    char ip4[16] = "192.168.60.7";
    u32 ip_addr;
    u32 ip_addr1;
    u32 ip_addr2;
    u32 ip_addr3;
    u32 ip_addr4;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);
    in4_pton(ip1, -1, (u8 *)&ip_addr1, '\0', NULL);
    in4_pton(ip2, -1, (u8 *)&ip_addr2, '\0', NULL);
    in4_pton(ip3, -1, (u8 *)&ip_addr3, '\0', NULL);
    in4_pton(ip4, -1, (u8 *)&ip_addr4, '\0', NULL);

    if (iph->protocol == IPPROTO_ICMP)
    {
        icmph = icmp_hdr(skb);
        if (iph->daddr == ip_addr && icmph->type == ICMP_ECHO)
        {
            int index = -1;

            // Check mapping first
            if(iph->saddr == ip_addr1)
            {
                index = 0;
            }
            else if(iph->saddr == ip_addr2)
            {
                index = 1;
            }
            else if(iph->saddr == ip_addr3)
            {
                index = 2;
            }
            else if(iph->saddr == ip_addr4)
            {
                index = 3;
            }
            
            if(pingCount[index] < P)
            {
                pingCount[index]++;
                printk(KERN_INFO "Received ping from %pI4, Current Count: %d\n", &(iph->saddr), pingCount[index]);
            }
            else
            {
                printk(KERN_WARNING "*** Dropping from %pI4 (ICMP)\n", &(iph->saddr));
            	return NF_DROP;
            }
        }
    }
    return NF_ACCEPT;
}

int registerFilter(void)
{
    printk(KERN_INFO "Online: Registering filters.\n");
    hook1.hook = blockPPings;
    hook1.hooknum = NF_INET_PRE_ROUTING;
    hook1.pf = PF_INET;
    hook1.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &hook1);

    return 0;
}

void removeFilter(void)
{
    printk(KERN_INFO "Online: The filters are being removed.\n");
    nf_unregister_net_hook(&init_net, &hook1);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
