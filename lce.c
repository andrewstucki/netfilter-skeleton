#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "lce.h"

#define DEBUG 1

/*
 * Local defnitions of netfilter macros.
 * Some kernels don't appear to pickup
 * the macros properly, despite definition
 * in <linux/netfilter_ipv4.h>
 */

#ifndef NF_IP_LOCAL_IN
#define NF_IP_LOCAL_IN 1
#endif

#ifndef NF_IP_LOCAL_OUT
#define NF_IP_LOCAL_OUT 3
#endif

#if DEBUG > 0
struct sk_buff *sock_buff;
struct iphdr *ip_header;
struct tcphdr *tcp_header;
#endif

static struct nf_hook_ops nf_traffic_in_ops;
static struct nf_hook_ops nf_traffic_out_ops;

static unsigned int hook_traffic_in(unsigned int hooknum,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int (*okfn)(struct sk_buff *))
{
#if DEBUG > 0
  sock_buff = skb;

  if(sock_buff) {

    ip_header = (struct iphdr *)skb_network_header(sock_buff);

    if (ip_header) {
      if (ip_header->protocol == IPPROTO_TCP) {

        tcp_header = (struct tcphdr *)(skb_transport_header(sock_buff)+sizeof(struct iphdr));
        printk(KERN_INFO "[TCP_C_IN] DEBUG: From IP address: %d.%d.%d.%d\n",
               ip_header->saddr & 0x000000FF,
               (ip_header->saddr & 0x0000FF00) >> 8,
               (ip_header->saddr & 0x00FF0000) >> 16,
               (ip_header->saddr & 0xFF000000) >> 24);

      }
    }
  }
#endif

  return NF_ACCEPT;
}

static unsigned int hook_traffic_out(unsigned int hooknum,
                                     struct sk_buff *skb,
                                     const struct net_device *in,
                                     const struct net_device *out,
                                     int (*okfn)(struct sk_buff *))
{
#if DEBUG > 0
  sock_buff = skb;

  if(sock_buff) {

    ip_header = (struct iphdr *)skb_network_header(sock_buff);

    if (ip_header) {
      if (ip_header->protocol == IPPROTO_TCP) {

        tcp_header = (struct tcphdr *)(skb_transport_header(sock_buff)+sizeof(struct iphdr));
        printk(KERN_INFO "[TCP_C_OUT] DEBUG: To IP address: %d.%d.%d.%d\n",
               ip_header->daddr & 0x000000FF,
               (ip_header->daddr & 0x0000FF00) >> 8,
               (ip_header->daddr & 0x00FF0000) >> 16,
               (ip_header->daddr & 0xFF000000) >> 24);

      }
    }
  }
#endif

  return NF_ACCEPT;
}


static int __init init_main(void)
{
  nf_traffic_in_ops.hook = hook_traffic_in;
  nf_traffic_in_ops.hooknum = NF_IP_LOCAL_IN;
  nf_traffic_in_ops.pf = PF_INET;
  nf_traffic_in_ops.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nf_traffic_in_ops);

  nf_traffic_out_ops.hook = hook_traffic_out;
  nf_traffic_out_ops.hooknum = NF_IP_LOCAL_OUT;
  nf_traffic_out_ops.pf = PF_INET;
  nf_traffic_out_ops.priority = NF_IP_PRI_FIRST;
  nf_register_hook(&nf_traffic_out_ops);

#if DEBUG > 0
  printk(KERN_INFO "[TCP_C] Successfully inserted protocol module!\n");
#endif

  return 0;
}

static void __exit cleanup_main(void)
{
  nf_unregister_hook(&nf_traffic_in_ops);
  nf_unregister_hook(&nf_traffic_out_ops);

#if DEBUG > 0
  printk(KERN_INFO "[TCP_C] Succesfully unloaded protocol module!\n");
#endif
}

module_init(init_main);
module_exit(cleanup_main);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);

