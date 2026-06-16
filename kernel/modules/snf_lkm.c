#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <net/netns/generic.h>
//including the ip and tcp headers and netfilter
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>


static unsigned int lkm_net_id;

// adding the counters for capturing 
static unsigned long syn_count = 0;
static unsigned long ack_count = 0;
static unsigned long fin_count = 0;
static unsigned long rst_count = 0;

struct lkm_netns_data {
	struct nf_hook_ops nf_hops;
};

static unsigned int nf_callback(void *priv, struct sk_buff *skb,
				const struct nf_hook_state *state)

//continuing tomorrow from here				
{
	struct ipv6hdr *ip6h;
	//adding the tcp header to the callback function
	struct tcphdr *tcph;


	if (!skb || !pskb_may_pull(skb, sizeof(*ip6h))) {
		printk("weird skb?! Drop it!\n");
		return NF_DROP;
	}

	ip6h = ipv6_hdr(skb);
	if (ip6h->nexthdr == IPPROTO_ICMPV6) {
		printk("recevied ICMPv6 packet! Drop it!\n");
		return NF_DROP;
	
	//adding the check for TCP packets and counting the flags
	if (ip6h->nexthdr == IPPROTO_TCP) {

    tcph = (struct tcphdr *)
           ((unsigned char *)ip6h + sizeof(struct ipv6hdr));

    if (tcph->syn)
        syn_count++;

    if (tcph->ack)
        ack_count++;

    if (tcph->fin)
        fin_count++;

    if (tcph->rst)
        rst_count++;
}
	}

	return NF_ACCEPT;
}

static const struct nf_hook_ops lkm_nf_hook_ops_template = {
	.hook		= nf_callback,		/* hook function */
	.hooknum	= NF_INET_PRE_ROUTING,	/* received packets */
	.pf		= PF_INET6,		/* IPv6 */
	.priority 	= NF_IP6_PRI_FIRST,	/* max hook priority */
};

static struct nf_hook_ops *lkm_nf_hook_ops(struct net *net)
{
	struct lkm_netns_data *netns_data = net_generic(net, lkm_net_id);

	return &netns_data->nf_hops;
}

static int __net_init netns_init(struct net *net)
{
	struct nf_hook_ops *ops = lkm_nf_hook_ops(net);
	int rc;

	/* Technically, it isn't necessary because we can use the
	 * lkm_nf_hook_ops_template directly. However, we demonstrate how to
	 * allocate storage for each network namespace and initialize it,
	 * primarily for documentation purposes.
	 */
	memcpy(ops, &lkm_nf_hook_ops_template, sizeof(*ops));

	rc = nf_register_net_hook(net, ops);
	if (rc) {
		printk("cannot register netfilter hook\n");
		return rc;
	}

	printk("netfilter hook registered\n");
	return 0;
}

static void __net_exit netns_exit(struct net *net)
{
	struct nf_hook_ops *ops = lkm_nf_hook_ops(net);

	nf_unregister_net_hook(net, ops);

	printk("netfilter hook unregistered\n");
}

static struct pernet_operations lkm_netns_ops = {
	.init = netns_init,
	.exit = netns_exit,
	.id = &lkm_net_id,
	.size = sizeof(struct lkm_netns_data),
};

static int __init lkm_init(void)
{
	int rc;

	rc = register_pernet_subsys(&lkm_netns_ops);
	if (rc) {
		printk("cannot register the pernet ops\n");
		return rc;
	}

	printk("lkm netfilter module registered\n");
	return 0;
}

static void __exit lkm_exit(void)
{
	unregister_pernet_subsys(&lkm_netns_ops);
	// adding the kernal print to display the TCP flag statistics
    printk("========== TCP FLAG STATISTICS ==========\n");
    printk("SYN : %lu\n", syn_count);
    printk("ACK : %lu\n", ack_count);
    printk("FIN : %lu\n", fin_count);
    printk("RST : %lu\n", rst_count);
    printk("=========================================\n");

    printk("lkm netfilter module unregistered\n");
	printk("lkm netfilter module unregistered\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mayer");
MODULE_DESCRIPTION("Simple Linux kernel Netfilter Module for dropping ICMPv6 ingress packets");
MODULE_VERSION("1.0.0");
