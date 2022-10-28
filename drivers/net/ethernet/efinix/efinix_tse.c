
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/of_platform.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/phy.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include "efinix_tse.h"

#define DRIVER_DESCRIPTION	"Efinix TSEMAC driver"
#define DRIVER_VERSION		"0.01"

#define LAST_REGISTER_ADDR	TSEMAC_DST_MAC_ADDR_HI

#define TX_BD_NUM_DEFAULT		128
#define RX_BD_NUM_DEFAULT		1024
#define TX_BD_NUM_MIN			(MAX_SKB_FRAGS + 1)
#define TX_BD_NUM_MAX			4096
#define RX_BD_NUM_MAX			4096

static struct tsemac_option tsemac_options[] = {
	/* Turn on jumbo packet support for both Rx and Tx */
	{
		.opt = XAE_OPTION_JUMBO,
		.reg = XAE_TC_OFFSET,
		.m_or = XAE_TC_JUM_MASK,
	}, {
		.opt = XAE_OPTION_JUMBO,
		.reg = XAE_RCW1_OFFSET,
		.m_or = XAE_RCW1_JUM_MASK,
	}, { /* Turn on VLAN packet support for both Rx and Tx */
		.opt = XAE_OPTION_VLAN,
		.reg = XAE_TC_OFFSET,
		.m_or = XAE_TC_VLAN_MASK,
	}, {
		.opt = XAE_OPTION_VLAN,
		.reg = XAE_RCW1_OFFSET,
		.m_or = XAE_RCW1_VLAN_MASK,
	}, { /* Turn on FCS stripping on receive packets */
		.opt = XAE_OPTION_FCS_STRIP,
		.reg = XAE_RCW1_OFFSET,
		.m_or = XAE_RCW1_FCS_MASK,
	}, { /* Turn on FCS insertion on transmit packets */
		.opt = XAE_OPTION_FCS_INSERT,
		.reg = XAE_TC_OFFSET,
		.m_or = XAE_TC_FCS_MASK,
	}, { /* Turn off length/type field checking on receive packets */
		.opt = XAE_OPTION_LENTYPE_ERR,
		.reg = XAE_RCW1_OFFSET,
		.m_or = XAE_RCW1_LT_DIS_MASK,
	}, { /* Turn on Rx flow control */
		.opt = XAE_OPTION_FLOW_CONTROL,
		.reg = XAE_FCC_OFFSET,
		.m_or = XAE_FCC_FCRX_MASK,
	}, { /* Turn on Tx flow control */
		.opt = XAE_OPTION_FLOW_CONTROL,
		.reg = XAE_FCC_OFFSET,
		.m_or = XAE_FCC_FCTX_MASK,
	}, { /* Turn on promiscuous frame filtering */
		.opt = XAE_OPTION_PROMISC,
		.reg = XAE_FMI_OFFSET,
		.m_or = XAE_FMI_PM_MASK,
	}, { /* Enable transmitter */
		.opt = XAE_OPTION_TXEN,
		.reg = XAE_TC_OFFSET,
		.m_or = XAE_TC_TX_MASK,
	}, { /* Enable receiver */
		.opt = XAE_OPTION_RXEN,
		.reg = XAE_RCW1_OFFSET,
		.m_or = XAE_RCW1_RX_MASK,
	},
	{}
};

// struct dmasg_descriptor {
// 	u32 next;	/* Physical address of next buffer descriptor */
// 	u32 next_msb;	/* high 32 bits for IP >= v7.1, reserved on older IP */
// 	u32 phys;
// 	u32 phys_msb;	/* for IP >= v7.1, reserved for older IP */
// 	u32 reserved3;
// 	u32 reserved4;
// 	u32 cntrl;
// 	u32 status;
// 	u32 app0;
// 	u32 app1;	/* TX start << 16 | insert */
// 	u32 app2;	/* TX csum seed */
// 	u32 app3;
// 	u32 app4;   /* Last field used by HW */
// 	struct sk_buff *skb;
// } __aligned(XAXIDMA_BD_MINIMUM_ALIGNMENT);

int tsemac_mdio_setup(struct efx_tsemac_local *lp) {

}

static inline void tsemac_lock_mii(struct efx_tsemac_local *lp)
{
	if (lp->mii_bus)
		mutex_lock(&lp->mii_bus->mdio_lock);
}

static inline void tsemac_unlock_mii(struct efx_tsemac_local *lp)
{
	if (lp->mii_bus)
		mutex_unlock(&lp->mii_bus->mdio_lock);
}

static void desc_set_phys_addr(struct efx_tsemac_local *lp, dma_addr_t addr,
			       struct dmasg_descriptor *desc)
{
	desc->from = lower_32_bits(addr);
}

static dma_addr_t desc_get_phys_addr(struct axienet_local *lp,
				     struct dmasg_descriptor *desc)
{
	return desc->from;
}

static void tsemac_set_mac_address(struct net_device *ndev, const void *address)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	if (address)
		eth_hw_addr_set(ndev, address);
	if (!is_valid_ether_addr(ndev->dev_addr))
		eth_hw_addr_random(ndev);

	/* Set up unicast MAC address filter set its mac address */
	tsemac_iow(lp, TSEMAC_MAC_ADDR_LO,
		    (ndev->dev_addr[0]) |
		    (ndev->dev_addr[1] << 8) |
		    (ndev->dev_addr[2] << 16) |
		    (ndev->dev_addr[3] << 24));
	tsemac_iow(lp, TSEMAC_MAC_ADDR_HI,
		     (ndev->dev_addr[4]) |
		     (ndev->dev_addr[5] << 8));

	tsemac_iow(lp, TSEMAC_MAC_ADDR_MAKE_LO, 0xFFFFFFFF);
	tsemac_iow(lp, TSEMAC_MAC_ADDR_MAKE_HI, 0x0000FFFF);
}

static int netdev_set_mac_address(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;
	tsemac_set_mac_address(ndev, addr->sa_data);
	return 0;
}

static void tsemac_set_multicast_list(struct net_device *ndev)
{
	int i;
	u32 reg, af0reg, af1reg;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	//TODO: support other IFF mode 
	if (ndev->flags & (IFF_ALLMULTI | IFF_PROMISC) ||
							netdev_mc_count(ndev) > 1 ) {
		ndev->flags |= IFF_PROMISC;
		reg = tsemac_ior(lp, TSEMAC_COMMAND_CONFIG);
		reg |= ETHERNET_CMD_PROMIS_EN;
		tsemac_iow(lp, TSEMAC_COMMAND_CONFIG, reg);
		dev_info(&ndev->dev, "Promiscuous mode enabled.\n");
	} else {
		reg = tsemac_ior(lp, TSEMAC_COMMAND_CONFIG);
		reg &= ~ETHERNET_CMD_PROMIS_EN;
		tsemac_iow(lp, TSEMAC_COMMAND_CONFIG, reg);
		dev_info(&ndev->dev, "Promiscuous mode disabled.\n");
	}
}

static void tsemac_setoptions(struct net_device *ndev, u32 options)
{
	//TODO: optional. May not needed in our IP
}

static void __tsemac_device_reset(struct efx_tsemac_local *lp, off_t offset)
{
	//TODO: optional
}

static void tsemac_device_reset(struct net_device *ndev)
{
	//TODO: PHY, MAC, DMA reset
}

static void tsemac_adjust_link(struct net_device *ndev)
{
	//TODO: adjest PHY speed settings. called afte auto negotiation
}

static void tsemac_start_xmit_done(struct net_device *ndev)
{
	//TODO: dma fields clear upon transmit complete 
}

static inline int tsemac_check_tx_bd_space(struct efx_tsemac_local *lp, int num_frag)
{
	//TODO: what are READ_ONCE, num_frag and lp->tx_bd_num
	struct dmasg_descriptor *cur_p;

	/* Ensure we see all descriptor updates from device or TX polling */
	rmb();
	cur_p = &lp->tx_bd_v[(READ_ONCE(lp->tx_bd_tail) + num_frag) %
			     lp->tx_bd_num];
	if (cur_p->busy		//TODO: check busy bit
		return NETDEV_TX_BUSY;
	return 0;
}


static netdev_tx_t tsemac_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	u32 ii;
	u32 num_frag;
	u32 csum_start_off;
	u32 csum_index_off;
	skb_frag_t *frag;
	dma_addr_t tail_p, phys;
	u32 orig_tail_ptr, new_tail_ptr;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	struct dmasg_descriptor *cur_p;

	orig_tail_ptr = lp->tx_bd_tail;
	new_tail_ptr = orig_tail_ptr;

	num_frag = skb_shinfo(skb)->nr_frags;
	cur_p = &lp->tx_bd_v[orig_tail_ptr];

	if (tsemac_check_tx_bd_space(lp, num_frag + 1)) {
		/* Should not happen as last start_xmit call should have
		 * checked for sufficient space and queue should only be
		 * woken when sufficient space is available.
		 */
		netif_stop_queue(ndev);
		if (net_ratelimit())
			netdev_warn(ndev, "TX ring unexpectedly full\n");
		return NETDEV_TX_BUSY;
	}

	if (skb->ip_summed == CHECKSUM_PARTIAL || skb->ip_summed == CHECKSUM_UNNECESSARY) {
		if (net_ratelimit())
			netdev_err(ndev, "Unsupported checksum mode\n");
		ndev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}
	//TODO: support hardware checksum in the future
	// if (skb->ip_summed == CHECKSUM_PARTIAL) {
	// 	if (lp->features & XAE_FEATURE_FULL_TX_CSUM) {
	// 		/* Tx Full Checksum Offload Enabled */
	// 		cur_p->app0 |= 2;
	// 	} else if (lp->features & XAE_FEATURE_PARTIAL_TX_CSUM) {
	// 		csum_start_off = skb_transport_offset(skb);
	// 		csum_index_off = csum_start_off + skb->csum_offset;
	// 		/* Tx Partial Checksum Offload Enabled */
	// 		cur_p->app0 |= 1;
	// 		cur_p->app1 = (csum_start_off << 16) | csum_index_off;
	// 	}
	// } else if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
	// 	cur_p->app0 |= 2; /* Tx Full Checksum Offload Enabled */
	// }

	phys = dma_map_single(lp->dev, skb->data,
			      skb_headlen(skb), DMA_TO_DEVICE);
	if (unlikely(dma_mapping_error(lp->dev, phys))) {
		if (net_ratelimit())
			netdev_err(ndev, "TX DMA mapping error\n");
		ndev->stats.tx_dropped++;
		return NETDEV_TX_OK;
	}
	desc_set_phys_addr(lp, phys, cur_p);
	//TODO: check location of the byte length register in our sg_bd 
	cur_p->cntrl = skb_headlen(skb) | XAXIDMA_BD_CTRL_TXSOF_MASK;

	for (ii = 0; ii < num_frag; ii++) {
		if (++new_tail_ptr >= lp->tx_bd_num)
			new_tail_ptr = 0;
		cur_p = &lp->tx_bd_v[new_tail_ptr];
		frag = &skb_shinfo(skb)->frags[ii];
		phys = dma_map_single(lp->dev,
				      skb_frag_address(frag),
				      skb_frag_size(frag),
				      DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(lp->dev, phys))) {
			if (net_ratelimit())
				netdev_err(ndev, "TX DMA mapping error\n");
			ndev->stats.tx_dropped++;
			tsemac_free_tx_chain(lp, orig_tail_ptr, ii + 1,
					      true, NULL, 0);
			return NETDEV_TX_OK;
		}
		desc_set_phys_addr(lp, phys, cur_p);
		cur_p->cntrl = skb_frag_size(frag);
	}
	//TODO: check the end of frame mask in our sg_bd
	cur_p->cntrl |= XAXIDMA_BD_CTRL_TXEOF_MASK;
	// cur_p->skb = skb;	

	tail_p = lp->tx_bd_p + sizeof(*lp->tx_bd_v) * new_tail_ptr;
	if (++new_tail_ptr >= lp->tx_bd_num)
		new_tail_ptr = 0;
	WRITE_ONCE(lp->tx_bd_tail, new_tail_ptr);

	/* Start the transfer */
	tsemac_dma_out_addr(lp, XAXIDMA_TX_TDESC_OFFSET, tail_p);

	/* Stop queue if next transmit may not have space */
	if (tsemac_check_tx_bd_space(lp, MAX_SKB_FRAGS + 1)) {
		netif_stop_queue(ndev);

		/* Matches barrier in tsemac_tx_poll */
		smp_mb();

		/* Space might have just been freed - check again */
		if (!tsemac_check_tx_bd_space(lp, MAX_SKB_FRAGS + 1))
			netif_wake_queue(ndev);
	}

	return NETDEV_TX_OK;
}

static void tsemac_recv(struct net_device *ndev)
{
	//TODO: optional 
}
static irqreturn_t tsemac_tx_irq(int irq, void *_ndev)
{
	//TODO: tx irq handler
	u32 cr;
	unsigned int status;
	struct net_device *ndev = _ndev;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	status = tsemac_dma_in32(lp, XAXIDMA_TX_SR_OFFSET);
	if (status & (XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_DELAY_MASK)) {
		tsemac_dma_out32(lp, XAXIDMA_TX_SR_OFFSET, status);
		tsemac_start_xmit_done(lp->ndev);
		goto out;
	}
	if (!(status & XAXIDMA_IRQ_ALL_MASK))
		dev_err(&ndev->dev, "No interrupts asserted in Tx path\n");
	if (status & XAXIDMA_IRQ_ERROR_MASK) {
		dev_err(&ndev->dev, "DMA Tx error 0x%x\n", status);
		dev_err(&ndev->dev, "Current BD is at: 0x%x\n",
			(lp->tx_bd_v[lp->tx_bd_ci]).phys);

		cr = tsemac_dma_in32(lp, XAXIDMA_TX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* Write to the Tx channel control register */
		tsemac_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, cr);

		cr = tsemac_dma_in32(lp, XAXIDMA_RX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* Write to the Rx channel control register */
		tsemac_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, cr);

		tasklet_schedule(&lp->dma_err_tasklet);
		tsemac_dma_out32(lp, XAXIDMA_TX_SR_OFFSET, status);
	}
out:
	return IRQ_HANDLED;
}

static irqreturn_t tsemac_rx_irq(int irq, void *_ndev)
{
	//TODO: RX irq handler
	u32 cr;
	unsigned int status;
	struct net_device *ndev = _ndev;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	status = tsemac_dma_in32(lp, XAXIDMA_RX_SR_OFFSET);
	if (status & (XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_DELAY_MASK)) {
		tsemac_dma_out32(lp, XAXIDMA_RX_SR_OFFSET, status);
		tsemac_recv(lp->ndev);
		goto out;
	}
	if (!(status & XAXIDMA_IRQ_ALL_MASK))
		dev_err(&ndev->dev, "No interrupts asserted in Rx path\n");
	if (status & XAXIDMA_IRQ_ERROR_MASK) {
		dev_err(&ndev->dev, "DMA Rx error 0x%x\n", status);
		dev_err(&ndev->dev, "Current BD is at: 0x%x\n",
			(lp->rx_bd_v[lp->rx_bd_ci]).phys);

		cr = tsemac_dma_in32(lp, XAXIDMA_TX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* Finally write to the Tx channel control register */
		tsemac_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, cr);

		cr = tsemac_dma_in32(lp, XAXIDMA_RX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* write to the Rx channel control register */
		tsemac_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, cr);

		tasklet_schedule(&lp->dma_err_tasklet);
		tsemac_dma_out32(lp, XAXIDMA_RX_SR_OFFSET, status);
	}
out:
	return IRQ_HANDLED;
}

static irqreturn_t tsemac_eth_irq(int irq, void *_ndev)
{
	struct net_device *ndev = _ndev;
	struct tsemac_local *lp = netdev_priv(ndev);
	unsigned int pending;

	pending = tsemac_ior(lp, XAE_IP_OFFSET);
	if (!pending)
		return IRQ_NONE;

	if (pending & XAE_INT_RXFIFOOVR_MASK)
		ndev->stats.rx_missed_errors++;

	if (pending & XAE_INT_RXRJECT_MASK)
		ndev->stats.rx_frame_errors++;

	tsemac_iow(lp, XAE_IS_OFFSET, pending);
	return IRQ_HANDLED;
}

static int tsemac_open(struct net_device *ndev)
{
	//TODO:
	int ret;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	dev_dbg(&ndev->dev, "tsemac_open()\n");

	/* When we do an Axi Ethernet reset, it resets the complete core
	 * including the MDIO. MDIO must be disabled before resetting.
	 * Hold MDIO bus lock to avoid MDIO accesses during the reset.
	 */
	tsemac_lock_mii(lp);
	ret = tsemac_device_reset(ndev);
	tsemac_unlock_mii(lp);

	ret = phylink_of_phy_connect(lp->phylink, lp->dev->of_node, 0);
	if (ret) {
		dev_err(lp->dev, "phylink_of_phy_connect() failed: %d\n", ret);
		return ret;
	}

	phylink_start(lp->phylink);

	/* Enable worker thread for Axi DMA error handling */
	INIT_WORK(&lp->dma_err_task, tsemac_dma_err_handler);

	napi_enable(&lp->napi_rx);
	napi_enable(&lp->napi_tx);

	/* Enable interrupts for Axi DMA Tx */
	ret = request_irq(lp->tx_irq, tsemac_tx_irq, IRQF_SHARED,
			  ndev->name, ndev);
	if (ret)
		goto err_tx_irq;
	/* Enable interrupts for Axi DMA Rx */
	ret = request_irq(lp->rx_irq, tsemac_rx_irq, IRQF_SHARED,
			  ndev->name, ndev);
	if (ret)
		goto err_rx_irq;
	/* Enable interrupts for Axi Ethernet core (if defined) */
	if (lp->eth_irq > 0) {
		ret = request_irq(lp->eth_irq, tsemac_eth_irq, IRQF_SHARED,
				  ndev->name, ndev);
		if (ret)
			goto err_eth_irq;
	}

	return 0;

err_eth_irq:
	free_irq(lp->rx_irq, ndev);
err_rx_irq:
	free_irq(lp->tx_irq, ndev);
err_tx_irq:
	napi_disable(&lp->napi_tx);
	napi_disable(&lp->napi_rx);
	phylink_stop(lp->phylink);
	phylink_disconnect_phy(lp->phylink);
	cancel_work_sync(&lp->dma_err_task);
	dev_err(lp->dev, "request_irq() failed\n");
	return ret;
}


static int tsemac_stop(struct net_device *ndev)
{
	struct tsemac_local *lp = netdev_priv(ndev);

	dev_dbg(&ndev->dev, "tsemac_close()\n");

	napi_disable(&lp->napi_tx);
	napi_disable(&lp->napi_rx);

	phylink_stop(lp->phylink);
	phylink_disconnect_phy(lp->phylink);

	tsemac_setoptions(ndev, lp->options &
			   ~(XAE_OPTION_TXEN | XAE_OPTION_RXEN));	//TODO: check DISABLE options

	tsemac_dma_stop(lp);

	tsemac_iow(lp, XAE_IE_OFFSET, 0);

	cancel_work_sync(&lp->dma_err_task);

	if (lp->eth_irq > 0)
		free_irq(lp->eth_irq, ndev);
	free_irq(lp->tx_irq, ndev);
	free_irq(lp->rx_irq, ndev);

	tsemac_dma_bd_release(ndev);
	return 0;
}

static int tsemac_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	//TODO: port to our IP
	if (netif_running(ndev))
		return -EBUSY;

	// invalid if greater than buffer size 
	if ((new_mtu + VLAN_ETH_HLEN + XAE_TRL_SIZE) > lp->rxmem)
		return -EINVAL;

	ndev->mtu = new_mtu;

	return 0;
}

#ifdef
//TODO: determine whether need to implement it
static void tsemac_poll_controller(struct net_device *ndev);
#endif
static void tsemac_ethtools_get_drvinfo(struct net_device *ndev, struct ethtool_drvinfo *ed)
{
	strlcpy(ed->driver, DRIVER_NAME, sizeof(ed->driver));
	strlcpy(ed->version, DRIVER_VERSION, sizeof(ed->version));
}
static int tsemac_ethtools_get_regs_len(struct net_device *ndev)
{
	(void) ndev;
	return LAST_REGISTER_ADDR + 4;
}

static void tsemac_ethtools_get_regs(struct net_device *ndev, struct ethtool_regs *regs, void *ret)
{
	int i;
	u32 *data = (u32 *) ret;
	size_t len = sizeof(u32) * tsemac_REGS_N;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	regs->version = 0;
	regs->len = tsemac_ethtools_get_regs_len(ndev);

	memset(data, 0, regs->len);
	for(i=0 ; i<len ; i+=4) {
		data[i] = tsemac_ior(lp, i);
	}
}


static void tsemac_ethtools_get_ringparam(struct net_device *ndev,
			       struct ethtool_ringparam *ering,
			       struct kernel_ethtool_ringparam *kernel_ering,
			       struct netlink_ext_ack *extack)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	ering->rx_max_pending = RX_BD_NUM_MAX;
	ering->rx_mini_max_pending = 0;
	ering->rx_jumbo_max_pending = 0;
	ering->tx_max_pending = TX_BD_NUM_MAX;
	ering->rx_pending = lp->rx_bd_num;
	ering->rx_mini_pending = 0;
	ering->rx_jumbo_pending = 0;
	ering->tx_pending = lp->tx_bd_num;
}


static int tsemac_ethtools_set_ringparam(struct net_device *ndev,
			       struct ethtool_ringparam *ering,
			       struct kernel_ethtool_ringparam *kernel_ering,
			       struct netlink_ext_ack *extack)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	if (ering->rx_pending > RX_BD_NUM_MAX ||
	    ering->rx_mini_pending ||
	    ering->rx_jumbo_pending ||
	    ering->tx_pending < TX_BD_NUM_MIN ||
	    ering->tx_pending > TX_BD_NUM_MAX)
		return -EINVAL;

	if (netif_running(ndev))
		return -EBUSY;

	lp->rx_bd_num = ering->rx_pending;
	lp->tx_bd_num = ering->tx_pending;
	return 0;
}


static void tsemac_ethtools_get_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *epauseparm)
{	
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	phylink_ethtool_get_pauseparam(lp->phylink, epauseparm);
}

static int tsemac_ethtools_set_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *epauseparm)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	return phylink_ethtool_set_pauseparam(lp->phylink, epauseparm);
}

static int tsemac_ethtools_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ecoalesce)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	ecoalesce->rx_max_coalesced_frames = lp->coalesce_count_rx;
	ecoalesce->rx_coalesce_usecs = lp->coalesce_usec_rx;
	ecoalesce->tx_max_coalesced_frames = lp->coalesce_count_tx;
	ecoalesce->tx_coalesce_usecs = lp->coalesce_usec_tx;
	return 0;
}

static int tsemac_ethtools_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ecoalesce)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	if (netif_running(ndev)) {
		netdev_err(ndev,
			   "Please stop netif before applying configuration\n");
		return -EBUSY;
	}

	if (ecoalesce->rx_max_coalesced_frames)
		lp->coalesce_count_rx = ecoalesce->rx_max_coalesced_frames;
	if (ecoalesce->rx_coalesce_usecs)
		lp->coalesce_usec_rx = ecoalesce->rx_coalesce_usecs;
	if (ecoalesce->tx_max_coalesced_frames)
		lp->coalesce_count_tx = ecoalesce->tx_max_coalesced_frames;
	if (ecoalesce->tx_coalesce_usecs)
		lp->coalesce_usec_tx = ecoalesce->tx_coalesce_usecs;

	return 0;
}

static int
tsemac_ethtools_get_link_ksettings(struct net_device *ndev,
				    struct ethtool_link_ksettings *cmd)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	return phylink_ethtool_ksettings_get(lp->phylink, cmd);
}

static int
tsemac_ethtools_set_link_ksettings(struct net_device *ndev,
				    const struct ethtool_link_ksettings *cmd)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	return phylink_ethtool_ksettings_set(lp->phylink, cmd);
}

static int tsemac_ethtools_nway_reset(struct net_device *dev)
{
	struct efx_tsemac_local *lp = netdev_priv(dev);

	return phylink_ethtool_nway_reset(lp->phylink);
}


static void tsemac_dma_err_handler(unsigned long data);
static int tsemac_probe(struct platform_device *pdev) 
{
	int ret;
	struct device_node *np;
	struct efx_tsemac_local *lp;
	struct net_device *ndev;
	struct resource *ethres;
	u8 mac_addr[ETH_ALEN];
	int addr_width = 32;
	u32 value;
    
	ndev = alloc_etherdev(sizeof(*lp));
	if (!ndev)
		return -ENOMEM;

	platform_set_drvdata(pdev, ndev);

	SET_NETDEV_DEV(ndev, &pdev->dev);
	ndev->flags &= ~IFF_MULTICAST;
	ndev->features = NETIF_F_SG;	//TODO: determine whether supporting SG mode or not 
	ndev->netdev_ops = &tsemac_netdev_ops;	//TODO: use custom ops
	ndev->ethtool_ops = &tsemac_ethtool_ops;	//TODO: use custom ops

	/* MTU range: 64 - 1500 */
	ndev->min_mtu = 64;
	ndev->max_mtu = EFXTSE_MTU;

	//TODO: port lp to Efinix TSEMAC 
	lp = netdev_priv(ndev);
	lp->ndev = ndev;
	lp->dev = &pdev->dev;
	lp->options = XAE_OPTION_DEFAULTS;	//TODO: may use custom options
	lp->rx_bd_num = RX_BD_NUM_DEFAULT;	//is SG supported?
	lp->tx_bd_num = TX_BD_NUM_DEFAULT;	//is SG supported?

	//TODO: napi support
	netif_napi_add(ndev, &lp->napi_rx, tsemac_rx_poll, NAPI_POLL_WEIGHT);
	netif_napi_add(ndev, &lp->napi_tx, tsemac_tx_poll, NAPI_POLL_WEIGHT);

	/* Map device registers */
	lp->regs = devm_platform_get_and_ioremap_resource(pdev, 0, &ethres);
	// ethres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	// lp->regs = devm_ioremap_resource(&pdev->dev, ethres);
	if (IS_ERR(lp->regs)) {
		dev_err(&pdev->dev, "could not map Efinix TSEMAC regs.\n");
		ret = PTR_ERR(lp->regs);
		goto free_netdev;
	}
	lp->regs_start = ethres->start;

	/* Setup checksum offload, but default to off if not specified */
	lp->features = 0;

	//TODO: check whether Checksum exists in Efinix TSEMAC
	ret = of_property_read_u32(pdev->dev.of_node, "efx,txcsum", &value);	//TODO: add this to device tree
	if (!ret) {
		switch (value) {
		case 1:
			lp->csum_offload_on_tx_path =
				XAE_FEATURE_PARTIAL_TX_CSUM;
			lp->features |= XAE_FEATURE_PARTIAL_TX_CSUM;
			/* Can checksum TCP/UDP over IPv4. */
			ndev->features |= NETIF_F_IP_CSUM;
			break;
		case 2:
			lp->csum_offload_on_tx_path =
				XAE_FEATURE_FULL_TX_CSUM;
			lp->features |= XAE_FEATURE_FULL_TX_CSUM;
			/* Can checksum TCP/UDP over IPv4. */
			ndev->features |= NETIF_F_IP_CSUM;
			break;
		default:
			lp->csum_offload_on_tx_path = XAE_NO_CSUM_OFFLOAD;
		}
	}
	ret = of_property_read_u32(pdev->dev.of_node, "efx,rxcsum", &value);	//TODO: add this to device tree
	if (!ret) {
		switch (value) {
		case 1:
			lp->csum_offload_on_rx_path =
				XAE_FEATURE_PARTIAL_RX_CSUM;
			lp->features |= XAE_FEATURE_PARTIAL_RX_CSUM;
			break;
		case 2:
			lp->csum_offload_on_rx_path =
				XAE_FEATURE_FULL_RX_CSUM;
			lp->features |= XAE_FEATURE_FULL_RX_CSUM;
			break;
		default:
			lp->csum_offload_on_rx_path = XAE_NO_CSUM_OFFLOAD;
		}
	}

	//TODO: customize the memory size in our own device tree
	of_property_read_u32(pdev->dev.of_node, "xlnx,rxmem", &lp->rxmem);

	// lp->switch_x_sgmii = of_property_read_bool(pdev->dev.of_node,
	// 					   "xlnx,switch-x-sgmii");
	//TODO: define our node to select the PHY mode 
	/* Start with the proprietary, and broken phy_type */
	ret = of_property_read_u32(pdev->dev.of_node, "xlnx,phy-type", &value);
	if (!ret) {
		netdev_warn(ndev, "Please upgrade your device tree binary blob to use phy-mode");
		switch (value) {
		case XAE_PHY_TYPE_MII:
			lp->phy_mode = PHY_INTERFACE_MODE_MII;
			break;
		case XAE_PHY_TYPE_GMII:
			lp->phy_mode = PHY_INTERFACE_MODE_GMII;
			break;
		case XAE_PHY_TYPE_RGMII_2_0:
			lp->phy_mode = PHY_INTERFACE_MODE_RGMII_ID;
			break;
		case XAE_PHY_TYPE_SGMII:
			lp->phy_mode = PHY_INTERFACE_MODE_SGMII;
			break;
		case XAE_PHY_TYPE_1000BASE_X:
			lp->phy_mode = PHY_INTERFACE_MODE_1000BASEX;
			break;
		default:
			ret = -EINVAL;
			goto free_netdev;
		}
	} else {
		ret = of_get_phy_mode(pdev->dev.of_node, &lp->phy_mode);
		if (ret)
			goto free_netdev;
	}
	
	//TODO: find how does of_parse_phandle work 
	/* Find the DMA node, map the DMA registers, and decode the DMA IRQs */
	np = of_parse_phandle(pdev->dev.of_node, "axistream-connected", 0);
	if (np) {
		struct resource dmares;

		ret = of_address_to_resource(np, 0, &dmares);
		if (ret) {
			dev_err(&pdev->dev,
				"unable to get DMA resource\n");
			of_node_put(np);
			goto free_netdev;
		}
		lp->dma_regs = devm_ioremap_resource(&pdev->dev,
						     &dmares);
		lp->rx_irq = irq_of_parse_and_map(np, 1);
		lp->tx_irq = irq_of_parse_and_map(np, 0);
		of_node_put(np);
		lp->eth_irq = platform_get_irq_optional(pdev, 0);
	} else {
		/* Check for these resources directly on the Ethernet node. */
		lp->dma_regs = devm_platform_get_and_ioremap_resource(pdev, 1, NULL);
		lp->rx_irq = platform_get_irq(pdev, 1);
		lp->tx_irq = platform_get_irq(pdev, 0);
		lp->eth_irq = platform_get_irq_optional(pdev, 2);
	}
	if (IS_ERR(lp->dma_regs)) {
		dev_err(&pdev->dev, "could not map DMA regs\n");
		ret = PTR_ERR(lp->dma_regs);
		goto free_netdev;
	}
	if ((lp->rx_irq <= 0) || (lp->tx_irq <= 0)) {
		dev_err(&pdev->dev, "could not determine irqs\n");
		ret = -ENOMEM;
		goto free_netdev;
	}

	//TODO: add 64-bit system support

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(addr_width));
	if (ret) {
		dev_err(&pdev->dev, "No suitable DMA available\n");
		goto cleanup_clk;
	}

	/* Retrieve the MAC address from device */
	ret = of_get_mac_address(pdev->dev.of_node, mac_addr);
	if (!ret) {
		tsemac_set_mac_address(ndev, mac_addr);
	} else {
		dev_warn(&pdev->dev, "could not find MAC address property: %d\n",
			 ret);
		tsemac_set_mac_address(ndev, NULL);
	}

	//TODO: check whether we support interrupt coalescing
	lp->coalesce_count_rx = EFXTSE_RX_COUNT;
	lp->coalesce_usec_rx = EFXTSE_RX_USEC;
	lp->coalesce_count_tx = EFXTSE_TX_COUNT;
	lp->coalesce_usec_tx = EFXTSE_TX_USEC;
	
	/* Reset core now that clocks are enabled, prior to accessing MDIO */
	ret = __tsemac_device_reset(lp);
	if (ret)
		goto cleanup_clk;

	//TODO: define MDIO in devicetree
	ret = tsemac_mdio_setup(lp);
	if (ret)
		dev_warn(&pdev->dev,
			 "error registering MDIO bus: %d\n", ret);

	if (lp->phy_mode == PHY_INTERFACE_MODE_SGMII ||
	    lp->phy_mode == PHY_INTERFACE_MODE_1000BASEX) {
		np = of_parse_phandle(pdev->dev.of_node, "pcs-handle", 0);
		if (!np) {
			dev_err(&pdev->dev, "pcs-handle required for 1000BaseX/SGMII\n");
			ret = -EINVAL;
			goto cleanup_mdio;
		}
		lp->pcs_phy = of_mdio_find_device(np);
		if (!lp->pcs_phy) {
			ret = -EPROBE_DEFER;
			of_node_put(np);
			goto cleanup_mdio;
		}
		of_node_put(np);
		lp->pcs.ops = &tsemac_pcs_ops;
		lp->pcs.poll = true;
	}

	lp->phylink_config.dev = &ndev->dev;
	lp->phylink_config.type = PHYLINK_NETDEV;
	lp->phylink_config.mac_capabilities = MAC_SYM_PAUSE | MAC_ASYM_PAUSE |
		MAC_10FD | MAC_100FD | MAC_1000FD;	//TODO: verify what can the MAC do

	__set_bit(lp->phy_mode, lp->phylink_config.supported_interfaces);
	// if (lp->switch_x_sgmii) {	//TODO: should we use "switch_x_sgmii" in our device tree to determine PHY mode?
	// 	__set_bit(PHY_INTERFACE_MODE_1000BASEX,
	// 		  lp->phylink_config.supported_interfaces);
	// 	__set_bit(PHY_INTERFACE_MODE_SGMII,
	// 		  lp->phylink_config.supported_interfaces);
	// }

	lp->phylink = phylink_create(&lp->phylink_config, pdev->dev.fwnode,
				     lp->phy_mode,
				     &tsemac_phylink_ops);
	if (IS_ERR(lp->phylink)) {
		ret = PTR_ERR(lp->phylink);
		dev_err(&pdev->dev, "phylink_create error (%i)\n", ret);
		goto cleanup_mdio;
	}
	
	ret = register_netdev(lp->ndev);
	if (ret) {
		dev_err(lp->dev, "register_netdev() error (%i)\n", ret);
		goto free_netdev;
	}
	return 0;

cleanup_mdio:
	if (lp->pcs_phy)
		put_device(&lp->pcs_phy->dev);
	if (lp->mii_bus)
		tsemac_mdio_teardown(lp);//TODO:
free_netdev:
	free_netdev(ndev);

	return ret;
}

static int tsemac_remove(struct platform_device *pdev);

static int tsemac_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct efx_tsemac_local *lp = netdev_priv(dev);

	if (!netif_running(dev))
		return -EBUSY;

	return phylink_mii_ioctl(lp->phylink, rq, cmd);
}


static const struct net_device_ops tsemac_netdev_ops = {
	.ndo_open = tsemac_open,
	.ndo_stop = tsemac_stop,
	.ndo_start_xmit = tsemac_start_xmit,
	.ndo_change_mtu	= tsemac_change_mtu,
	.ndo_set_mac_address = netdev_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_rx_mode = tsemac_set_multicast_list,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = tsemac_poll_controller,
#endif
};

static const struct ethtool_ops tsemac_ethtool_ops = {
	.get_drvinfo    = tsemac_ethtools_get_drvinfo,
	.get_regs_len   = tsemac_ethtools_get_regs_len,
	.get_regs       = tsemac_ethtools_get_regs,
	.get_link       = ethtool_op_get_link,
	.get_ringparam	= tsemac_ethtools_get_ringparam,
	.set_ringparam	= tsemac_ethtools_set_ringparam,
	.get_pauseparam = tsemac_ethtools_get_pauseparam,
	.set_pauseparam = tsemac_ethtools_set_pauseparam,
	.get_coalesce   = tsemac_ethtools_get_coalesce,
	.set_coalesce   = tsemac_ethtools_set_coalesce,
	.get_link_ksettings = phy_ethtool_get_link_ksettings,
	.set_link_ksettings = phy_ethtool_set_link_ksettings,
	.get_link_ksettings = tsemac_ethtools_get_link_ksettings,
	.set_link_ksettings = tsemac_ethtools_set_link_ksettings,
	.nway_reset	= tsemac_ethtools_nway_reset
};

static struct platform_driver efinix_tse_driver = {
	.probe = tsemac_probe,
	.remove = tsemac_remove,
	.driver = {
		 .name = "efinix_tsemac",
		 .of_match_table = tsemac_of_match,
	},
};

module_platform_driver(efinix_tse_driver);

MODULE_AUTHOR("Efinix");
MODULE_DESCRIPTION("Efinix Triple Speed Ethernet MAC driver");
MODULE_LICENSE("GPL v2");
