
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


int tsemac_mdio_setup(struct efx_tsemac_local *lp) {

}


static void tsemac_set_mac_address(struct net_device *ndev, const void *address)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	if (address)
		eth_hw_addr_set(ndev, address);
	if (!is_valid_ether_addr(ndev->dev_addr))
		eth_hw_addr_random(ndev);

	/* Set up unicast MAC address filter set its mac address */
	tsemac_out32(lp, TSEMAC_MAC_ADDR_LO,
		    (ndev->dev_addr[0]) |
		    (ndev->dev_addr[1] << 8) |
		    (ndev->dev_addr[2] << 16) |
		    (ndev->dev_addr[3] << 24));
	tsemac_out32(lp, TSEMAC_MAC_ADDR_HI,
		     (ndev->dev_addr[4]) |
		     (ndev->dev_addr[5] << 8));

	tsemac_out32(lp, TSEMAC_MAC_ADDR_MAKE_LO, 0xFFFFFFFF);
	tsemac_out32(lp, TSEMAC_MAC_ADDR_MAKE_HI, 0x0000FFFF);
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
		reg = tsemac_in32(lp, TSEMAC_COMMAND_CONFIG);
		reg |= ETHERNET_CMD_PROMIS_EN;
		tsemac_out32(lp, TSEMAC_COMMAND_CONFIG, reg);
		dev_info(&ndev->dev, "Promiscuous mode enabled.\n");
	} else {
		reg = tsemac_in32(lp, TSEMAC_COMMAND_CONFIG);
		reg &= ~ETHERNET_CMD_PROMIS_EN;
		tsemac_out32(lp, TSEMAC_COMMAND_CONFIG, reg);
		dev_info(&ndev->dev, "Promiscuous mode disabled.\n");
	}
}



static inline int tsemac_check_tx_bd_space(struct efx_tsemac_local *lp, int num_frag)
{
	//TODO: what are READ_ONCE, num_frag and lp->tx_bd_num
	struct dmasg_descriptor *cur_p;

	/* Ensure we see all descriptor updates from device or TX polling */
	rmb();
	cur_p = &lp->tx_bd_v[(READ_ONCE(lp->tx_bd_tail) + num_frag) %
			     lp->tx_bd_num];
	if (cur_p->busy)		//TODO: check busy bit
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
	cur_p->skb = skb;

	tail_p = lp->tx_bd_p + sizeof(*lp->tx_bd_v) * new_tail_ptr;
	if (++new_tail_ptr >= lp->tx_bd_num)
		new_tail_ptr = 0;
	WRITE_ONCE(lp->tx_bd_tail, new_tail_ptr);

	/* Start the transfer */
	tsemac_dma_out32(lp, XAXIDMA_TX_TDESC_OFFSET, tail_p);

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

static irqreturn_t tsemac_tx_irq(int irq, void *_ndev)
{
	unsigned int status;
	struct net_device *ndev = _ndev;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	status = axienet_dma_in32(lp, XAXIDMA_TX_SR_OFFSET);

	if (!(status & XAXIDMA_IRQ_ALL_MASK))
		return IRQ_NONE;

	axienet_dma_out32(lp, XAXIDMA_TX_SR_OFFSET, status);

	if (unlikely(status & XAXIDMA_IRQ_ERROR_MASK)) {
		netdev_err(ndev, "DMA Tx error 0x%x\n", status);
		netdev_err(ndev, "Current BD is at: 0x%x%08x\n",
			   (lp->tx_bd_v[lp->tx_bd_ci]).phys_msb,
			   (lp->tx_bd_v[lp->tx_bd_ci]).phys);
		schedule_work(&lp->dma_err_task);
	} else {
		/* Disable further TX completion interrupts and schedule
		 * NAPI to handle the completions.
		 */
		u32 cr = lp->tx_dma_cr;

		cr &= ~(XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_DELAY_MASK);
		axienet_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, cr);

		napi_schedule(&lp->napi_tx);
	}

	return IRQ_HANDLED;
}

static irqreturn_t tsemac_rx_irq(int irq, void *_ndev)
{
	//TODO: RX irq handler
	unsigned int status;
	struct net_device *ndev = _ndev;
	struct axienet_local *lp = netdev_priv(ndev);

	status = axienet_dma_in32(lp, XAXIDMA_RX_SR_OFFSET);

	if (!(status & XAXIDMA_IRQ_ALL_MASK))
		return IRQ_NONE;

	axienet_dma_out32(lp, XAXIDMA_RX_SR_OFFSET, status);

	if (unlikely(status & XAXIDMA_IRQ_ERROR_MASK)) {
		netdev_err(ndev, "DMA Rx error 0x%x\n", status);
		netdev_err(ndev, "Current BD is at: 0x%x%08x\n",
			   (lp->rx_bd_v[lp->rx_bd_ci]).phys_msb,
			   (lp->rx_bd_v[lp->rx_bd_ci]).phys);
		schedule_work(&lp->dma_err_task);
	} else {
		/* Disable further RX completion interrupts and schedule
		 * NAPI receive.
		 */
		u32 cr = lp->rx_dma_cr;

		cr &= ~(XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_DELAY_MASK);
		axienet_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, cr);

		napi_schedule(&lp->napi_rx);
	}

	return IRQ_HANDLED;
}

static irqreturn_t tsemac_eth_irq(int irq, void *_ndev)
{
	//TODO: 
	struct net_device *ndev = _ndev;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	unsigned int pending;

	pending = tsemac_in32(lp, XAE_IP_OFFSET);
	if (!pending)
		return IRQ_NONE;

	if (pending & XAE_INT_RXFIFOOVR_MASK)
		ndev->stats.rx_missed_errors++;

	if (pending & XAE_INT_RXRJECT_MASK)
		ndev->stats.rx_frame_errors++;

	tsemac_out32(lp, XAE_IS_OFFSET, pending);
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
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	dev_dbg(&ndev->dev, "tsemac_close()\n");

	napi_disable(&lp->napi_tx);
	napi_disable(&lp->napi_rx);

	phylink_stop(lp->phylink);
	phylink_disconnect_phy(lp->phylink);

	// tsemac_setoptions(ndev, lp->options &
	// 		   ~(XAE_OPTION_TXEN | XAE_OPTION_RXEN));	//TODO: check DISABLE options
	tsemac_clear_32bit(lp, TSEMAC_COMMAND_CONFIG, 
		ETHERNET_CMD_TX_ENA | ETHERNET_CMD_RX_ENA);

	tsemac_dma_stop(lp);

	tsemac_out32(lp, XAE_IE_OFFSET, 0);

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

	//TODO: can I reject new_mtu if it is larger than lp_rxmem's size?
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
		data[i] = tsemac_in32(lp, i);
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

static int tsemac_tx_poll(struct napi_struct *napi, int budget)
{
	//TODO:
	struct efx_tsemac_local *lp = container_of(napi, struct efx_tsemac_local, napi_tx);
	struct net_device *ndev = lp->ndev;
	u32 size = 0;
	int packets;

	packets = tsemac_free_tx_chain(lp, lp->tx_bd_ci, budget, false, &size, budget);

	if (packets) {
		lp->tx_bd_ci += packets;
		if (lp->tx_bd_ci >= lp->tx_bd_num)
			lp->tx_bd_ci %= lp->tx_bd_num;

		ndev->stats.tx_packets += packets;
		ndev->stats.tx_bytes += size;

		/* Matches barrier in tsemac_start_xmit */
		smp_mb();

		if (!tsemac_check_tx_bd_space(lp, MAX_SKB_FRAGS + 1))
			netif_wake_queue(ndev);
	}

	if (packets < budget && napi_complete_done(napi, packets)) {
		/* Re-enable TX completion interrupts. This should
		 * cause an immediate interrupt if any TX packets are
		 * already pending.
		 */
		tsemac_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, lp->tx_dma_cr);
	}
	return packets;
}

static int tsemac_rx_poll(struct napi_struct *napi, int budget)
{
	//TODO: 
	u32 length;
	u32 csumstatus;
	u32 size = 0;
	int packets = 0;
	dma_addr_t tail_p = 0;
	struct efx_tsemac_local *cur_p;
	struct sk_buff *skb, *new_skb;
	struct efx_tsemac_local *lp = container_of(napi, struct efx_tsemac_local, napi_rx);

	cur_p = &lp->rx_bd_v[lp->rx_bd_ci];

	while (packets < budget && (cur_p->status & XAXIDMA_BD_STS_COMPLETE_MASK)) {
		dma_addr_t phys;

		/* Ensure we see complete descriptor update */
		dma_rmb();

		skb = cur_p->skb;
		cur_p->skb = NULL;

		/* skb could be NULL if a previous pass already received the
		 * packet for this slot in the ring, but failed to refill it
		 * with a newly allocated buffer. In this case, don't try to
		 * receive it again.
		 */
		if (likely(skb)) {
			length = cur_p->app4 & 0x0000FFFF;

			phys = desc_get_phys_addr(lp, cur_p);
			dma_unmap_single(lp->dev, phys, lp->max_frm_size,
					 DMA_FROM_DEVICE);

			skb_put(skb, length);
			skb->protocol = eth_type_trans(skb, lp->ndev);
			/*skb_checksum_none_assert(skb);*/
			skb->ip_summed = CHECKSUM_NONE;

			/* if we're doing Rx csum offload, set it up */
			if (lp->features & XAE_FEATURE_FULL_RX_CSUM) {
				csumstatus = (cur_p->app2 &
					      XAE_FULL_CSUM_STATUS_MASK) >> 3;
				if (csumstatus == XAE_IP_TCP_CSUM_VALIDATED ||
				    csumstatus == XAE_IP_UDP_CSUM_VALIDATED) {
					skb->ip_summed = CHECKSUM_UNNECESSARY;
				}
			} else if ((lp->features & XAE_FEATURE_PARTIAL_RX_CSUM) != 0 &&
				   skb->protocol == htons(ETH_P_IP) &&
				   skb->len > 64) {
				skb->csum = be32_to_cpu(cur_p->app3 & 0xFFFF);
				skb->ip_summed = CHECKSUM_COMPLETE;
			}

			napi_gro_receive(napi, skb);

			size += length;
			packets++;
		}

		new_skb = napi_alloc_skb(napi, lp->max_frm_size);
		if (!new_skb)
			break;

		phys = dma_map_single(lp->dev, new_skb->data,
				      lp->max_frm_size,
				      DMA_FROM_DEVICE);
		if (unlikely(dma_mapping_error(lp->dev, phys))) {
			if (net_ratelimit())
				netdev_err(lp->ndev, "RX DMA mapping error\n");
			dev_kfree_skb(new_skb);
			break;
		}
		desc_set_phys_addr(lp, phys, cur_p);

		cur_p->cntrl = lp->max_frm_size;
		cur_p->status = 0;
		cur_p->skb = new_skb;

		/* Only update tail_p to mark this slot as usable after it has
		 * been successfully refilled.
		 */
		tail_p = lp->rx_bd_p + sizeof(*lp->rx_bd_v) * lp->rx_bd_ci;

		if (++lp->rx_bd_ci >= lp->rx_bd_num)
			lp->rx_bd_ci = 0;
		cur_p = &lp->rx_bd_v[lp->rx_bd_ci];
	}

	lp->ndev->stats.rx_packets += packets;
	lp->ndev->stats.rx_bytes += size;

	if (tail_p)
		tsemac_dma_out_addr(lp, XAXIDMA_RX_TDESC_OFFSET, tail_p);

	if (packets < budget && napi_complete_done(napi, packets)) {
		/* Re-enable RX completion interrupts. This should
		 * cause an immediate interrupt if any RX packets are
		 * already pending.
		 */
		tsemac_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, lp->rx_dma_cr);
	}
	return packets;
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


static struct efx_tsemac_local *pcs_to_tsemac_local(struct phylink_pcs *pcs)
{
	return container_of(pcs, struct efx_tsemac_local, pcs);
}

static void tsemac_pcs_get_state(struct phylink_pcs *pcs,
				  struct phylink_link_state *state)
{
	struct mdio_device *pcs_phy = pcs_to_tsemac_local(pcs)->pcs_phy;

	phylink_mii_c22_pcs_get_state(pcs_phy, state);
}

static void tsemac_pcs_an_restart(struct phylink_pcs *pcs)
{
	struct mdio_device *pcs_phy = pcs_to_tsemac_local(pcs)->pcs_phy;

	phylink_mii_c22_pcs_an_restart(pcs_phy);
}

static int tsemac_pcs_config(struct phylink_pcs *pcs, unsigned int mode,
			      phy_interface_t interface,
			      const unsigned long *advertising,
			      bool permit_pause_to_mac)
{
	struct mdio_device *pcs_phy = pcs_to_tsemac_local(pcs)->pcs_phy;
	struct net_device *ndev = pcs_to_tsemac_local(pcs)->ndev;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	int ret;

	// if (lp->switch_x_sgmii) {
	// 	ret = mdiodev_write(pcs_phy, XLNX_MII_STD_SELECT_REG,
	// 			    interface == PHY_INTERFACE_MODE_SGMII ?
	// 				XLNX_MII_STD_SELECT_SGMII : 0);
	// 	if (ret < 0) {
	// 		netdev_warn(ndev,
	// 			    "Failed to switch PHY interface: %d\n",
	// 			    ret);
	// 		return ret;
	// 	}
	// }

	ret = phylink_mii_c22_pcs_config(pcs_phy, mode, interface, advertising);
	if (ret < 0)
		netdev_warn(ndev, "Failed to configure PCS: %d\n", ret);

	return ret;
}

static struct phylink_pcs *tsemac_mac_select_pcs(struct phylink_config *config,
						  phy_interface_t interface)
{
	struct net_device *ndev = to_net_dev(config->dev);
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	if (interface == PHY_INTERFACE_MODE_1000BASEX ||
	    interface ==  PHY_INTERFACE_MODE_SGMII)
		return &lp->pcs;

	return NULL;
}

static void tsemac_mac_config(struct phylink_config *config, unsigned int mode,
			       const struct phylink_link_state *state)
{
	/* nothing meaningful to do */
}

static void tsemac_mac_link_down(struct phylink_config *config,
				  unsigned int mode,
				  phy_interface_t interface)
{
	/* nothing meaningful to do */
}

static void tsemac_mac_link_up(struct phylink_config *config,
				struct phy_device *phy,
				unsigned int mode, phy_interface_t interface,
				int speed, int duplex,
				bool tx_pause, bool rx_pause)
{
	struct net_device *ndev = to_net_dev(config->dev);
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	u32 cmd_cfg, fcc_reg;

	cmd_cfg = tsemac_in32(lp, TSEMAC_COMMAND_CONFIG);

	switch (speed) {
	case SPEED_1000:
		cmd_cfg &= ETH_SPEED_MASK_1000;
		break;
	case SPEED_100:
		cmd_cfg &= ETH_SPEED_MASK_100;
		break;
	case SPEED_10:
		cmd_cfg &= ETH_SPEED_MASK_10;
		break;
	default:
		dev_err(&ndev->dev,
			"Speed other than 10, 100 or 1Gbps is not supported\n");
		break;
	}

	//TODO: handle tx_pause
	// if (tx_pause)
	// 	fcc_reg |= XAE_FCC_FCTX_MASK;
	// else
	// 	fcc_reg &= ~XAE_FCC_FCTX_MASK;
	if (rx_pause)
		cmd_cfg &= ~ETHERNET_CMD_PAUSE_IGNORE;
	else
		cmd_cfg |= ETHERNET_CMD_PAUSE_IGNORE;

	tsemac_out32(lp, TSEMAC_COMMAND_CONFIG, cmd_cfg);
}

void __tsemac_device_reset(struct efx_tsemac_local *lp, off_t offset)
{
	tsemac_out32(lp, ETHERNET_CTRL_PHY_RST, 1);
	tsemac_out32(lp, ETHERNET_CTRL_MAC_RST, 1);
	msleep(100);
	tsemac_out32(lp, ETHERNET_CTRL_PHY_RST, 0);
	tsemac_out32(lp, ETHERNET_CTRL_MAC_RST, 0);
}

static void tsemac_device_reset(struct net_device *ndev)
{
	//TODO: PHY, MAC, DMA reset
	
	u32 tsemac_status;
	u32 frm_size_temp;
	u32 cmd_cfg;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	int ret;

	ret = __tsemac_device_reset(lp);
	if (ret)
		return ret;

	lp->max_frm_size = ETHERNET_MAX_FRAME_SIZE;
	// lp->options |= XAE_OPTION_VLAN;
	// lp->options &= (~XAE_OPTION_JUMBO);


	//TODO: can I skip this checkign if it has already been checked in tsemac_change_mtu function? 
	if ((ndev->mtu > ETHERNET_MTU) && (ndev->mtu <= ETHERNET_JUMBO_MTU)) {
		frm_size_temp = ndev->mtu + ETHERNET_HDR_SIZE +
					ETHERNET_TRL_SIZE;

		if (frm_size_temp <= lp->rxmem)
			lp->max_frm_size = frm_size_temp;
	}

	ret = tsemac_dma_bd_init(ndev);
	if (ret) {
		netdev_err(ndev, "%s: descriptor allocation failed\n",
			   __func__);
		return ret;
	}

	// disable RX
	tsemac_out32(lp, ETHERNET_CTRL_INTERRUPT_EN, 0);
	tsemac_out32(lp, ETHERNET_CTRL_RECEIVE_START, 0);
	// tsemac_status = tsemac_ior(lp, XAE_RCW1_OFFSET);
	// tsemac_status &= ~XAE_RCW1_RX_MASK;
	// tsemac_iow(lp, XAE_RCW1_OFFSET, tsemac_status);
	// tsemac_status = tsemac_ior(lp, XAE_IP_OFFSET);
	// if (tsemac_status & XAE_INT_RXRJECT_MASK)
	// 	tsemac_iow(lp, XAE_IS_OFFSET, XAE_INT_RXRJECT_MASK);
	// tsemac_iow(lp, XAE_IE_OFFSET, lp->eth_irq > 0 ?
	// 	    XAE_INT_RECV_ERROR_MASK : 0);

	// enable RX flow control
	// tsemac_iow(lp, XAE_FCC_OFFSET, XAE_FCC_FCRX_MASK);
	tsemac_clear_32bit(lp, TSEMAC_COMMAND_CONFIG, ETHERNET_CMD_PAUSE_IGNORE);

	/* Sync default options with HW but leave receiver and
	 * transmitter disabled.
	 */
	// tsemac_setoptions(ndev, lp->options & ~(XAE_OPTION_TXEN | XAE_OPTION_RXEN));
	tsemac_clear_32bit(lp, TSEMAC_COMMAND_CONFIG, 
		ETHERNET_CMD_TX_ENA | ETHERNET_CMD_RX_ENA);
	tsemac_set_mac_address(ndev, NULL);
	tsemac_set_multicast_list(ndev);
	// tsemac_setoptions(ndev, lp->options);

	netif_trans_update(ndev);

	return 0;
}

static void tsemac_dma_err_handler(unsigned long data)
{
	u32 i;
	u32 tsemac_status;
	struct dmasg_descriptor *cur_p;
	struct efx_tsemac_local *lp = container_of(work, struct efx_tsemac_local,
						dma_err_task);
	struct net_device *ndev = lp->ndev;

	napi_disable(&lp->napi_tx);
	napi_disable(&lp->napi_rx);

	// tsemac_setoptions(ndev, lp->options &
	// 		   ~(XAE_OPTION_TXEN | XAE_OPTION_RXEN));
	tsemac_clear_32bit(lp, TSEMAC_COMMAND_CONFIG, 
		ETHERNET_CMD_TX_ENA | ETHERNET_CMD_RX_ENA);

	tsemac_dma_stop(lp);

	for (i = 0; i < lp->tx_bd_num; i++) {
		cur_p = &lp->tx_bd_v[i];
		if (cur_p->cntrl) {
			dma_addr_t phys = desc_get_phys_addr(lp, cur_p);

			dma_unmap_single(lp->dev, phys,
					 (cur_p->control & DMASG_DESCRIPTOR_CONTROL_BYTES),
					 DMA_TO_DEVICE);
		}
		if (cur_p->skb)
			dev_kfree_skb_irq(cur_p->skb);
		cur_p->status = 0ULL;
		cur_p->control = 0ULL;
		cur_p->from = 0ULL;
		cur_p->to = 0ULL;
		cur_p->next = 0ULL;
		cur_p->skb = NULL;
	}

	for (i = 0; i < lp->rx_bd_num; i++) {
		cur_p = &lp->rx_bd_v[i];
		cur_p->status = 0;
		//TODO: do I need to clear control and the address?
		cur_p->status = 0ULL;
		cur_p->control = 0ULL;
		cur_p->from = 0ULL;
		cur_p->to = 0ULL;
		cur_p->next = 0ULL;
	}

	lp->tx_bd_ci = 0;
	lp->tx_bd_tail = 0;
	lp->rx_bd_ci = 0;

	tsemac_dma_start(lp);

	// tsemac_status = tsemac_ior(lp, XAE_RCW1_OFFSET);
	// tsemac_status &= ~XAE_RCW1_RX_MASK;
	// tsemac_iow(lp, XAE_RCW1_OFFSET, tsemac_status);
	tsemac_clear_32bit(lp, TSEMAC_COMMAND_CONFIG, 
			ETHERNET_CMD_RX_ENA);

	// tsemac_status = tsemac_ior(lp, XAE_IP_OFFSET);
	// if (tsemac_status & XAE_INT_RXRJECT_MASK)
	// 	tsemac_iow(lp, XAE_IS_OFFSET, XAE_INT_RXRJECT_MASK);
	// tsemac_iow(lp, XAE_IE_OFFSET, lp->eth_irq > 0 ?
	// 	    XAE_INT_RECV_ERROR_MASK : 0);
	// tsemac_iow(lp, XAE_FCC_OFFSET, XAE_FCC_FCRX_MASK);
	tsemac_out32(lp, ETHERNET_CTRL_INTERRUPT_EN, 0);
	tsemac_out32(lp, ETHERNET_CTRL_RECEIVE_START, 0);

	/* Sync default options with HW but leave receiver and
	 * transmitter disabled.
	 */
	// tsemac_setoptions(ndev, lp->options &
	// 		   ~(XAE_OPTION_TXEN | XAE_OPTION_RXEN));
	tsemac_clear_32bit(lp, TSEMAC_COMMAND_CONFIG, 
		ETHERNET_CMD_TX_ENA | ETHERNET_CMD_RX_ENA);
	tsemac_set_mac_address(ndev, NULL);
	tsemac_set_multicast_list(ndev);
	// tsemac_setoptions(ndev, lp->options);
	napi_enable(&lp->napi_rx);
	napi_enable(&lp->napi_tx);
}

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
	// lp->options = XAE_OPTION_DEFAULTS;	//TODO: may use custom options
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
		case TSEMAC_PHY_TYPE_MII:
			lp->phy_mode = PHY_INTERFACE_MODE_MII;
			break;
		case TSEMAC_PHY_TYPE_GMII:
			lp->phy_mode = PHY_INTERFACE_MODE_GMII;
			break;
		case TSEMAC_PHY_TYPE_RGMII_2_0:
			lp->phy_mode = PHY_INTERFACE_MODE_RGMII_ID;
			break;
		case TSEMAC_PHY_TYPE_SGMII:
			lp->phy_mode = PHY_INTERFACE_MODE_SGMII;
			break;
		case TSEMAC_PHY_TYPE_1000BASE_X:
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

static const struct phylink_pcs_ops tsemac_pcs_ops = {
	.pcs_get_state = tsemac_pcs_get_state,
	.pcs_config = tsemac_pcs_config,
	.pcs_an_restart = tsemac_pcs_an_restart,
};

static const struct phylink_mac_ops tsemac_phylink_ops = {
	.validate = phylink_generic_validate,
	.mac_select_pcs = tsemac_mac_select_pcs,
	.mac_config = tsemac_mac_config,
	.mac_link_down = tsemac_mac_link_down,
	.mac_link_up = tsemac_mac_link_up,
};

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
