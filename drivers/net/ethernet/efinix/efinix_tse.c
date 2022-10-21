
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

static struct axienet_option axienet_options[] = {
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

static inline u32 axienet_dma_in32(struct efx_tsemac_local *lp, off_t reg)
{

}

static inline void axienet_dma_out32(struct efx_tsemac_local *lp, off_t reg, u32 value)
{

}

static void axienet_dma_bd_release(struct net_device *ndev)
{
	//TODO: 
}

static int axienet_dma_bd_init(struct net_device *ndev)
{
	//TODO: port to our DMA 	
	u32 cr;
	int i;
	struct sk_buff *skb;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	/* Reset the indexes which are used for accessing the BDs */
	lp->tx_bd_ci = 0;
	lp->tx_bd_tail = 0;
	lp->rx_bd_ci = 0;

	/* Allocate the Tx and Rx buffer descriptors. */
	lp->tx_bd_v = dma_alloc_coherent(ndev->dev.parent,
					 sizeof(*lp->tx_bd_v) * TX_BD_NUM,
					 &lp->tx_bd_p, GFP_KERNEL);
	if (!lp->tx_bd_v)
		goto out;

	lp->rx_bd_v = dma_alloc_coherent(ndev->dev.parent,
					 sizeof(*lp->rx_bd_v) * RX_BD_NUM,
					 &lp->rx_bd_p, GFP_KERNEL);
	if (!lp->rx_bd_v)
		goto out;

	for (i = 0; i < TX_BD_NUM; i++) {
		lp->tx_bd_v[i].next = lp->tx_bd_p +
				      sizeof(*lp->tx_bd_v) *
				      ((i + 1) % TX_BD_NUM);
	}

	for (i = 0; i < RX_BD_NUM; i++) {
		lp->rx_bd_v[i].next = lp->rx_bd_p +
				      sizeof(*lp->rx_bd_v) *
				      ((i + 1) % RX_BD_NUM);

		skb = netdev_alloc_skb_ip_align(ndev, lp->max_frm_size);
		if (!skb)
			goto out;

		lp->rx_bd_v[i].sw_id_offset = (u32) skb;
		lp->rx_bd_v[i].phys = dma_map_single(ndev->dev.parent,
						     skb->data,
						     lp->max_frm_size,
						     DMA_FROM_DEVICE);
		lp->rx_bd_v[i].cntrl = lp->max_frm_size;
	}

	/* Start updating the Rx channel control register */
	cr = axienet_dma_in32(lp, XAXIDMA_RX_CR_OFFSET);
	/* Update the interrupt coalesce count */
	cr = ((cr & ~XAXIDMA_COALESCE_MASK) |
	      ((lp->coalesce_count_rx) << XAXIDMA_COALESCE_SHIFT));
	/* Update the delay timer count */
	cr = ((cr & ~XAXIDMA_DELAY_MASK) |
	      (XAXIDMA_DFT_RX_WAITBOUND << XAXIDMA_DELAY_SHIFT));
	/* Enable coalesce, delay timer and error interrupts */
	cr |= XAXIDMA_IRQ_ALL_MASK;
	/* Write to the Rx channel control register */
	axienet_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, cr);

	/* Start updating the Tx channel control register */
	cr = axienet_dma_in32(lp, XAXIDMA_TX_CR_OFFSET);
	/* Update the interrupt coalesce count */
	cr = (((cr & ~XAXIDMA_COALESCE_MASK)) |
	      ((lp->coalesce_count_tx) << XAXIDMA_COALESCE_SHIFT));
	/* Update the delay timer count */
	cr = (((cr & ~XAXIDMA_DELAY_MASK)) |
	      (XAXIDMA_DFT_TX_WAITBOUND << XAXIDMA_DELAY_SHIFT));
	/* Enable coalesce, delay timer and error interrupts */
	cr |= XAXIDMA_IRQ_ALL_MASK;
	/* Write to the Tx channel control register */
	axienet_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, cr);

	/* Populate the tail pointer and bring the Rx Axi DMA engine out of
	 * halted state. This will make the Rx side ready for reception.
	 */
	axienet_dma_out32(lp, XAXIDMA_RX_CDESC_OFFSET, lp->rx_bd_p);
	cr = axienet_dma_in32(lp, XAXIDMA_RX_CR_OFFSET);
	axienet_dma_out32(lp, XAXIDMA_RX_CR_OFFSET,
			  cr | XAXIDMA_CR_RUNSTOP_MASK);
	axienet_dma_out32(lp, XAXIDMA_RX_TDESC_OFFSET, lp->rx_bd_p +
			  (sizeof(*lp->rx_bd_v) * (RX_BD_NUM - 1)));

	/* Write to the RS (Run-stop) bit in the Tx channel control register.
	 * Tx channel is now ready to run. But only after we write to the
	 * tail pointer register that the Tx channel will start transmitting.
	 */
	axienet_dma_out32(lp, XAXIDMA_TX_CDESC_OFFSET, lp->tx_bd_p);
	cr = axienet_dma_in32(lp, XAXIDMA_TX_CR_OFFSET);
	axienet_dma_out32(lp, XAXIDMA_TX_CR_OFFSET,
			  cr | XAXIDMA_CR_RUNSTOP_MASK);

	return 0;
out:
	axienet_dma_bd_release(ndev);
	return -ENOMEM;
}

static void axienet_set_mac_address(struct net_device *ndev, const void *address)
{
	//TODO: 
}

static int netdev_set_mac_address(struct net_device *ndev, void *p)
{
	//TODO: 
}

static void axienet_set_multicast_list(struct net_device *ndev)
{
	//TODO: determine whether this is supported
}

static void axienet_setoptions(struct net_device *ndev, u32 options)
{
	//TODO: optional. May not needed in our IP
}

static void __axienet_device_reset(struct efx_tsemac_local *lp, off_t offset)
{
	//TODO: optional
}

static void axienet_device_reset(struct net_device *ndev)
{
	//TODO: PHY, MAC, DMA reset
}

static void axienet_adjust_link(struct net_device *ndev)
{
	//TODO: adjest PHY speed settings. called afte auto negotiation
}

static void axienet_start_xmit_done(struct net_device *ndev)
{
	//TODO: dma fields clear upon transmit complete 
}

static inline int axienet_check_tx_bd_space(struct efx_tsemac_local *lp, int num_frag)
{
	//TODO:
}

static netdev_tx_t axienet_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	u32 ii;
	u32 num_frag;
	u32 csum_start_off;
	u32 csum_index_off;
	skb_frag_t *frag;
	dma_addr_t tail_p;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	struct axidma_bd *cur_p;

	num_frag = skb_shinfo(skb)->nr_frags;
	cur_p = &lp->tx_bd_v[lp->tx_bd_tail];

	//TODO: define my check bd space function
	if (axienet_check_tx_bd_space(lp, num_frag)) {
		if (!netif_queue_stopped(ndev))
			netif_stop_queue(ndev);
		return NETDEV_TX_BUSY;
	}

	//TODO: port to my DMA
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (lp->features & XAE_FEATURE_FULL_TX_CSUM) {
			/* Tx Full Checksum Offload Enabled */
			cur_p->app0 |= 2;
		} else if (lp->features & XAE_FEATURE_PARTIAL_RX_CSUM) {
			csum_start_off = skb_transport_offset(skb);
			csum_index_off = csum_start_off + skb->csum_offset;
			/* Tx Partial Checksum Offload Enabled */
			cur_p->app0 |= 1;
			cur_p->app1 = (csum_start_off << 16) | csum_index_off;
		}
	} else if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
		cur_p->app0 |= 2; /* Tx Full Checksum Offload Enabled */
	}

	cur_p->cntrl = skb_headlen(skb) | XAXIDMA_BD_CTRL_TXSOF_MASK;
	cur_p->phys = dma_map_single(ndev->dev.parent, skb->data,
				     skb_headlen(skb), DMA_TO_DEVICE);
					 
	for (ii = 0; ii < num_frag; ii++) {
		++lp->tx_bd_tail;
		lp->tx_bd_tail %= TX_BD_NUM;
		cur_p = &lp->tx_bd_v[lp->tx_bd_tail];
		frag = &skb_shinfo(skb)->frags[ii];
		cur_p->phys = dma_map_single(ndev->dev.parent,
					     skb_frag_address(frag),
					     skb_frag_size(frag),
					     DMA_TO_DEVICE);
		cur_p->cntrl = skb_frag_size(frag);
	}
	
	cur_p->cntrl |= XAXIDMA_BD_CTRL_TXEOF_MASK;
	cur_p->app4 = (unsigned long)skb;

	tail_p = lp->tx_bd_p + sizeof(*lp->tx_bd_v) * lp->tx_bd_tail;
	/* Start the transfer */
	axienet_dma_out32(lp, XAXIDMA_TX_TDESC_OFFSET, tail_p);
	++lp->tx_bd_tail;
	lp->tx_bd_tail %= TX_BD_NUM;

	return NETDEV_TX_OK;
}

static void axienet_recv(struct net_device *ndev)
{
	//TODO: optional 
}
static irqreturn_t axienet_tx_irq(int irq, void *_ndev)
{
	//TODO: tx irq handler
	u32 cr;
	unsigned int status;
	struct net_device *ndev = _ndev;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	status = axienet_dma_in32(lp, XAXIDMA_TX_SR_OFFSET);
	if (status & (XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_DELAY_MASK)) {
		axienet_dma_out32(lp, XAXIDMA_TX_SR_OFFSET, status);
		axienet_start_xmit_done(lp->ndev);
		goto out;
	}
	if (!(status & XAXIDMA_IRQ_ALL_MASK))
		dev_err(&ndev->dev, "No interrupts asserted in Tx path\n");
	if (status & XAXIDMA_IRQ_ERROR_MASK) {
		dev_err(&ndev->dev, "DMA Tx error 0x%x\n", status);
		dev_err(&ndev->dev, "Current BD is at: 0x%x\n",
			(lp->tx_bd_v[lp->tx_bd_ci]).phys);

		cr = axienet_dma_in32(lp, XAXIDMA_TX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* Write to the Tx channel control register */
		axienet_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, cr);

		cr = axienet_dma_in32(lp, XAXIDMA_RX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* Write to the Rx channel control register */
		axienet_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, cr);

		tasklet_schedule(&lp->dma_err_tasklet);
		axienet_dma_out32(lp, XAXIDMA_TX_SR_OFFSET, status);
	}
out:
	return IRQ_HANDLED;
}

static irqreturn_t axienet_rx_irq(int irq, void *_ndev)
{
	//TODO: RX irq handler
	u32 cr;
	unsigned int status;
	struct net_device *ndev = _ndev;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	status = axienet_dma_in32(lp, XAXIDMA_RX_SR_OFFSET);
	if (status & (XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_DELAY_MASK)) {
		axienet_dma_out32(lp, XAXIDMA_RX_SR_OFFSET, status);
		axienet_recv(lp->ndev);
		goto out;
	}
	if (!(status & XAXIDMA_IRQ_ALL_MASK))
		dev_err(&ndev->dev, "No interrupts asserted in Rx path\n");
	if (status & XAXIDMA_IRQ_ERROR_MASK) {
		dev_err(&ndev->dev, "DMA Rx error 0x%x\n", status);
		dev_err(&ndev->dev, "Current BD is at: 0x%x\n",
			(lp->rx_bd_v[lp->rx_bd_ci]).phys);

		cr = axienet_dma_in32(lp, XAXIDMA_TX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* Finally write to the Tx channel control register */
		axienet_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, cr);

		cr = axienet_dma_in32(lp, XAXIDMA_RX_CR_OFFSET);
		/* Disable coalesce, delay timer and error interrupts */
		cr &= (~XAXIDMA_IRQ_ALL_MASK);
		/* write to the Rx channel control register */
		axienet_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, cr);

		tasklet_schedule(&lp->dma_err_tasklet);
		axienet_dma_out32(lp, XAXIDMA_RX_SR_OFFSET, status);
	}
out:
	return IRQ_HANDLED;
}

static int axienet_open(struct net_device *ndev)
{
	//TODO: 
	int ret, mdio_mcreg;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	struct phy_device *phydev = NULL;

	dev_dbg(&ndev->dev, "axienet_open()\n");

	mdio_mcreg = axienet_ior(lp, XAE_MDIO_MC_OFFSET);
	ret = axienet_mdio_wait_until_ready(lp);
	if (ret < 0)
		return ret;
	/* Disable the MDIO interface till Axi Ethernet Reset is completed.
	 * When we do an Axi Ethernet reset, it resets the complete core
	 * including the MDIO. If MDIO is not disabled when the reset
	 * process is started, MDIO will be broken afterwards.
	 */
	axienet_iow(lp, XAE_MDIO_MC_OFFSET,
		    (mdio_mcreg & (~XAE_MDIO_MC_MDIOEN_MASK)));
	axienet_device_reset(ndev);
	/* Enable the MDIO */
	axienet_iow(lp, XAE_MDIO_MC_OFFSET, mdio_mcreg);
	ret = axienet_mdio_wait_until_ready(lp);
	if (ret < 0)
		return ret;

	if (lp->phy_node) {
		phydev = of_phy_connect(lp->ndev, lp->phy_node,
					axienet_adjust_link, 0, lp->phy_mode);

		if (!phydev)
			dev_err(lp->dev, "of_phy_connect() failed\n");
		else
			phy_start(phydev);
	}

	/* Enable tasklets for Axi DMA error handling */
	tasklet_init(&lp->dma_err_tasklet, axienet_dma_err_handler,
		     (unsigned long) lp);

	/* Enable interrupts for Axi DMA Tx */
	ret = request_irq(lp->tx_irq, axienet_tx_irq, 0, ndev->name, ndev);
	if (ret)
		goto err_tx_irq;
	/* Enable interrupts for Axi DMA Rx */
	ret = request_irq(lp->rx_irq, axienet_rx_irq, 0, ndev->name, ndev);
	if (ret)
		goto err_rx_irq;

	return 0;

err_rx_irq:
	free_irq(lp->tx_irq, ndev);
err_tx_irq:
	if (phydev)
		phy_disconnect(phydev);
	tasklet_kill(&lp->dma_err_tasklet);
	dev_err(lp->dev, "request_irq() failed\n");
	return ret;
}


static int axienet_stop(struct net_device *ndev)
{
	u32 cr;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	// dev_dbg(&ndev->dev, "axienet_close()\n");

	//TODO: use our registers
	cr = axienet_dma_in32(lp, XAXIDMA_RX_CR_OFFSET);
	axienet_dma_out32(lp, XAXIDMA_RX_CR_OFFSET,
			  cr & (~XAXIDMA_CR_RUNSTOP_MASK));
	cr = axienet_dma_in32(lp, XAXIDMA_TX_CR_OFFSET);
	axienet_dma_out32(lp, XAXIDMA_TX_CR_OFFSET,
			  cr & (~XAXIDMA_CR_RUNSTOP_MASK));
	axienet_setoptions(ndev, lp->options &
			   ~(XAE_OPTION_TXEN | XAE_OPTION_RXEN));

	tasklet_kill(&lp->dma_err_tasklet);

	free_irq(lp->tx_irq, ndev);
	free_irq(lp->rx_irq, ndev);

	if (ndev->phydev)
		phy_disconnect(ndev->phydev);

	//TODO: implement our release function
	axienet_dma_bd_release(ndev);
	return 0;
}

static int axienet_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	//TODO: port to our IP
	if (netif_running(ndev))
		return -EBUSY;

	if ((new_mtu + VLAN_ETH_HLEN +
		XAE_TRL_SIZE) > lp->rxmem)
		return -EINVAL;

	ndev->mtu = new_mtu;

	return 0;
}

#ifdef
//TODO: determine whether need to implement it
static void axienet_poll_controller(struct net_device *ndev);
#endif
static void axienet_ethtools_get_drvinfo(struct net_device *ndev, struct ethtool_drvinfo *ed)
{
	//TODO: 
}
static int axienet_ethtools_get_regs_len(struct net_device *ndev)
{
	//TODO: 
}
static void axienet_ethtools_get_regs(struct net_device *ndev, struct ethtool_regs *regs, void *ret)
{
	//TODO: Dump all registers
}

static void axienet_ethtools_get_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *epauseparm)
{	
	//TODO: use our registers
	u32 regval;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	epauseparm->autoneg  = 0;
	regval = axienet_ior(lp, XAE_FCC_OFFSET);
	epauseparm->tx_pause = regval & XAE_FCC_FCTX_MASK;
	epauseparm->rx_pause = regval & XAE_FCC_FCRX_MASK;
}

static int axienet_ethtools_set_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *epauseparm)
{
	//TODO: use our registers
	u32 regval = 0;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	if (netif_running(ndev)) {
		netdev_err(ndev,
			   "Please stop netif before applying configuration\n");
		return -EFAULT;
	}

	//TODO: define a new function to access IO
	regval = axienet_ior(lp, XAE_FCC_OFFSET);
	if (epauseparm->tx_pause)
		regval |= XAE_FCC_FCTX_MASK;
	else
		regval &= ~XAE_FCC_FCTX_MASK;
	if (epauseparm->rx_pause)
		regval |= XAE_FCC_FCRX_MASK;
	else
		regval &= ~XAE_FCC_FCRX_MASK;
	axienet_iow(lp, XAE_FCC_OFFSET, regval);

	return 0;
}

static int axienet_ethtools_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ecoalesce);
static int axienet_ethtools_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ecoalesce);
static void axienet_dma_err_handler(unsigned long data);
static int tsemac_probe(struct platform_device *pdev) 
{
	int ret;
	struct device_node *np;
	struct efx_tsemac_local *lp;
	struct net_device *ndev;
	const void *mac_addr;
	struct resource *ethres, dmares;
	u32 value;
    
	ndev = alloc_etherdev(sizeof(*lp));
	if (!ndev)
		return -ENOMEM;

	platform_set_drvdata(pdev, ndev);

	SET_NETDEV_DEV(ndev, &pdev->dev);
	ndev->flags &= ~IFF_MULTICAST;	//FIXME: should I clear IFF_MULTICAST?
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
	/* Map device registers */
	ethres = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	lp->regs = devm_ioremap_resource(&pdev->dev, ethres);
	if (IS_ERR(lp->regs)) {
		dev_err(&pdev->dev, "could not map Efinix TSEMAC regs.\n");
		ret = PTR_ERR(lp->regs);
		goto free_netdev;
	}

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

	//TODO: customize the memory size in our own devicetree
	of_property_read_u32(pdev->dev.of_node, "xlnx,rxmem", &lp->rxmem);

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
		lp->phy_mode = of_get_phy_mode(pdev->dev.of_node);
		if (lp->phy_mode < 0) {
			ret = -EINVAL;
			goto free_netdev;
		}
	}
	
	//TODO: find how does of_parse_phandle work 
	/* Find the DMA node, map the DMA registers, and decode the DMA IRQs */
	np = of_parse_phandle(pdev->dev.of_node, "axistream-connected", 0);
	if (!np) {
		dev_err(&pdev->dev, "could not find DMA node\n");
		ret = -ENODEV;
		goto free_netdev;
	}
	ret = of_address_to_resource(np, 0, &dmares);
	if (ret) {
		dev_err(&pdev->dev, "unable to get DMA resource\n");
		goto free_netdev;
	}
	lp->dma_regs = devm_ioremap_resource(&pdev->dev, &dmares);
	if (IS_ERR(lp->dma_regs)) {
		dev_err(&pdev->dev, "could not map DMA regs\n");
		ret = PTR_ERR(lp->dma_regs);
		goto free_netdev;
	}

	//TODO: define our IRQs level in devicetree
	lp->rx_irq = irq_of_parse_and_map(np, 1);
	lp->tx_irq = irq_of_parse_and_map(np, 0);
	of_node_put(np);
	if ((lp->rx_irq <= 0) || (lp->tx_irq <= 0)) {
		dev_err(&pdev->dev, "could not determine irqs\n");
		ret = -ENOMEM;
		goto free_netdev;
	}

	/* Retrieve the MAC address */
	mac_addr = of_get_mac_address(pdev->dev.of_node);
	if (!mac_addr) {
		dev_err(&pdev->dev, "could not find MAC address\n");
		goto free_netdev;
	}

	//TODO: define a function to set MAC address
	axienet_set_mac_address(ndev, mac_addr);

	//TODO: check whether we support interrupt coalescing
	lp->coalesce_count_rx = XAXIDMA_DFT_RX_THRESHOLD;
	lp->coalesce_count_tx = XAXIDMA_DFT_TX_THRESHOLD;

	//TODO: define MDIO in devicetree
	lp->phy_node = of_parse_phandle(pdev->dev.of_node, "phy-handle", 0);
	if (lp->phy_node) {
		ret = axienet_mdio_setup(lp, pdev->dev.of_node);
		if (ret)
			dev_warn(&pdev->dev, "error registering MDIO bus\n");
	}
	
	ret = register_netdev(lp->ndev);
	if (ret) {
		dev_err(lp->dev, "register_netdev() error (%i)\n", ret);
		goto free_netdev;
	}
	return 0;

free_netdev:
	free_netdev(ndev);

	return ret;
}

static int tsemac_remove(struct platform_device *pdev);

static const struct net_device_ops tsemac_netdev_ops = {
	.ndo_open = axienet_open,
	.ndo_stop = axienet_stop,
	.ndo_start_xmit = axienet_start_xmit,
	.ndo_change_mtu	= axienet_change_mtu,
	.ndo_set_mac_address = netdev_set_mac_address,
	.ndo_validate_addr = eth_validate_addr,
	.ndo_set_rx_mode = axienet_set_multicast_list,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller = axienet_poll_controller,
#endif
};

static const struct ethtool_ops tsemac_ethtool_ops = {
	.get_drvinfo    = axienet_ethtools_get_drvinfo,
	.get_regs_len   = axienet_ethtools_get_regs_len,
	.get_regs       = axienet_ethtools_get_regs,
	.get_link       = ethtool_op_get_link,
	.get_pauseparam = axienet_ethtools_get_pauseparam,
	.set_pauseparam = axienet_ethtools_set_pauseparam,
	.get_coalesce   = axienet_ethtools_get_coalesce,
	.set_coalesce   = axienet_ethtools_set_coalesce,
	.get_link_ksettings = phy_ethtool_get_link_ksettings,
	.set_link_ksettings = phy_ethtool_set_link_ksettings,
};

static struct platform_driver efinix_tse_driver = {
	.probe = tsemac_probe,
	.remove = tsemac_remove,
	.driver = {
		 .name = "xilinx_axienet",
		 .of_match_table = axienet_of_match,
	},
};

module_platform_driver(efinix_tse_driver);

MODULE_AUTHOR("Efinix");
MODULE_DESCRIPTION("Efinix Triple Speed Ethernet MAC driver");
MODULE_LICENSE("GPL v2");
