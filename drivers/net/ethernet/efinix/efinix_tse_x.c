
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

static inline u32 axienet_dma_in32(struct axienet_local *lp, off_t reg);
static inline void axienet_dma_out32(struct axienet_local *lp, off_t reg, u32 value);
static void axienet_dma_bd_release(struct net_device *ndev);
static int axienet_dma_bd_init(struct net_device *ndev);
static void axienet_set_mac_address(struct net_device *ndev, const void *address);
static int netdev_set_mac_address(struct net_device *ndev, void *p);
static void axienet_set_multicast_list(struct net_device *ndev);
static void axienet_setoptions(struct net_device *ndev, u32 options);
static void __axienet_device_reset(struct axienet_local *lp, off_t offset);
static void axienet_device_reset(struct net_device *ndev);
static void axienet_adjust_link(struct net_device *ndev);
static void axienet_start_xmit_done(struct net_device *ndev);
static inline int axienet_check_tx_bd_space(struct axienet_local *lp, int num_frag);
static netdev_tx_t axienet_start_xmit(struct sk_buff *skb, struct net_device *ndev);
static void axienet_recv(struct net_device *ndev);
static irqreturn_t axienet_tx_irq(int irq, void *_ndev);
static irqreturn_t axienet_rx_irq(int irq, void *_ndev);
static int axienet_open(struct net_device *ndev);
static int axienet_stop(struct net_device *ndev);
static int axienet_change_mtu(struct net_device *ndev, int new_mtu);
#ifdef
static void axienet_poll_controller(struct net_device *ndev);
#endif
static void axienet_ethtools_get_drvinfo(struct net_device *ndev, struct ethtool_drvinfo *ed);
static int axienet_ethtools_get_regs_len(struct net_device *ndev);
static void axienet_ethtools_get_regs(struct net_device *ndev, struct ethtool_regs *regs, void *ret);
static void axienet_ethtools_get_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *epauseparm);
static int axienet_ethtools_set_pauseparam(struct net_device *ndev, struct ethtool_pauseparam *epauseparm);
static int axienet_ethtools_get_coalesce(struct net_device *ndev, struct ethtool_coalesce *ecoalesce);
static int axienet_ethtools_set_coalesce(struct net_device *ndev, struct ethtool_coalesce *ecoalesce);
static void axienet_dma_err_handler(unsigned long data);
static int axienet_probe(struct platform_device *pdev);
static int axienet_remove(struct platform_device *pdev);

static const struct net_device_ops axienet_netdev_ops = {
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

static const struct ethtool_ops axienet_ethtool_ops = {
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

static struct platform_driver axienet_driver = {
	.probe = axienet_probe,
	.remove = axienet_remove,
	.driver = {
		 .name = "xilinx_axienet",
		 .of_match_table = axienet_of_match,
	},
};

module_platform_driver(axienet_driver);

MODULE_DESCRIPTION("Xilinx Axi Ethernet driver");
MODULE_AUTHOR("Xilinx");
MODULE_LICENSE("GPL");
