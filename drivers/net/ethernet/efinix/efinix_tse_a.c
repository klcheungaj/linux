


static inline u32 tse_tx_avail(struct altera_tse_private *priv);
static u16 sgmii_pcs_read(struct altera_tse_private *priv, int regnum);
static void sgmii_pcs_write(struct altera_tse_private *priv, int regnum, u16 value);
static int sgmii_pcs_scratch_test(struct altera_tse_private *priv, u16 value);
static int altera_tse_mdio_read(struct mii_bus *bus, int mii_id, int regnum);
static int altera_tse_mdio_write(struct mii_bus *bus, int mii_id, int regnum, u16 value);
static int altera_tse_mdio_create(struct net_device *dev, unsigned int id);
static void altera_tse_mdio_destroy(struct net_device *dev);
static int tse_init_rx_buffer(struct altera_tse_private *priv, struct tse_buffer *rxbuffer, int len);
static void tse_free_rx_buffer(struct altera_tse_private *priv, struct tse_buffer *rxbuffer);
static void tse_free_tx_buffer(struct altera_tse_private *priv, struct tse_buffer *buffer);
static int alloc_init_skbufs(struct altera_tse_private *priv);
static void free_skbufs(struct net_device *dev);
static inline void tse_rx_refill(struct altera_tse_private *priv);
static inline void tse_rx_vlan(struct net_device *dev, struct sk_buff *skb);
static int tse_rx(struct altera_tse_private *priv, int limit);
static int tse_tx_complete(struct altera_tse_private *priv);
static int tse_poll(struct napi_struct *napi, int budget);
static irqreturn_t altera_isr(int irq, void *dev_id);
static int tse_start_xmit(struct sk_buff *skb, struct net_device *dev);
static void altera_tse_adjust_link(struct net_device *dev);
static struct phy_device *connect_local_phy(struct net_device *dev);
static int altera_tse_phy_get_addr_mdio_create(struct net_device *dev);
static int init_phy(struct net_device *dev);
static void tse_update_mac_addr(struct altera_tse_private *priv, u8 *addr);
static int reset_mac(struct altera_tse_private *priv);
static int init_mac(struct altera_tse_private *priv);
static void tse_set_mac(struct altera_tse_private *priv, bool enable);
static int tse_change_mtu(struct net_device *dev, int new_mtu);
static void altera_tse_set_mcfilter(struct net_device *dev);
static void altera_tse_set_mcfilterall(struct net_device *dev);
static void tse_set_rx_mode_hashfilter(struct net_device *dev);
static void tse_set_rx_mode(struct net_device *dev);
static int init_sgmii_pcs(struct net_device *dev);
static int tse_open(struct net_device *dev);
static int tse_shutdown(struct net_device *dev);
static int request_and_map(struct platform_device *pdev, const char *name, struct resource **res, void __iomem **ptr);
static int efinix_tse_probe(struct platform_device *pdev);
static int efinix_tse_remove(struct platform_device *pdev);


static struct net_device_ops altera_tse_netdev_ops = {
	.ndo_open		= tse_open,
	.ndo_stop		= tse_shutdown,
	.ndo_start_xmit		= tse_start_xmit,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_set_rx_mode	= tse_set_rx_mode,
	.ndo_change_mtu		= tse_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
};

static const struct altera_dmaops altera_dtype_sgdma = {
	.altera_dtype = ALTERA_DTYPE_SGDMA,
	.dmamask = 32,
	.reset_dma = sgdma_reset,
	.enable_txirq = sgdma_enable_txirq,
	.enable_rxirq = sgdma_enable_rxirq,
	.disable_txirq = sgdma_disable_txirq,
	.disable_rxirq = sgdma_disable_rxirq,
	.clear_txirq = sgdma_clear_txirq,
	.clear_rxirq = sgdma_clear_rxirq,
	.tx_buffer = sgdma_tx_buffer,
	.tx_completions = sgdma_tx_completions,
	.add_rx_desc = sgdma_add_rx_desc,
	.get_rx_status = sgdma_rx_status,
	.init_dma = sgdma_initialize,
	.uninit_dma = sgdma_uninitialize,
	.start_rxdma = sgdma_start_rxdma,
};

static const struct altera_dmaops altera_dtype_msgdma = {
	.altera_dtype = ALTERA_DTYPE_MSGDMA,
	.dmamask = 64,
	.reset_dma = msgdma_reset,
	.enable_txirq = msgdma_enable_txirq,
	.enable_rxirq = msgdma_enable_rxirq,
	.disable_txirq = msgdma_disable_txirq,
	.disable_rxirq = msgdma_disable_rxirq,
	.clear_txirq = msgdma_clear_txirq,
	.clear_rxirq = msgdma_clear_rxirq,
	.tx_buffer = msgdma_tx_buffer,
	.tx_completions = msgdma_tx_completions,
	.add_rx_desc = msgdma_add_rx_desc,
	.get_rx_status = msgdma_rx_status,
	.init_dma = msgdma_initialize,
	.uninit_dma = msgdma_uninitialize,
	.start_rxdma = msgdma_start_rxdma,
};

static const struct of_device_id efinix_tse_ids[] = {
	{ .compatible = "efinix,tse-1.0", .data = &efinix_dtype_sgdma, },
	{},
};
MODULE_DEVICE_TABLE(of, efinix_tse_ids);

static struct platform_driver efinix_tse_driver = {
	.probe		= efinix_tse_probe,
	.remove		= efinix_tse_remove,
	.suspend	= NULL,
	.resume		= NULL,
	.driver		= {
		.name	= EFINIX_TSE_RESOURCE_NAME,
		.of_match_table = efinix_tse_ids,
	},
};

module_platform_driver(efinix_tse_driver);

MODULE_AUTHOR("Efinix");
MODULE_DESCRIPTION("Efinix Triple Speed Ethernet MAC driver");
MODULE_LICENSE("GPL v2");
