
#ifndef EFINIX_TSE_H
#define EFINIX_TSE_H

#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>

#define EFXTSE_MTU      1500

#define EFXTSE_TX_COUNT		0
#define EFXTSE_TX_USEC		0
#define EFXTSE_RX_COUNT		1
#define EFXTSE_RX_USEC		50

#define ETHERNET_CMD_TX_ENA                 0U
#define ETHERNET_CMD_RX_ENA                 1U
#define ETHERNET_CMD_XON_GEN                2U
#define ETHERNET_CMD_PROMIS_EN              4U
#define ETHERNET_CMD_CRC_FWD                6U
#define ETHERNET_CMD_PAUSE_IGNORE           8U
#define ETHERNET_CMD_TX_ADDR_INS            9U
#define ETHERNET_CMD_RGMII_LOOP_ENA         15U
#define ETHERNET_CMD_ETH_SPEED              16U
#define ETHERNET_CMD_XOFF_GEN               22U
#define ETHERNET_CMD_CNT_RESET              31U

//MAC Configuration Registers
#define TSEMAC_VERSION 				0x0000
#define TSEMAC_COMMAND_CONFIG		0x0008
#define TSEMAC_MAC_ADDR_LO			0x000C
#define TSEMAC_MAC_ADDR_HI			0x0010
#define TSEMAC_FRM_LENGHT			0x0014
#define TSEMAC_PAUSE_QUANT			0x0018
#define TSEMAC_TX_IPG_LEN			0x005C

//MDIO Configuration Registers
#define	TSEMAC_DIVIDER_PRE			0x0100
#define	TSEMAC_RD_WR_EN				0x0104
#define	TSEMAC_REG_PHY_ADDR			0x0108
#define	TSEMAC_WR_DATA				0x010C
#define	TSEMAC_RD_DATA				0x0110
#define	TSEMAC_STATUS				0x0114

//Receive Supplementary Registers
#define	TSEMAC_BOARD_FILTER_EN		0x0140
#define	TSEMAC_MAC_ADDR_MAKE_LO		0x0144
#define	TSEMAC_MAC_ADDR_MAKE_HI		0x0148
#define TSEMAC_TX_DST_ADDR_INS		0x0180
#define TSEMAC_DST_MAC_ADDR_LO		0x0184
#define	TSEMAC_DST_MAC_ADDR_HI		0x0188


struct dmasg_descriptor {
	// See all DMASG_DESCRIPTOR_STATUS_* defines
	// Updated by the DMA at the end of each descriptor and when a S -> M packet is completely transferred into memory
	u32 status;
	// See all DMASG_DESCRIPTOR_CONTROL_* defines
	u32 control;
	// For M -> ? transfers, memory address of the input data
	u64 from;
	// For ? -> M transfers, memory address of the output data
	u64 to;
	// Memory address of the next descriptor
	u64 next;
	struct sk_buff *skb;
} __aligned(0x40);

struct efx_tsemac_local {
	struct net_device *ndev;
	struct device *dev;

	/* Connection to PHY device */
	struct phylink *phylink;
	struct phylink_config phylink_config;
	
	struct mdio_device *pcs_phy;
	struct phylink_pcs pcs;

	/* MDIO bus data */
	struct mii_bus *mii_bus;	/* MII bus reference */
	u8 mii_clk_div;

	/* IO registers, dma functions and IRQs */
	resource_size_t regs_start;
	void __iomem *regs;
	void __iomem *dma_regs;

	struct tasklet_struct dma_err_tasklet;

	int tx_irq;
	int rx_irq;
	int eth_irq;
	phy_interface_t phy_mode;

	/* Buffer descriptors */
	//TODO: support SG mode
	struct napi_struct napi_rx;
	struct napi_struct napi_tx;

	struct dmasg_descriptor *tx_bd_v;
	dma_addr_t tx_bd_p;
	u32 tx_bd_ci;
	u32 tx_bd_tail;
	u32 tx_dma_cr;
	u32 tx_bd_num;

	struct dmasg_descriptor *rx_bd_v;
	dma_addr_t rx_bd_p;
	u32 rx_bd_ci;
	u32 rx_dma_cr;
	u32 rx_bd_num;

	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	struct u64_stats_sync rx_stat_sync;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	struct u64_stats_sync tx_stat_sync;
	u32 options;		//in Xilinx's driver, used for TXON/RXON/FLOW_CONTROL
	u32 features;		//in XIlinx's driver, usef for checksum offload

	u32 max_frm_size;
	u32 rxmem;

	int csum_offload_on_tx_path;		//in XIlinx's driver, usef for checksum offload
	int csum_offload_on_rx_path;		//in XIlinx's driver, usef for checksum offload

	u32 coalesce_count_rx;
	u32 coalesce_usec_rx;
	u32 coalesce_count_tx;
	u32 coalesce_usec_tx;
};

static inline u32 tsemac_ior(struct efx_tsemac_local *lp, off_t reg)
{
	return ioread32(lp->regs + reg);
}

static inline void tsemac_iow(struct efx_tsemac_local *lp, off_t reg,
			       u32 value)
{
	iowrite32(value, lp->regs + reg);
}

static inline u32 tsemac_dma_ior(struct efx_tsemac_local *lp, off_t reg)
{
	return ioread32(lp->dma_regs + reg);
}

static inline void tsemac_dma_iow(struct efx_tsemac_local *lp, off_t reg,
			       u32 value)
{
	return iowrite32(value, lp->dma_regs + reg);
}
#endif
