
#ifndef EFINIX_TSE_H
#define EFINIX_TSE_H

#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>

#define EFXTSE_MTU      1500

struct efx_tsemac_local {
	struct net_device *ndev;
	struct device *dev;

	/* Connection to PHY device */
	struct device_node *phy_node;

	/* MDIO bus data */
	struct mii_bus *mii_bus;	/* MII bus reference */

	/* IO registers, dma functions and IRQs */
	void __iomem *regs;
	void __iomem *dma_regs;

	struct tasklet_struct dma_err_tasklet;

	int tx_irq;
	int rx_irq;
	phy_interface_t phy_mode;

	u32 options;		//in Xilinx's driver, used for TXON/RXON/FLOW_CONTROL
	u32 last_link;
	u32 features;		//in XIlinx's driver, usef for checksum offload

	/* Buffer descriptors */
	//TODO: support SG mode
	// struct axidma_bd *tx_bd_v;
	// dma_addr_t tx_bd_p;
	// struct axidma_bd *rx_bd_v;
	// dma_addr_t rx_bd_p;
	// u32 tx_bd_ci;
	// u32 tx_bd_tail;
	// u32 rx_bd_ci;

	u32 max_frm_size;
	u32 rxmem;

	int csum_offload_on_tx_path;		//in XIlinx's driver, usef for checksum offload
	int csum_offload_on_rx_path;		//in XIlinx's driver, usef for checksum offload

	u32 coalesce_count_rx;
	u32 coalesce_count_tx;
};

#endif
