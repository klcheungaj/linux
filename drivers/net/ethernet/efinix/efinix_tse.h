
#ifndef EFINIX_TSE_H
#define EFINIX_TSE_H

#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/if_vlan.h>
#include <linux/phylink.h>


#define ETHERNET_HDR_SIZE				14 	/* Size of Ethernet header */
#define ETHERNET_TRL_SIZE			 	4 	/* Size of Ethernet trailer (FCS) */
#define ETHERNET_MTU					1500 /* Max MTU of an Ethernet frame */
#define ETHERNET_JUMBO_MTU		      	9000 /* Max MTU of a jumbo Eth. frame */	
#define ETHERNET_MAX_FRAME_SIZE			(ETHERNET_HDR_SIZE + ETHERNET_TRL_SIZE + ETHERNET_MTU)

#define EFXTSE_TX_COUNT		0
#define EFXTSE_TX_USEC		0
#define EFXTSE_RX_COUNT		1
#define EFXTSE_RX_USEC		50

#define BIT_0   			(1U << 0)
#define BIT_1   			(1U << 1)
#define BIT_2   			(1U << 2)
#define BIT_3   			(1U << 3)
#define BIT_4   			(1U << 4)
#define BIT_5   			(1U << 5)
#define BIT_6   			(1U << 6)
#define BIT_7   			(1U << 7)
#define BIT_8   			(1U << 8)
#define BIT_9   			(1U << 9)
#define BIT_10  			(1U << 10)
#define BIT_11  			(1U << 11)
#define BIT_12  			(1U << 12)
#define BIT_13  			(1U << 13)
#define BIT_14  			(1U << 14)
#define BIT_15  			(1U << 15)
#define BIT_16  			(1U << 16)
#define BIT_17  			(1U << 17)
#define BIT_18  			(1U << 18)
#define BIT_19  			(1U << 19)
#define BIT_20  			(1U << 20)
#define BIT_21  			(1U << 21)
#define BIT_22  			(1U << 22)
#define BIT_23  			(1U << 23)
#define BIT_24  			(1U << 24)
#define BIT_25  			(1U << 25)
#define BIT_26  			(1U << 26)
#define BIT_27  			(1U << 27)
#define BIT_28  			(1U << 28)
#define BIT_29  			(1U << 29)
#define BIT_30  			(1U << 30)
#define BIT_31  			(1U << 31)

#define ETHERNET_CMD_TX_ENA                 BIT_0
#define ETHERNET_CMD_RX_ENA                 BIT_1
#define ETHERNET_CMD_XON_GEN                BIT_2
#define ETHERNET_CMD_PROMIS_EN              BIT_4
#define ETHERNET_CMD_CRC_FWD                BIT_6
#define ETHERNET_CMD_PAUSE_IGNORE           BIT_8
#define ETHERNET_CMD_TX_ADDR_INS            BIT_9
#define ETHERNET_CMD_RGMII_LOOP_ENA         BIT_15
#define ETHERNET_CMD_ETH_SPEED              BIT_16
#define ETHERNET_CMD_XOFF_GEN               BIT_22
#define ETHERNET_CMD_CNT_RESET              BIT_31

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

// additional TSEMAC control
#define ETHERNET_CTRL_MAC_RST               0x200
#define ETHERNET_CTRL_PHY_RST               0x204
#define ETHERNET_CTRL_INTERRUPT_EN          0x208
#define ETHERNET_CTRL_READ_COUNT            0x212
#define ETHERNET_CTRL_INTERRUPT_CLR         0x216
#define ETHERNET_CTRL_TRANSFER_START        0x220
#define ETHERNET_CTRL_RECEIVE_START         0x224
#define ETHERNET_CTRL_RECEIVE_COUNT         0x228
#define ETHERNET_CTRL_RX_COALESCE           0x232
#define ETHERNET_CTRL_RX_USEC               0x236

#define TSEMAC_PHY_TYPE_MII				0
#define TSEMAC_PHY_TYPE_GMII			1
#define TSEMAC_PHY_TYPE_RGMII_1_3		2
#define TSEMAC_PHY_TYPE_RGMII_2_0		3
#define TSEMAC_PHY_TYPE_SGMII			4
#define TSEMAC_PHY_TYPE_1000BASE_X		5

#define ETH_SPEED_MASK_10				0xFFF1FFFF
#define ETH_SPEED_MASK_100				0xFFF2FFFF
#define ETH_SPEED_MASK_1000				0xFFF4FFFF


#define dmasg_ca(base, channel)                                 (base + channel*0x80)
#define DMA_CH_BYTE_PER_BURST_MASK                       0xFFF
#define DMA_CH_INPUT_ADDRESS                             0x00
#define DMA_CH_INPUT_STREAM                              0x08
#define DMA_CH_INPUT_CONFIG                              0x0C
#define DMA_CH_INPUT_CONFIG_MEMORY                       BIT_12
#define DMA_CH_INPUT_CONFIG_COMPLETION_ON_PACKET         BIT_13
#define DMA_CH_INPUT_CONFIG_WAIT_ON_PACKET               BIT_14
#define DMA_CH_OUTPUT_ADDRESS                            0x10
#define DMA_CH_OUTPUT_STREAM                             0x18
#define DMA_CH_OUTPUT_CONFIG                             0x1C
#define DMA_CH_OUTPUT_CONFIG_MEMORY                      BIT_12
#define DMA_CH_OUTPUT_CONFIG_LAST                        BIT_13
#define DMA_CH_DIRECT_BYTES                              0x20
#define DMA_CH_STATUS                                    0x2C
#define DMA_CH_STATUS_DIRECT_START                       BIT_0
#define DMA_CH_STATUS_BUSY                               BIT_0
#define DMA_CH_STATUS_SELF_RESTART                       BIT_1
#define DMA_CH_STATUS_STOP                               BIT_2
#define DMA_CH_STATUS_LINKED_LIST_START                  BIT_4
#define DMA_CH_FIFO                                      0x40
#define DMA_CH_PRIORITY                                  0x44
#define DMA_CH_INTERRUPT_ENABLE                          0x50
#define DMA_CH_INTERRUPT_PENDING                         0x54
#define DMA_CH_PROGRESS_BYTES                            0x60
#define DMA_CH_LINKED_LIST_HEAD                          0x70
// Interrupt at the end of each descriptor
#define DMA_CH_INTERRUPT_DESCRIPTOR_COMPLETION_MASK      BIT_0
// Interrupt at the middle of each descriptor, require the half_completion_interrupt option to be enabled for the channel
#define DMA_CH_INTERRUPT_DESCRIPTOR_COMPLETION_HALF_MASK BIT_1
// Interrupt when the channel is going off (not busy anymore)
#define DMA_CH_INTERRUPT_CHANNEL_COMPLETION_MASK         BIT_2
// Interrupt each time that a linked list's descriptor status field is updated
#define DMA_CH_INTERRUPT_LINKED_LIST_UPDATE_MASK         BIT_3
// Interrupt each time a S -> M  channel has done transferring a packet into the memory
#define DMA_CH_INTERRUPT_INPUT_PACKET_MASK               BIT_4
// Number of bytes (minus one) reserved at the descriptor FROM/TO addresses.
// If you want to transfer 10 bytes, this field should take the value 9
#define DMASG_DESCRIPTOR_CONTROL_BYTES                          0x7FFFFFF
//Only for M -> S transfers, specify if a end of packet should be send at the end of the transfer
#define DMASG_DESCRIPTOR_CONTROL_END_OF_PACKET                  BIT_30
// Number of bytes transferred by the DMA for this descriptor.
#define DMASG_DESCRIPTOR_STATUS_BYTES                           0x7FFFFFF
// Only for S -> M transfers, specify if the descriptor mark the end of a received packet
// Can be used when the dmasg_input_stream function is called with completion_on_packet set.
#define DMASG_DESCRIPTOR_STATUS_END_OF_PACKET                   BIT_30
// Specify if the descriptor was executed by the DMA.
// If the DMA read a completed descriptor, the channel is stopped and will produce a CHANNEL_COMPLETION interrupt.
#define DMASG_DESCRIPTOR_STATUS_COMPLETED                       BIT_31
#define DMASG_RX_BASE											0x0
#define DMASG_TX_BASE											0x80

#define DMASG_IRQ_ALL_MASK										0x1F

#define TSEMAC_FEATURE_PARTIAL_RX_CSUM	(1 << 0)
#define TSEMAC_FEATURE_PARTIAL_TX_CSUM	(1 << 1)
#define TSEMAC_FEATURE_FULL_RX_CSUM	(1 << 2)
#define TSEMAC_FEATURE_FULL_TX_CSUM	(1 << 3)
#define TSEMAC_FEATURE_DMA_64BIT		(1 << 4)

#define TSEMAC_NO_CSUM_OFFLOAD		0

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

	struct clk *axi_clk;
	/* MDIO bus data */
	struct mii_bus *mii_bus;	/* MII bus reference */
	u8 mii_clk_div;

	/* IO registers, dma functions and IRQs */
	resource_size_t regs_start;
	void __iomem *regs;
	void __iomem *dma_regs;

	struct work_struct dma_err_task;

	int tx_irq;
	int rx_irq;
	int eth_irq;
	phy_interface_t phy_mode;

	/* Buffer descriptors */
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

static inline void desc_set_tx_phys_addr(struct efx_tsemac_local *lp, dma_addr_t addr,
			       struct dmasg_descriptor *desc)
{
	desc->from = lower_32_bits(addr);
}

static inline dma_addr_t desc_get_tx_phys_addr(struct efx_tsemac_local *lp,
				     struct dmasg_descriptor *desc)
{
	return desc->from;
}

static inline void desc_set_rx_phys_addr(struct efx_tsemac_local *lp, dma_addr_t addr,
			       struct dmasg_descriptor *desc)
{
	desc->to = lower_32_bits(addr);
}

static inline dma_addr_t desc_get_rx_phys_addr(struct efx_tsemac_local *lp,
				     struct dmasg_descriptor *desc)
{
	return desc->to;
}

static inline u32 tsemac_in32(struct efx_tsemac_local *lp, off_t reg)
{
	return ioread32(lp->regs + reg);
}

static inline void tsemac_out32(struct efx_tsemac_local *lp, off_t reg,
			       u32 value)
{
	iowrite32(value, lp->regs + reg);
}

static inline void tsemac_set_32bit(struct efx_tsemac_local *lp, off_t reg,
			       u32 value)
{
	u32 temp = tsemac_in32(lp, reg);
	temp |= value;
	tsemac_out32(lp, reg, temp);
}

static inline void tsemac_clear_32bit(struct efx_tsemac_local *lp, off_t reg,
			       u32 value)
{
	u32 temp = tsemac_in32(lp, reg);
	temp &= ~value;
	tsemac_out32(lp, reg, temp);
}

static inline u32 tsemac_dma_in32(struct efx_tsemac_local *lp, off_t reg, off_t ch_offset)
{
	return ioread32(lp->dma_regs + reg + ch_offset);
}

static inline void tsemac_dma_out32(struct efx_tsemac_local *lp, off_t reg, off_t ch_offset,
			       u32 value)
{
	return iowrite32(value, lp->dma_regs + reg + ch_offset);
}

int __tsemac_device_reset(struct efx_tsemac_local *lp);

int tsemac_free_tx_chain(struct efx_tsemac_local *lp, u32 first_bd,
				 int nr_bds, bool force, u32 *sizep, int budget);

void tsemac_dma_stop(struct efx_tsemac_local *lp);

void tsemac_dma_bd_release(struct net_device *ndev);

int tsemac_dma_bd_init(struct net_device *ndev);

void tsemac_dma_start(struct efx_tsemac_local *lp);

void tsemac_mdio_teardown(struct efx_tsemac_local *lp);

int tsemac_mdio_setup(struct efx_tsemac_local *lp);
#endif
