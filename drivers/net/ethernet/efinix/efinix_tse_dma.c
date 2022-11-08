
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

#define DMASG_BYTE_PER_BURST		32

int tsemac_free_tx_chain(struct efx_tsemac_local *lp, u32 first_bd,
				 int nr_bds, bool force, u32 *sizep, int budget)
{
	struct dmasg_descriptor *cur_p;
	u32 status;
	dma_addr_t phys;
	int i;

	for (i = 0; i < nr_bds; i++) {
		cur_p = &lp->tx_bd_v[(first_bd + i) % lp->tx_bd_num];
		status = cur_p->status;

		/* If force is not specified, clean up only descriptors
		 * that have been completed by the MAC.
		 */
		if (!force && !(status & DMASG_DESCRIPTOR_STATUS_COMPLETED))
			break;

		/* Ensure we see complete descriptor update */
		dma_rmb();
		phys = desc_get_tx_phys_addr(lp, cur_p);
		dma_unmap_single(lp->dev, phys,
				 (cur_p->control & DMASG_DESCRIPTOR_CONTROL_BYTES),
				 DMA_TO_DEVICE);

		if (cur_p->skb && (status & DMASG_DESCRIPTOR_STATUS_COMPLETED))
			napi_consume_skb(cur_p->skb, budget);

		cur_p->skb = NULL;
		/* ensure our transmit path and device don't prematurely see status cleared */
		wmb();
		cur_p->control = 0;
		cur_p->status = 0;

		if (sizep)
			*sizep += status & DMASG_DESCRIPTOR_STATUS_BYTES;
	}

	return i;
}

void tsemac_dma_bd_release(struct net_device *ndev)
{
	int i;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

	/* If we end up here, tx_bd_v must have been DMA allocated. */
	dma_free_coherent(lp->dev,
			  sizeof(*lp->tx_bd_v) * lp->tx_bd_num,
			  lp->tx_bd_v,
			  lp->tx_bd_p);

	if (!lp->rx_bd_v)
		return;

	for (i = 0; i < lp->rx_bd_num; i++) {
		dma_addr_t phys;

		/* A NULL skb means this descriptor has not been initialised
		 * at all.
		 */
		if (!lp->rx_bd_v[i].skb)
			break;

		dev_kfree_skb(lp->rx_bd_v[i].skb);

		/* For each descriptor, we programmed control with the (non-zero)
		 * descriptor size, after it had been successfully allocated.
		 * So a non-zero value in there means we need to unmap it.
		 */
		if (lp->rx_bd_v[i].control) {
			phys = desc_get_rx_phys_addr(lp, &lp->rx_bd_v[i]);
			dma_unmap_single(lp->dev, phys,
					 lp->max_frm_size, DMA_FROM_DEVICE);
		}
	}

	dma_free_coherent(lp->dev,
			  sizeof(*lp->rx_bd_v) * lp->rx_bd_num,
			  lp->rx_bd_v,
			  lp->rx_bd_p);
}

void tsemac_dma_stop(struct efx_tsemac_local *lp)
{
	int count;
	u32 cr, sr;

	cr = tsemac_dma_in32(lp, DMA_CH_STATUS, DMASG_RX_BASE);
	cr &= ~DMA_CH_STATUS_STOP;
	tsemac_dma_out32(lp, DMA_CH_STATUS, DMASG_RX_BASE, cr);
	tsemac_dma_out32(lp, DMA_CH_INTERRUPT_ENABLE, DMASG_RX_BASE, 0);
	synchronize_irq(lp->rx_irq);

	cr = tsemac_dma_in32(lp, DMA_CH_STATUS, DMASG_TX_BASE);
	cr &= ~DMA_CH_STATUS_STOP;
	tsemac_dma_out32(lp, DMA_CH_STATUS, DMASG_TX_BASE, cr);
	synchronize_irq(lp->tx_irq);

	sr = tsemac_dma_in32(lp, DMA_CH_STATUS, DMASG_RX_BASE);
	for (count = 0; (sr & DMA_CH_STATUS_BUSY) && count < 5; ++count) {
		msleep(20);
		sr = tsemac_dma_in32(lp, DMA_CH_STATUS, DMASG_RX_BASE);
	}

	sr = tsemac_dma_in32(lp, DMA_CH_STATUS, DMASG_TX_BASE);
	for (count = 0; (sr & DMA_CH_STATUS_BUSY) && count < 5; ++count) {
		msleep(20);
		sr = tsemac_dma_in32(lp, DMA_CH_STATUS, DMASG_TX_BASE);
	}

	/* Do a reset to ensure DMA is really stopped */
	tsemac_lock_mii(lp);
	__tsemac_device_reset(lp);
	tsemac_unlock_mii(lp);
}

void tsemac_dma_start(struct efx_tsemac_local *lp)
{
	//TODO: add AXI-Stream ID support
	//TODO: find an alternative solution for DMA interrupt coalescing

	// /* Start updating the Rx channel control register */
	// lp->rx_dma_cr = (lp->coalesce_count_rx << XAXIDMA_COALESCE_SHIFT) |
	// 		XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_ERROR_MASK;
	// /* Only set interrupt delay timer if not generating an interrupt on
	//  * the first RX packet. Otherwise leave at 0 to disable delay interrupt.
	//  */
	// if (lp->coalesce_count_rx > 1)
	// 	lp->rx_dma_cr |= (axienet_usec_to_timer(lp, lp->coalesce_usec_rx)
	// 				<< XAXIDMA_DELAY_SHIFT) |
	// 			 XAXIDMA_IRQ_DELAY_MASK;
	// tsemac_dma_out32(lp, XAXIDMA_RX_CR_OFFSET, lp->rx_dma_cr);

	// /* Start updating the Tx channel control register */
	// lp->tx_dma_cr = (lp->coalesce_count_tx << XAXIDMA_COALESCE_SHIFT) |
	// 		XAXIDMA_IRQ_IOC_MASK | XAXIDMA_IRQ_ERROR_MASK;
	// /* Only set interrupt delay timer if not generating an interrupt on
	//  * the first TX packet. Otherwise leave at 0 to disable delay interrupt.
	//  */
	// if (lp->coalesce_count_tx > 1)
	// 	lp->tx_dma_cr |= (axienet_usec_to_timer(lp, lp->coalesce_usec_tx)
	// 				<< XAXIDMA_DELAY_SHIFT) |
	// 			 XAXIDMA_IRQ_DELAY_MASK;
	// tsemac_dma_out32(lp, XAXIDMA_TX_CR_OFFSET, lp->tx_dma_cr);

	//TODO: setup irq, descrpitor address
	tsemac_dma_out32(lp, DMA_CH_INPUT_CONFIG, DMASG_RX_BASE, 
				DMA_CH_INPUT_CONFIG_COMPLETION_ON_PACKET | 
					DMA_CH_INPUT_CONFIG_WAIT_ON_PACKET);
	tsemac_dma_out32(lp, DMA_CH_OUTPUT_CONFIG, DMASG_RX_BASE, 
				DMA_CH_OUTPUT_CONFIG_MEMORY | 
				((DMASG_BYTE_PER_BURST-1) & DMA_CH_BYTE_PER_BURST_MASK)); 
	tsemac_dma_out32(lp, DMA_CH_LINKED_LIST_HEAD, DMASG_RX_BASE, lower_32_bits(lp->rx_bd_p));
	lp->rx_dma_cr = DMA_CH_INTERRUPT_DESCRIPTOR_COMPLETION_MASK;
	tsemac_dma_out32(lp, DMA_CH_INTERRUPT_ENABLE, DMASG_RX_BASE, lp->rx_dma_cr);
	tsemac_dma_out32(lp, DMA_CH_STATUS, DMASG_RX_BASE, DMA_CH_STATUS_LINKED_LIST_START);

	tsemac_dma_out32(lp, DMA_CH_INPUT_CONFIG, DMASG_TX_BASE, 
					DMA_CH_INPUT_CONFIG_MEMORY |
					((DMASG_BYTE_PER_BURST-1) & DMA_CH_BYTE_PER_BURST_MASK)); 
	/* nothing to set. Make sure BIT_12 is zero */
	tsemac_dma_out32(lp, DMA_CH_OUTPUT_CONFIG, DMASG_TX_BASE, 0);
	tsemac_dma_out32(lp, DMA_CH_LINKED_LIST_HEAD, DMASG_TX_BASE, lower_32_bits(lp->tx_bd_p));
	lp->tx_dma_cr = DMA_CH_INTERRUPT_DESCRIPTOR_COMPLETION_MASK;
	tsemac_dma_out32(lp, DMA_CH_INTERRUPT_ENABLE, DMASG_TX_BASE, lp->tx_dma_cr);
	tsemac_dma_out32(lp, DMA_CH_STATUS, DMASG_TX_BASE, lp->tx_dma_cr);
}

int tsemac_dma_bd_init(struct net_device *ndev)
{
	int i;
	struct sk_buff *skb;
	struct efx_tsemac_local *lp = netdev_priv(ndev);
	//TODO: set channel config. S2MM or MM2S?

	/* Reset the indexes which are used for accessing the BDs */
	lp->tx_bd_ci = 0;
	lp->tx_bd_tail = 0;
	lp->rx_bd_ci = 0;

	/* Allocate the Tx and Rx buffer descriptors. */
	lp->tx_bd_v = dma_alloc_coherent(lp->dev,
					 sizeof(*lp->tx_bd_v) * lp->tx_bd_num,
					 &lp->tx_bd_p, GFP_KERNEL);
	if (!lp->tx_bd_v)
		return -ENOMEM;

	lp->rx_bd_v = dma_alloc_coherent(lp->dev,
					 sizeof(*lp->rx_bd_v) * lp->rx_bd_num,
					 &lp->rx_bd_p, GFP_KERNEL);
	if (!lp->rx_bd_v)
		goto out;

	for (i = 0; i < lp->tx_bd_num; i++) {
		dma_addr_t next_addr = lp->tx_bd_p + sizeof(*lp->tx_bd_v) *
					((i + 1) % lp->tx_bd_num);
		/* next address of the last descriptor is the first descriptor */
		lp->tx_bd_v[i].next = lower_32_bits(next_addr);
	}

	for (i = 0; i < lp->rx_bd_num; i++) {
		dma_addr_t addr = lp->rx_bd_p + sizeof(*lp->rx_bd_v) *
			((i + 1) % lp->rx_bd_num);
		lp->rx_bd_v[i].next = lower_32_bits(addr);

		skb = netdev_alloc_skb_ip_align(ndev, lp->max_frm_size);
		if (!skb)
			goto out;

		lp->rx_bd_v[i].skb = skb;
		addr = dma_map_single(lp->dev, skb->data,
				      lp->max_frm_size, DMA_FROM_DEVICE);
		if (dma_mapping_error(lp->dev, addr)) {
			netdev_err(ndev, "DMA mapping error\n");
			goto out;
		}
		desc_set_rx_phys_addr(lp, addr, &lp->rx_bd_v[i]);

		lp->rx_bd_v[i].control = lp->max_frm_size | DMASG_DESCRIPTOR_CONTROL_BYTES;
	}

	tsemac_dma_start(lp);

	return 0;
out:
	tsemac_dma_bd_release(ndev);
	return -ENOMEM;
}