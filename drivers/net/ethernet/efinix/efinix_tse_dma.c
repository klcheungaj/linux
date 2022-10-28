
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

static inline u32 tsemac_dma_in32(struct efx_tsemac_local *lp, off_t reg)
{

}

static inline void tsemac_dma_out32(struct efx_tsemac_local *lp, off_t reg, u32 value)
{

}

static int tsemac_free_tx_chain(struct efx_tsemac_local *lp, u32 first_bd,
				 int nr_bds, bool force, u32 *sizep, int budget)
{
	//TODO:
}

static void tsemac_dma_bd_release(struct net_device *ndev)
{
	//TODO: 
}

static int tsemac_dma_bd_init(struct net_device *ndev)
{
	int i;
	struct sk_buff *skb;
	struct efx_tsemac_local *lp = netdev_priv(ndev);

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
		dma_addr_t addr = lp->tx_bd_p +
				  sizeof(*lp->tx_bd_v) *
				  ((i + 1) % lp->tx_bd_num);

		lp->tx_bd_v[i].next = lower_32_bits(addr);
	}

	for (i = 0; i < lp->rx_bd_num; i++) {
		dma_addr_t addr;

		addr = lp->rx_bd_p + sizeof(*lp->rx_bd_v) *
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
		desc_set_phys_addr(lp, addr, &lp->rx_bd_v[i]);

		lp->rx_bd_v[i].control = lp->max_frm_size;	//TODO: add bit mask
	}

	axienet_dma_start(lp);

	return 0;
out:
	axienet_dma_bd_release(ndev);
	return -ENOMEM;
}