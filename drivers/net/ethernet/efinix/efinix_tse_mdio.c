// SPDX-License-Identifier: GPL-2.0
/*
 * MDIO bus driver for the Xilinx Axi Ethernet device
 *
 * Copyright (c) 2009 Secret Lab Technologies, Ltd.
 * Copyright (c) 2010 - 2011 Michal Simek <monstr@monstr.eu>
 * Copyright (c) 2010 - 2011 PetaLogix
 * Copyright (c) 2019 SED Systems, a division of Calian Ltd.
 * Copyright (c) 2010 - 2012 Xilinx, Inc. All rights reserved.
 */

#include <linux/clk.h>
#include <linux/of_address.h>
#include <linux/of_mdio.h>
#include <linux/jiffies.h>
#include <linux/iopoll.h>

#include "efinix_tse.h"

#define MAX_MDIO_FREQ		2500000 /* 2.5 MHz */
#define DEFAULT_HOST_CLOCK	100000000 /* 100 MHz */


#define	MDIO_REG_DIVIDER_PRE            0x0100
#define	MDIO_REG_RD_WR_EN               0x0104
#define	MDIO_REG_REG_PHY_ADDR           0x0108
#define	MDIO_REG_WR_DATA                0x010C
#define	MDIO_REG_RD_DATA                0x0110
#define	MDIO_REG_STATUS                 0x0114

#define MDIO_DIVIDER_MASK               0x000000FF
#define MDIO_NOPRE                      BIT_8
#define MDIO_RD_EN                      BIT_0
#define MDIO_WR_EN                      BIT_1
#define MDIO_REG_ADDR_BASE              1U
#define MDIO_REG_ADDR_MASK              0x0000001F
#define MDIO_PHY_ADDR_BASE              8U
#define MDIO_PHY_ADDR_MASK              0x00001F00
#define MDIO_WRITE_DATA_MASK            0x0000FFFF
#define MDIO_READ_DATA_MASK             0x0000FFFF
#define MDIO_STATUS_LINK_FAIL           BIT_0
#define MDIO_STATUS_BUSY                BIT_1
#define MDIO_STATUS_INVALID             BIT_2

static inline u32 tsemac_in32_mdio_status(struct efx_tsemac_local *lp)
{
	return tsemac_in32(lp, MDIO_REG_STATUS);
}

static int tsemac_mdio_wait_until_ready(struct efx_tsemac_local *lp)
{
	u32 val;

	return readx_poll_timeout(tsemac_in32_mdio_status, lp,
				  val, !(val & (MDIO_STATUS_LINK_FAIL | MDIO_STATUS_BUSY)),
				  1, 20000);
}

static int tsemac_mdio_read(struct mii_bus *bus, int phy_id, int reg)
{
	u32 rc;
	int ret;
	struct efx_tsemac_local *lp = bus->priv;

	ret = tsemac_mdio_wait_until_ready(lp);
	if (ret < 0) {
		return ret;
	}

    tsemac_out32(lp, MDIO_REG_REG_PHY_ADDR, ((reg << MDIO_REG_ADDR_BASE) & MDIO_REG_ADDR_MASK) | 
            ((phy_id << MDIO_PHY_ADDR_BASE) & MDIO_PHY_ADDR_MASK));
    tsemac_out32(lp, MDIO_REG_RD_WR_EN, MDIO_RD_EN);

	ret = tsemac_mdio_wait_until_ready(lp);
	if (ret < 0) {
		return ret;
	}

	rc = tsemac_in32(lp, MDIO_REG_RD_DATA) & MDIO_READ_DATA_MASK;

	dev_dbg(lp->dev, "tsemac_mdio_read(phy_id=%i, reg=%x) == %x\n",
		phy_id, reg, rc);

	return rc;
}

static int tsemac_mdio_write(struct mii_bus *bus, int phy_id, int reg,
			      u16 val)
{
    //TODO:
	int ret;
	struct efx_tsemac_local *lp = bus->priv;

	dev_dbg(lp->dev, "tsemac_mdio_write(phy_id=%i, reg=%x, val=%x)\n",
		phy_id, reg, val);

	ret = tsemac_mdio_wait_until_ready(lp);
	if (ret < 0) {
		return ret;
	}

    tsemac_out32(lp, MDIO_REG_REG_PHY_ADDR, ((reg << MDIO_REG_ADDR_BASE) & MDIO_REG_ADDR_MASK) | 
            ((phy_id << MDIO_PHY_ADDR_BASE) & MDIO_PHY_ADDR_MASK));
    tsemac_out32(lp, MDIO_REG_WR_DATA, val & MDIO_WRITE_DATA_MASK);
    tsemac_out32(lp, MDIO_REG_RD_WR_EN, MDIO_WR_EN);

	ret = tsemac_mdio_wait_until_ready(lp);
	if (ret < 0) {
		return ret;
	}
	return 0;
}

int tsemac_mdio_enable(struct efx_tsemac_local *lp)
{
    //TODO:
	u32 host_clock;

	lp->mii_clk_div = 0;

	if (lp->axi_clk) {
		host_clock = clk_get_rate(lp->axi_clk);
	} else {
		struct device_node *np1;

		/* Legacy fallback: detect CPU clock frequency and use as AXI
		 * bus clock frequency. This only works on certain platforms.
		 */
		np1 = of_find_node_by_name(NULL, "cpu");
		if (!np1) {
			netdev_warn(lp->ndev, "Could not find CPU device node.\n");
			host_clock = DEFAULT_HOST_CLOCK;
		} else {
			int ret = of_property_read_u32(np1, "clock-frequency",
						       &host_clock);
			if (ret) {
				netdev_warn(lp->ndev, "CPU clock-frequency property not found.\n");
				host_clock = DEFAULT_HOST_CLOCK;
			}
			of_node_put(np1);
		}
		netdev_info(lp->ndev, "Setting assumed host clock to %u\n",
			    host_clock);
	}

	lp->mii_clk_div = (host_clock / (MAX_MDIO_FREQ * 2)) - 1;

	if (host_clock % (MAX_MDIO_FREQ * 2))
		lp->mii_clk_div++;

	netdev_dbg(lp->ndev,
		   "Setting MDIO clock divisor to %u/%u Hz host clock.\n",
		   lp->mii_clk_div, host_clock);

	tsemac_out32(lp, MDIO_REG_DIVIDER_PRE, lp->mii_clk_div | MDIO_DIVIDER_MASK);

	return tsemac_mdio_wait_until_ready(lp);
}

int tsemac_mdio_setup(struct efx_tsemac_local *lp)
{
    //TODO:
	struct device_node *mdio_node;
	struct mii_bus *bus;
	int ret;

	ret = tsemac_mdio_enable(lp);
	if (ret < 0)
		return ret;

	bus = mdiobus_alloc();
	if (!bus)
		return -ENOMEM;

	snprintf(bus->id, MII_BUS_ID_SIZE, "tsemac-%.8llx",
		 (unsigned long long)lp->regs_start);

	bus->priv = lp;
	bus->name = "Efinix TSEMAC MDIO";
	bus->read = tsemac_mdio_read;
	bus->write = tsemac_mdio_write;
	bus->parent = lp->dev;
	lp->mii_bus = bus;

	mdio_node = of_get_child_by_name(lp->dev->of_node, "mdio");
	ret = of_mdiobus_register(bus, mdio_node);
	of_node_put(mdio_node);
	if (ret) {
		mdiobus_free(bus);
		lp->mii_bus = NULL;
		return ret;
	}
	return 0;
}

void tsemac_mdio_teardown(struct efx_tsemac_local *lp)
{
	mdiobus_unregister(lp->mii_bus);
	mdiobus_free(lp->mii_bus);
	lp->mii_bus = NULL;
}
