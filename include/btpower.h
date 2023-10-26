/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __LINUX_BLUETOOTH_POWER_H
#define __LINUX_BLUETOOTH_POWER_H

#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox/qmp.h>
#include <linux/workqueue.h>

/*
 * voltage regulator information required for configuring the
 * bluetooth chipset
 */

enum power_modes {
	POWER_DISABLE = 0,
	POWER_ENABLE,
	POWER_RETENTION
};

enum SubSystem {
	BLUETOOTH = 1,
	UWB,
};

enum power_states {
	IDLE = 0,
	BT_ON,
	UWB_ON,
	ALL_CLIENTS_ON,
};

enum cores {
	BT_CORE = 0,
	UWB_CORE,
	PLATFORM_CORE
};

enum ssr_states {
	SUB_STATE_IDLE = 0,
	SSR_ON_BT,
	BT_SSR_COMPLETED,
	SSR_ON_UWB,
	UWB_SSR_COMPLETED,
	REG_BT_PID,
	REG_UWB_PID,
};

struct log_index {
	int init;
	int crash;
};

struct vreg_data {
	struct regulator *reg;  /* voltage regulator handle */
	const char *name;       /* regulator name */
	u32 min_vol;            /* min voltage level */
	u32 max_vol;            /* max voltage level */
	u32 load_curr;          /* current */
	bool is_enabled;        /* is this regulator enabled? */
	bool is_retention_supp; /* does this regulator support retention mode */
	struct log_index indx;  /* Index for reg. w.r.t init & crash */
};

struct pwr_data {
	char compatible[32];
	struct vreg_data *bt_vregs;
	int bt_num_vregs;
	struct vreg_data *uwb_vregs;
	int uwb_num_vregs;
	struct vreg_data *platform_vregs;
	int platform_num_vregs;
};

struct bt_power_clk_data {
	struct clk *clk;  /* clock regulator handle */
	const char *name; /* clock name */
	bool is_enabled;  /* is this clock enabled? */
};

/*
 * Platform data for the bluetooth power driver.
 */
struct platform_pwr_data {
	struct platform_device *pdev;
	int bt_gpio_sys_rst;                   /* Bluetooth reset gpio */
	int wl_gpio_sys_rst;                   /* Wlan reset gpio */
	int bt_gpio_sw_ctrl;                   /* Bluetooth sw_ctrl gpio */
	int bt_gpio_debug;                     /* Bluetooth debug gpio */
	unsigned int wlan_sw_ctrl_gpio;        /* Wlan switch control gpio*/
#ifdef CONFIG_MSM_BT_OOBS
	int bt_gpio_dev_wake;                  /* Bluetooth bt_wake */
	int bt_gpio_host_wake;                 /* Bluetooth bt_host_wake */
	int irq;                               /* Bluetooth host_wake IRQ */
#endif
	int sw_cntrl_gpio;
	int xo_gpio_clk;                       /* XO clock gpio*/
	struct device *slim_dev;
	struct vreg_data *bt_vregs;
	struct vreg_data *uwb_vregs;
	struct vreg_data *platform_vregs;
	struct bt_power_clk_data *bt_chip_clk; /* bluetooth reference clock */
	int (*power_setup)(int core, int id); /* Bluetooth power setup function */
	char compatible[32]; /*Bluetooth SoC name */
	int bt_num_vregs;
	int uwb_num_vregs;
	int platform_num_vregs;
	struct mbox_client mbox_client_data;
	struct mbox_chan *mbox_chan;
	const char *vreg_ipa;
	bool is_ganges_dt;
	int pdc_init_table_len;
	const char **pdc_init_table;
	int bt_device_type;
	bool sec_peri_feature_disable;
	int bt_sec_hw_disable;
#ifdef CONFIG_MSM_BT_OOBS
	struct file *reffilp_obs;
	struct task_struct *reftask_obs;
#endif
	struct task_struct *reftask;
	struct task_struct *reftask_bt;
	struct task_struct *reftask_uwb;
	enum power_states power_state;
	enum ssr_states sub_state;
	enum ssr_states wrkq_signal_state;
	struct workqueue_struct *workq;
	struct work_struct bt_wq;
	struct work_struct uwb_wq;
	struct device_node *bt_of_node;
	struct device_node *uwb_of_node;
};

int btpower_register_slimdev(struct device *dev);
int btpower_get_chipset_version(void);
int btpower_aop_mbox_init(struct platform_pwr_data *pdata);
int bt_aop_pdc_reconfig(struct platform_pwr_data *pdata);

#define WLAN_SW_CTRL_GPIO       "qcom,wlan-sw-ctrl-gpio"
#define BT_CMD_SLIM_TEST            0xbfac
#define BT_CMD_PWR_CTRL             0xbfad
#define BT_CMD_CHIPSET_VERS         0xbfae
#define BT_CMD_GET_CHIPSET_ID       0xbfaf
#define BT_CMD_CHECK_SW_CTRL        0xbfb0
#define BT_CMD_GETVAL_POWER_SRCS    0xbfb1
#define BT_CMD_SET_IPA_TCS_INFO     0xbfc0
#define BT_CMD_KERNEL_PANIC         0xbfc1
#define UWB_CMD_PWR_CTRL            0xbfe1
#define BT_CMD_REGISTRATION	    0xbfe2
#define UWB_CMD_REGISTRATION        0xbfe3

#ifdef CONFIG_MSM_BT_OOBS
#define BT_CMD_OBS_VOTE_CLOCK		0xbfd1
/**
 * enum btpower_obs_param: OOBS low power param
 * @BTPOWER_OBS_CLK_OFF: Transport bus is no longer acquired
 * @BTPOWER_OBS_CLK_ON: Acquire transport bus for either transmitting or receiving
 * @BTPOWER_OBS_DEV_OFF: Bluetooth is released because of no more transmission
 * @BTPOWER_OBS_DEV_ON: Wake up the Bluetooth controller for transmission
 */
enum btpower_obs_param {
	BTPOWER_OBS_CLK_OFF = 0,
	BTPOWER_OBS_CLK_ON,
	BTPOWER_OBS_DEV_OFF,
	BTPOWER_OBS_DEV_ON,
};
#endif

#endif /* __LINUX_BLUETOOTH_POWER_H */
