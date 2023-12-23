/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef __LINUX_BLUETOOTH_POWER_H
#define __LINUX_BLUETOOTH_POWER_H

#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/soc/qcom/qcom_aoss.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>

/*
 * voltage regulator information required for configuring the
 * bluetooth chipset
 */

enum power_modes {
	POWER_DISABLE = 0,
	POWER_ENABLE,
	POWER_RETENTION,
	POWER_DISABLE_RETENTION,
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

enum retention_states {
	/* Default state */
	RETENTION_IDLE = 0,
	/* When BT is only client and it is in retention_state */
	BT_IN_RETENTION,
	/* BT is retention mode and UWB powered ON triggered */
	BT_OUT_OF_RETENTION,
	/* When UWB is only client and it is in retention_state */
	UWB_IN_RETENTION,
	/* UWB is retention mode and BT powered ON triggered */
	UWB_OUT_OF_RETENTION,
	/* Both clients are voted for retention */
	BOTH_CLIENTS_IN_RETENTION,
};

enum grant_return_values {
	ACCESS_GRANTED = 0,
	ACCESS_DENIED  = 1,
	ACCESS_RELEASED = 2,
	ACCESS_DISALLOWED = -1,
};

enum grant_states {
	/* Default state */
	NO_GRANT_FOR_ANY_SS = 0,
	NO_OTHER_CLIENT_WAITING_FOR_GRANT,
	BT_HAS_GRANT,
	UWB_HAS_GRANT,
	BT_WAITING_FOR_GRANT,
	UWB_WAITING_FOR_GRANT,
};

static inline char *ConvertGrantRetToString(enum grant_return_values state)
{
	switch (state) {
	case ACCESS_GRANTED: {
		return "ACCESS_GRANTED";
		break;
	} case ACCESS_DENIED: {
		return "ACCESS_DENIED";
		break;
	} case ACCESS_RELEASED: {
		return "ACCESS_RELEASED";
		break;
	} case ACCESS_DISALLOWED: {
		return "ACCESS_DISALLOWED";
		break;
	} default: {
		return "INVALID State";
		break;
	}	
	}	     
}

static inline char *ConvertGrantToString(enum grant_states state) 
{
	switch (state) {
	case NO_GRANT_FOR_ANY_SS: {
		return "NO_GRANT_FOR_ANY_SS";
		break;
	} case NO_OTHER_CLIENT_WAITING_FOR_GRANT:{
		return "NO_OTHER_CLIENT_WAITING_FOR_GRANT";
		break;
	} case BT_HAS_GRANT : {
		return "BT_HAS_GRANT";
		break;
	} case UWB_HAS_GRANT: {
		return "UWB_HAS_GRANT";
		break;
	} case BT_WAITING_FOR_GRANT : {
		return "BT_WAITING_FOR_GRANT";
		break;
	} case UWB_WAITING_FOR_GRANT: {
		return "UWB_WAITING_FOR_GRANT";
		break;
	} default: {
		return "INVALID STATE";
		break;
	}
	}
}

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

enum plt_pwr_state {
	POWER_ON_BT = 0,
	POWER_OFF_BT,
	POWER_ON_UWB,
	POWER_OFF_UWB,
	POWER_ON_BT_RETENION,
	POWER_ON_UWB_RETENION,
	BT_ACCESS_REQ,
	UWB_ACCESS_REQ,
	BT_RELEASE_ACCESS,
	UWB_RELEASE_ACCESS,
	BT_MAX_PWR_STATE,
};

enum {
	PWR_WAITING_RSP = -2,
	PWR_RSP_RECV = 0,
	PWR_FAIL_RSP_RECV = -1,
	PWR_CLIENT_KILLED,
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

struct btpower_state_machine {
	struct mutex state_machine_lock;
	enum power_states power_state;
	enum retention_states retention_mode;
	enum grant_states grant_state;
	enum grant_states grant_pending;
};

#define BTPWR_MAX_REQ         BT_MAX_PWR_STATE 
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
	struct qmp *qmp;
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
	struct btpower_state_machine btpower_state;
	enum ssr_states sub_state;
	enum ssr_states wrkq_signal_state;
	struct workqueue_struct *workq;
	struct device_node *bt_of_node;
	struct device_node *uwb_of_node;
	struct work_struct bt_wq;
	struct work_struct uwb_wq;
	wait_queue_head_t rsp_wait_q[BTPWR_MAX_REQ];
	int wait_status[BTPWR_MAX_REQ];
	struct work_struct wq_pwr_voting;
	struct sk_buff_head rxq;
	struct mutex pwr_mtx;
};

int btpower_register_slimdev(struct device *dev);
int btpower_get_chipset_version(void);
int btpower_aop_mbox_init(struct platform_pwr_data *pdata);
int bt_aop_pdc_reconfig(struct platform_pwr_data *pdata);

static char const *pwr_req[] = {"POWER_ON_BT", "POWER_OFF_BT",
				"POWER_ON_UWB", "POWER_OFF_UWB",
				"POWER_ON_BT_RETENION",
				"POWER_ON_UWB_RETENION",
				"BT_ACCESS_REQ", "UWB_ACCESS_REQ",
				"BT_RELEASE_ACCESS", "UWB_RELEASE_ACCESS"};

#define WLAN_SW_CTRL_GPIO       "qcom,wlan-sw-ctrl-gpio"
#define BT_CMD_SLIM_TEST            0xbfac
#define BT_CMD_PWR_CTRL             0xbfad
#define BT_CMD_CHIPSET_VERS         0xbfae
#define BT_CMD_GET_CHIPSET_ID       0xbfaf
#define BT_CMD_CHECK_SW_CTRL        0xbfb0
#define BT_CMD_GETVAL_POWER_SRCS    0xbfb1
#define BT_CMD_SET_IPA_TCS_INFO     0xbfc0
#define BT_CMD_KERNEL_PANIC         0xbfc1
#define UWB_CMD_KERNEL_PANIC        0xbfc2
#define UWB_CMD_PWR_CTRL            0xbfe1
#define BT_CMD_REGISTRATION	    0xbfe2
#define UWB_CMD_REGISTRATION        0xbfe3
#define BT_CMD_ACCESS_CTRL	    0xbfe4
#define UWB_CMD_ACCESS_CTRL        0xbfe5

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
static const char * const bt_arg[] = {"power off BT", "power on BT",
				      "BT power retention"};
static const char * const uwb_arg[]= {"power off UWB", "power on UWB",
				       "UWB power retention"};
static const char * const pwr_states[] = {"Both Sub-System powered OFF", "BT powered ON",
					  "UWB powered ON",
					  "Both Sub-System powered ON"};
static const char * const ssr_state[ ] = {"No SSR on Sub-Sytem", "SSR on BT",
					  "SSR Completed on BT", "SSR on UWB",
					  "SSR Completed on UWB"};
static const char * const reg_mode[ ] = {"vote off", "vote on", "vote for retention", "vote off retention"};
static const char * const retention_mode[] = {"IDLE", "BT_IN_RETENTION", "BT_OUT_OF_RETENTION",
					      "UWB_IN_RETENTION", "UWB_OUT_OF_RETENTION",
					      "BOTH_CLIENT_IN_RETENTION"};
#endif /* __LINUX_BLUETOOTH_POWER_H */
