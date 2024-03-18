// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/regulator/consumer.h>
#include <linux/qti-regmap-debugfs.h>
#include <sound/core.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <soc/soundwire.h>
#include <sound/soc.h>
#include <sound/soc-dapm.h>
#include "qmp-dmic.h"

#define QMP_MAX_REGISTER 0x40900070
#define MCLK_12P288MHZ 12288000
#define MCLK_9P6MHZ 9600000

enum {
	QMP_SDCA_NORMAL_PORT,
	QMP_SDCA_LP_PORT,
	QMP_SDCA_DMIC_MAX_PORTS,
};

enum fu1_usage_modes {
	FU1_NORMAL_DIV_4 = 1,
	FU1_NORMAL_DIV_3 = 2,
	FU1_NORMAL_DIV_2 = 3,
	FU1_HDR_DIV_4 = 8,
	FU1_HDR_DIV_3 = 9,
	FU1_HDR_DIV_2 = 10,
	FU1_SNR_DIV_6 = 16,
	FU1_SNR_DIV_8 = 17,
	FU1_SNR_DIV_4 = 18,
	FU1_SNR_DIV_3 = 19,
	FU1_SNR_DIV_2 = 20,
	FU1_AOP_DIV_4 = 24,
	FU1_AOP_DIV_3 = 25,
	FU1_AOP_DIV_2 = 26,
	FU1_LP_DIV_16 = 32,
};

enum fu2_usage_modes {
	FU2_LP_DIV_16 = 1,
};

static int qmp_master_channel_map[] = {
	ZERO,
	SWRM_TX_PCM_OUT,
	SWRM_TX1_CH1,
	SWRM_TX1_CH2,
	SWRM_TX1_CH3,
	SWRM_TX1_CH4,
	SWRM_TX2_CH1,
	SWRM_TX2_CH2,
	SWRM_TX2_CH3,
	SWRM_TX2_CH4,
	SWRM_TX3_CH1,
	SWRM_TX3_CH2,
	SWRM_TX3_CH3,
	SWRM_TX3_CH4,
	SWRM_TX_PCM_IN,
};

struct qmp_sdca_dmic_priv {
	struct regmap *regmap;
	struct device *dev;
	struct swr_device *swr_slave;
	struct snd_soc_component *component;
	const struct snd_soc_component_driver *driver;
	struct snd_soc_dai_driver *dai_driver;
	struct regulator *slave_vdd;
	u8 tx_master_port_map[QMP_SDCA_DMIC_MAX_PORTS];
	struct swr_port_params tx_port_params[SWR_UC_MAX][QMP_SDCA_DMIC_MAX_PORTS];
	struct swr_dev_frame_config swr_tx_port_params[SWR_UC_MAX];
	int fu1_usage_mode;
	int fu2_usage_mode;
	unsigned long fu1_channel_rate;
	unsigned long fu2_channel_rate;
	unsigned long clk_freq;
	int dai_status_mask;
//	struct notifier_block nblock;
};

static const char * const codec_name_list[] = {
	"qmp-dmic.01",
	"qmp-dmic.02",
	"qmp-dmic.03",
	"qmp-dmic.04",
	"qmp-dmic.05",
	"qmp-dmic.06",
	"qmp-dmic.07",
	"qmp-dmic.08",
};

static const char * const dai_name_list[] = {
	"qmp_dmic_normal_tx1",
	"qmp_dmic_lp_tx1",
	"qmp_dmic_normal_tx2",
	"qmp_dmic_lp_tx2",
	"qmp_dmic_normal_tx3",
	"qmp_dmic_lp_tx3",
	"qmp_dmic_normal_tx4",
	"qmp_dmic_lp_tx4",
	"qmp_dmic_normal_tx5",
	"qmp_dmic_lp_tx5",
	"qmp_dmic_normal_tx6",
	"qmp_dmic_lp_tx6",
	"qmp_dmic_normal_tx7",
	"qmp_dmic_lp_tx7",
	"qmp_dmic_normal_tx8",
	"qmp_dmic_lp_tx8",
};

static const char *const aif_name_list[] = {
	"QMP_DMIC AIF1 Normal Capture",
	"QMP_DMIC AIF1 LP Capture",
	"QMP_DMIC AIF2 Normal Capture",
	"QMP_DMIC AIF2 LP Capture",
	"QMP_DMIC AIF3 Normal Capture",
	"QMP_DMIC AIF3 LP Capture",
	"QMP_DMIC AIF4 Normal Capture",
	"QMP_DMIC AIF4 LP Capture",
	"QMP_DMIC AIF5 Normal Capture",
	"QMP_DMIC AIF5 LP Capture",
	"QMP_DMIC AIF6 Normal Capture",
	"QMP_DMIC AIF6 LP Capture",
	"QMP_DMIC AIF7 Normal Capture",
	"QMP_DMIC AIF7 LP Capture",
	"QMP_DMIC AIF8 Normal Capture",
	"QMP_DMIC AIF8 LP Capture",
};

static bool qmp_sdca_dmic_readable_register(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_IT11, QMP_SDCA_CTL_IT_USAGE,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_REQ_PS,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_STAT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_ACT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_ACT_PS,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_IT11, QMP_SDCA_CTL_IT_USAGE,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_REQ_PS,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_STAT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_ACT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_SMPU, QMP_SDCA_CTL_FUNC_STAT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_SMPU, QMP_SDCA_CTL_FUNC_ACT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_ACT_PS,
			QMP_SDCA_CTL_NUM0):
		return true;
	default:
		return false;
	}
}

static bool qmp_sdca_dmic_writeable_register(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_IT11, QMP_SDCA_CTL_IT_USAGE,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_REQ_PS,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_STAT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_ACT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_IT11, QMP_SDCA_CTL_IT_USAGE,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_REQ_PS,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_STAT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_ENT0, QMP_SDCA_CTL_FUNC_ACT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_SMPU, QMP_SDCA_CTL_FUNC_STAT,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_SMPU, QMP_SDCA_CTL_FUNC_ACT,
			QMP_SDCA_CTL_NUM0):
		return true;
	default:
		return false;
	}
}

static bool qmp_sdca_dmic_volatile_register(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC1, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_ACT_PS,
			QMP_SDCA_CTL_NUM0):
	case SDW_SDCA_CTL(FUNC_NUM_SMP_MIC2, QMP_SDCA_ENT_PDE11, QMP_SDCA_CTL_PDE_ACT_PS,
			QMP_SDCA_CTL_NUM0):
		return true;
	default:
		return false;
	}
}

static const struct regmap_config qmp_sdca_dmic_regmap = {
	.reg_bits = 32,
	.val_bits = 8,
	.readable_reg = qmp_sdca_dmic_readable_register,
	.volatile_reg = qmp_sdca_dmic_volatile_register,
	.writeable_reg = qmp_sdca_dmic_writeable_register,
	.max_register = QMP_MAX_REGISTER,
	.reg_defaults = qmp_sdca_dmic_reg_defaults,
	.num_reg_defaults = ARRAY_SIZE(qmp_sdca_dmic_reg_defaults),
	.cache_type = REGCACHE_RBTREE,
	.use_single_read = true,
	.use_single_write = true,
};

static int qmp_enable_regulator(struct qmp_sdca_dmic_priv *qmp)
{
	int rc = 0;

	if (qmp->slave_vdd == NULL)
		return -EINVAL;

	rc = regulator_enable(qmp->slave_vdd);
	if (rc) {
		dev_err_ratelimited(qmp->dev, "qmp regulator enable failed %d", rc);
		return rc;
	}
	dev_err(qmp->dev, "%s: enabled qmp vdd regulator\n", __func__);
	return 0;
}

static int qmp_disable_regulator(struct qmp_sdca_dmic_priv *qmp)
{
	int rc = 0;

	if (qmp->slave_vdd == NULL)
		return -EINVAL;

	rc = regulator_disable(qmp->slave_vdd);
	if (rc) {
		dev_err_ratelimited(qmp->dev, "qmp regulator disable failed %d", rc);
		return rc;
	}
	dev_err(qmp->dev, "%s: disabled qmp vdd regulator\n", __func__);
	return 0;
}

static unsigned long qmp_get_channel_rate(struct qmp_sdca_dmic_priv *qmp,
		u8 slv_port_id)
{
	if (slv_port_id == QMP_SDCA_LP_PORT)
		return qmp->fu2_channel_rate;

	if (slv_port_id == QMP_SDCA_NORMAL_PORT)
		return qmp->fu1_channel_rate;

	return qmp->clk_freq / 4;
}

static const char *master_port_type_to_str(int port_type)
{
	switch (port_type) {
	case SWRM_TX1_CH1:
		return "SWRM_TX1_CH1";
	case SWRM_TX1_CH2:
		return "SWRM_TX1_CH2";
	case SWRM_TX1_CH3:
		return "SWRM_TX1_CH3";
	case SWRM_TX1_CH4:
		return "SWRM_TX1_CH4";
	case SWRM_TX2_CH1:
		return "SWRM_TX2_CH1";
	case SWRM_TX2_CH2:
		return "SWRM_TX2_CH2";
	case SWRM_TX2_CH3:
		return "SWRM_TX2_CH3";
	case SWRM_TX2_CH4:
		return "SWRM_TX2_CH4";
	case SWRM_TX3_CH1:
		return "SWRM_TX3_CH1";
	case SWRM_TX3_CH2:
		return "SWRM_TX3_CH2";
	case SWRM_TX3_CH3:
		return "SWRM_TX3_CH3";
	case SWRM_TX3_CH4:
		return "SWRM_TX3_CH4";
	case ZERO:
		return "ZERO";
	case SWRM_TX_PCM_OUT:
		return "TX_PCM_OUT";
	case SWRM_TX_PCM_IN:
		return "TX_PCM_IN";
	default:
		return "UNDEFINED";
	}
}

static int qmp_sdca_dmic_startup(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);
	int ret = 0;
	u8 dev_num;

	if (!qmp->swr_slave)
		return -EINVAL;

	pr_err("%s(): dai_name = %s substream = %s  stream = %d\n", __func__,
		 dai->name, substream->name, substream->stream);

	/* Enable QMP power supply */
	if (qmp_enable_regulator(qmp))
		return -EINVAL;

	/* Get logical address */
	usleep_range(5000, 5500);
	ret = swr_get_logical_dev_num(qmp->swr_slave, qmp->swr_slave->addr, &dev_num);
	if (ret) {
		dev_err(qmp->dev, "error while getting logical device number\n");
		goto err;
	}
	qmp->swr_slave->dev_num = dev_num;
	swr_init_port_params(qmp->swr_slave, QMP_SDCA_DMIC_MAX_PORTS,
			qmp->swr_tx_port_params);
	qmp->dai_status_mask |= BIT(dai->id);

err:
	return 0;
}

static int qmp_sdca_dmic_hw_params(struct snd_pcm_substream *substream,
			   struct snd_pcm_hw_params *params,
			   struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);

	if (!qmp->swr_slave)
		return -EINVAL;

	pr_err("%s(): dai_name = %s substream = %s  stream = %d\n", __func__,
		 dai->name, substream->name, substream->stream);

	return 0;
}

static int qmp_sdca_dmic_prepare(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);
	int ret = 0;
	u8 slv_port_id = dai->id;
	u8 ch_mask = 0x01; /* only DpnChannelEN1 register is available */
	u32 ch_rate;
	u8 num_ch = 1;
	u8 port_type = 0;

	if (!qmp->swr_slave)
		return -EINVAL;

	pr_err("%s(): dai name = %s substream = %s  stream = %d\n", __func__,
		 dai->name, substream->name, substream->stream);

	ch_rate = qmp_get_channel_rate(qmp, slv_port_id);
	port_type = qmp->tx_master_port_map[slv_port_id];

	dev_err(qmp->dev, "slv port id %d, master port_type: %s\n",
		(slv_port_id + 1), master_port_type_to_str(port_type));

	if (port_type == ZERO) {
		dev_err(qmp->dev, "master port map not set for dai %d, skip swr config\n",
				slv_port_id);
		goto exit;
	}

	ret = swr_connect_port(qmp->swr_slave, &slv_port_id, 1, &ch_mask, &ch_rate,
			&num_ch, &port_type);
	if (ret)
		goto exit;

	ret = swr_slvdev_datapath_control(qmp->swr_slave, qmp->swr_slave->dev_num, true);
exit:
	return ret;
}

static void qmp_sdca_dmic_shutdown(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);

	if (!qmp->swr_slave)
		return;

	pr_err("%s(): dai_name = %s substream = %s  stream = %d\n", __func__,
		 dai->name, substream->name, substream->stream);

	/* Disable QMP power supply */
	qmp_disable_regulator(qmp);
	qmp->dai_status_mask &= ~BIT(dai->id);
	if (!qmp->dai_status_mask) {
		qmp->swr_slave->dev_num = 0; /* Both dais are disabled */
		dev_err(component->dev, "Set dev_num to 0\n");
	}
}

static int qmp_sdca_dmic_hw_free(struct snd_pcm_substream *substream,
		struct snd_soc_dai *dai)
{
	struct snd_soc_component *component = dai->component;
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);

	if (!qmp->swr_slave)
		return -EINVAL;

	pr_err("%s(): dai_name = %s substream = %s  stream = %d\n", __func__,
		 dai->name, substream->name, substream->stream);

	return 0;
}

static const struct snd_soc_dai_ops qmp_sdca_dmic_dai_ops = {
	.startup = qmp_sdca_dmic_startup,
	.hw_params = qmp_sdca_dmic_hw_params,
	.prepare = qmp_sdca_dmic_prepare,
	.shutdown = qmp_sdca_dmic_shutdown,
	.hw_free = qmp_sdca_dmic_hw_free,
};

static struct snd_soc_dai_driver qmp_dmic_dai[] = {
	{
		.name = "",
		.id = QMP_SDCA_NORMAL_PORT,
		.capture = {
			.stream_name = "",
			.rates = (SNDRV_PCM_RATE_8000 | SNDRV_PCM_RATE_16000 |
				SNDRV_PCM_RATE_32000 | SNDRV_PCM_RATE_48000 |
				SNDRV_PCM_RATE_96000 | SNDRV_PCM_RATE_192000),
			.formats = (SNDRV_PCM_FMTBIT_S16_LE |
				SNDRV_PCM_FMTBIT_S24_LE |
				SNDRV_PCM_FMTBIT_S32_LE),
			.rate_max = 192000,
			.rate_min = 8000,
			.channels_min = 1,
			.channels_max = 2,
		},
		.ops = &qmp_sdca_dmic_dai_ops,
	},
	{
		.name = "",
		.id = QMP_SDCA_LP_PORT,
		.capture = {
			.stream_name = "",
			.rates = (SNDRV_PCM_RATE_8000 | SNDRV_PCM_RATE_16000 |
				SNDRV_PCM_RATE_32000 | SNDRV_PCM_RATE_48000 |
				SNDRV_PCM_RATE_96000 | SNDRV_PCM_RATE_192000),
			.formats = (SNDRV_PCM_FMTBIT_S16_LE |
				SNDRV_PCM_FMTBIT_S24_LE |
				SNDRV_PCM_FMTBIT_S32_LE),
			.rate_max = 192000,
			.rate_min = 8000,
			.channels_min = 1,
			.channels_max = 2,
		},
		.ops = &qmp_sdca_dmic_dai_ops,
	},
};

static struct snd_soc_dai_driver *get_dai_driver(struct device *dev, int dev_index)
{
	struct snd_soc_dai_driver *dai_drv = NULL;

	dai_drv = devm_kzalloc(dev,
			ARRAY_SIZE(qmp_dmic_dai) * sizeof(struct snd_soc_dai_driver),
					GFP_KERNEL);
	if (!dai_drv)
		return NULL;

	memcpy(dai_drv, qmp_dmic_dai,
			ARRAY_SIZE(qmp_dmic_dai) * sizeof(struct snd_soc_dai_driver));

	dai_drv[0].name = dai_name_list[2 * dev_index];
	dai_drv[1].name = dai_name_list[2 * dev_index + 1];
	dai_drv[0].capture.stream_name = aif_name_list[2 * dev_index];
	dai_drv[1].capture.stream_name = aif_name_list[2 * dev_index + 1];

	return dai_drv;
}

/* For SDCA control Usage Mode */
static int qmp_fu2_usage_modes_get(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);

	ucontrol->value.enumerated.item[0] = qmp->fu2_usage_mode;

	return 0;
}

static int qmp_fu2_usage_modes_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);

	qmp->fu2_usage_mode = ucontrol->value.enumerated.item[0];
	switch (qmp->fu2_usage_mode) {
	case FU2_LP_DIV_16:
		qmp->fu2_channel_rate = qmp->clk_freq / 16;
		break;
	default:
		qmp->fu2_channel_rate = qmp->clk_freq / 16;
		break;
	}
	dev_dbg(component->dev, "function2 usage %d channel rate %lu",
		qmp->fu2_usage_mode, qmp->fu2_channel_rate);

	return 0;
}

/* For SDCA control Usage Mode */
static int qmp_fu1_usage_modes_get(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);

	ucontrol->value.enumerated.item[0] = qmp->fu1_usage_mode;

	return 0;
}

static int qmp_fu1_usage_modes_put(struct snd_kcontrol *kcontrol,
	struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);

	qmp->fu1_usage_mode = ucontrol->value.enumerated.item[0];

	switch (qmp->fu1_usage_mode) {
	case FU1_NORMAL_DIV_4:
	case FU1_HDR_DIV_4:
	case FU1_SNR_DIV_4:
	case FU1_AOP_DIV_4:
		qmp->fu1_channel_rate = qmp->clk_freq / 4;
		break;
	case FU1_NORMAL_DIV_3:
	case FU1_HDR_DIV_3:
	case FU1_SNR_DIV_3:
	case FU1_AOP_DIV_3:
		qmp->fu1_channel_rate = qmp->clk_freq / 3;
		break;
	case FU1_NORMAL_DIV_2:
	case FU1_HDR_DIV_2:
	case FU1_SNR_DIV_2:
	case FU1_AOP_DIV_2:
		qmp->fu1_channel_rate = qmp->clk_freq / 2;
		break;
	case FU1_SNR_DIV_6:
		if (qmp->clk_freq == MCLK_12P288MHZ) {
			dev_info(component->dev, "div6 unsupported for MCLK 12.288MHz, setting to div4\n");
			qmp->fu1_channel_rate = qmp->clk_freq / 4;
		} else {
			qmp->fu1_channel_rate = qmp->clk_freq / 6;
		}
		break;
	case FU1_SNR_DIV_8:
		if (qmp->clk_freq == MCLK_9P6MHZ) {
			dev_info(component->dev, "div8 unsupported for MCLK 9.288MHz, setting to div4\n");
			qmp->fu1_channel_rate = qmp->clk_freq / 4;
		} else {
			qmp->fu1_channel_rate = qmp->clk_freq / 8;
		}
		break;
	case FU1_LP_DIV_16:
		qmp->fu1_channel_rate = qmp->clk_freq / 16;
		break;
	default:
		qmp->fu1_channel_rate = qmp->clk_freq / 4;
		break;
	}
	dev_dbg(component->dev, "function1 usage %d channel rate %lu",
		qmp->fu1_usage_mode, qmp->fu1_channel_rate);

	return 0;
}

static inline int qmp_dmic_get_master_port_val(int mport_idx)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(qmp_master_channel_map); ++i)
		if (mport_idx == qmp_master_channel_map[i])
			return i;

	return 0;
}

static int qmp_dmic_tx_master_port_get(struct snd_kcontrol *kcontrol,
							struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);
	u8 slv_port_id = QMP_SDCA_NORMAL_PORT;

	if (strnstr(kcontrol->id.name, "Normal", sizeof("Normal")))
		slv_port_id = QMP_SDCA_NORMAL_PORT;
	else if (strnstr(kcontrol->id.name, "LP", sizeof("LP")))
		slv_port_id = QMP_SDCA_LP_PORT;

	ucontrol->value.enumerated.item[0] = qmp_dmic_get_master_port_val(
			qmp->tx_master_port_map[slv_port_id]);

	dev_dbg(component->dev, "%s: ucontrol->value.enumerated.item[0] = %u\n",
		__func__, ucontrol->value.enumerated.item[0]);

	return 0;
}

static int qmp_dmic_tx_master_port_put(struct snd_kcontrol *kcontrol,
							struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);
	u8 slv_port_id = QMP_SDCA_NORMAL_PORT;
	unsigned int mport_idx = 0;

	if (strnstr(kcontrol->id.name, "Normal", sizeof("Normal")))
		slv_port_id = QMP_SDCA_NORMAL_PORT;
	else if (strnstr(kcontrol->id.name, "LP", sizeof("LP")))
		slv_port_id = QMP_SDCA_LP_PORT;

	mport_idx = ucontrol->value.enumerated.item[0];
	if (mport_idx < 0 || mport_idx >= ARRAY_SIZE(qmp_master_channel_map))
		return -EINVAL;

	qmp->tx_master_port_map[slv_port_id] = qmp_master_channel_map[mport_idx];
	dev_dbg(component->dev, "slv port id: %d, master_port_type: %s\n",
		(slv_port_id + 1), master_port_type_to_str(qmp->tx_master_port_map[slv_port_id]));

	return 0;
}

static const char * const tx_master_port_text[] = {
	"ZERO", "SWRM_PCM_OUT", "SWRM_TX1_CH1", "SWRM_TX1_CH2", "SWRM_TX1_CH3",
	"SWRM_TX1_CH4", "SWRM_TX2_CH1", "SWRM_TX2_CH2", "SWRM_TX2_CH3",
	"SWRM_TX2_CH4", "SWRM_TX3_CH1", "SWRM_TX3_CH2", "SWRM_TX3_CH3",
	"SWRM_TX3_CH4", "SWRM_PCM_IN",
};

static const struct soc_enum tx_master_port_enum =
SOC_ENUM_SINGLE_EXT(ARRAY_SIZE(tx_master_port_text), tx_master_port_text);

static const char * const fu1_usage_modes_text[] = {
	"UNDEF0", "NORMAL_DIV_4", "NORMAL_DIV_3", "NORMAL_DIV_2", "UNDEF4", "UNDEF5",
	"UNDEF6", "UNDEF7", "HDR_DIV_4", "HDR_DIV_3", "HDR_DIV_2", "UNDEF11", "UNDEF12",
	"UNDEF13", "UNDEF14", "UNDEF15", "SNR_DIV_6", "SNR_DIV_8", "SNR_DIV_4", "SNR_DIV_3",
	"SNR_DIV_2", "UNDEF21", "UNDEF22", "UNDEF23", "AOP_DIV_4", "AOP_DIV_3", "AOP_DIV_2",
	"UNDEF27", "UNDEF28", "UNDEF29", "UNDEF30", "UNDEF31", "LP_DIV_16",
};

static const char * const fu2_usage_modes_text[] = {
	"UNDEF0", "LP_DIV_16",
};

static const struct soc_enum fu1_usage_modes_enum =
SOC_ENUM_SINGLE_EXT(ARRAY_SIZE(fu1_usage_modes_text), fu1_usage_modes_text);

static const struct soc_enum fu2_usage_modes_enum =
SOC_ENUM_SINGLE_EXT(ARRAY_SIZE(fu2_usage_modes_text), fu2_usage_modes_text);

static const struct snd_kcontrol_new qmp_dmic_snd_controls[] = {
	SOC_ENUM_EXT("Normal PortMap", tx_master_port_enum,
		qmp_dmic_tx_master_port_get, qmp_dmic_tx_master_port_put),
	SOC_ENUM_EXT("LP PortMap", tx_master_port_enum,
		qmp_dmic_tx_master_port_get, qmp_dmic_tx_master_port_put),
	SOC_ENUM_EXT("FU1 IT11 Usage Mode", fu1_usage_modes_enum,
		qmp_fu1_usage_modes_get, qmp_fu1_usage_modes_put),
	SOC_ENUM_EXT("FU2 IT11 Usage Mode", fu2_usage_modes_enum,
		qmp_fu2_usage_modes_get, qmp_fu2_usage_modes_put),
};

static const struct snd_kcontrol_new qmp_dmic_normal_switch[] = {
	SOC_DAPM_SINGLE("Enable", SND_SOC_NOPM, 0, 1, 0)
};

static const struct snd_kcontrol_new qmp_dmic_lp_switch[] = {
	SOC_DAPM_SINGLE("Enable", SND_SOC_NOPM, 0, 1, 0)
};


static int qmp_get_function_number(int slv_port_id)
{
	if (slv_port_id == QMP_SDCA_NORMAL_PORT)
		return FUNC_NUM_SMP_MIC1;
	else if (slv_port_id == QMP_SDCA_LP_PORT)
		return FUNC_NUM_SMP_MIC2;

	return FUNC_NUM_SMP_MIC1;
}

static int qmp_get_usage_mode(struct qmp_sdca_dmic_priv *qmp, int function_number)
{
	if (function_number == FUNC_NUM_SMP_MIC1)
		return qmp->fu1_usage_mode;

	if (function_number == FUNC_NUM_SMP_MIC2)
		return qmp->fu2_usage_mode;

	return qmp->fu1_usage_mode;
}


static int wait_for_pde_state(struct qmp_sdca_dmic_priv *qmp, int ps, int func_num)
{
	int act_ps, cnt = 0;
	int rc = 0;

	do {
		usleep_range(1000, 1500);
		/* wait and read actual_PS */
		rc = regmap_read(qmp->regmap,
				SDW_SDCA_CTL(func_num, QMP_SDCA_ENT_PDE11,
					QMP_SDCA_CTL_PDE_ACT_PS, QMP_SDCA_CTL_NUM0),
				&act_ps);

		if (rc == 0 && act_ps == ps)
			return rc;
	} while (++cnt < 5);

	dev_err(qmp->dev, "qmp ps%d request failed, func num %d act_ps %d\n",
		ps, func_num, act_ps);

	return -EINVAL;

}

static int qmp_dmic_port_enable(struct snd_soc_dapm_widget *w,
	struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component = snd_soc_dapm_to_component(w->dapm);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);
	u8 ch_mask = 0x01; /* only DpnChannelEN1 register is available */
	u8 num_port = 1;
	u8 port_type = 0;
	u8 slv_port_id = w->shift;
	u32 ch_rate;
	int ret = 0;

	if (slv_port_id >= QMP_SDCA_DMIC_MAX_PORTS) {
		dev_err_ratelimited(component->dev, "invalid slv port id: %d\n", slv_port_id);
		return -EINVAL;
	}
	ch_rate = qmp_get_channel_rate(qmp, slv_port_id);
	port_type = qmp->tx_master_port_map[slv_port_id];

	dev_dbg(component->dev, "slv port id %d, master port_type: %s event: %d\n",
		(slv_port_id + 1), master_port_type_to_str(port_type), event);

	switch (event) {
	case SND_SOC_DAPM_POST_PMU:
		break;
	case SND_SOC_DAPM_PRE_PMD:
		ret = swr_disconnect_port(qmp->swr_slave, &slv_port_id, num_port, &ch_mask,
				&port_type);
		ret = swr_slvdev_datapath_control(qmp->swr_slave, qmp->swr_slave->dev_num,
				false);
		break;
	}
	return ret;
}

static int qmp_dmic_pde11_event(struct snd_soc_dapm_widget *w,
		struct snd_kcontrol *kcontrol, int event)
{
	struct snd_soc_component *component = snd_soc_dapm_to_component(w->dapm);
	struct qmp_sdca_dmic_priv *qmp = snd_soc_component_get_drvdata(component);
	int ret = 0;
	u8 slv_port_id = w->shift;
	unsigned char ps0 = 0x0, ps3 = 0x3;
	int function_number, usage_mode;

	if (slv_port_id >= QMP_SDCA_DMIC_MAX_PORTS) {
		dev_err_ratelimited(component->dev, "invalid slv port id: %d\n", slv_port_id);
		return -EINVAL;
	}
	function_number = qmp_get_function_number(slv_port_id);

	dev_dbg(component->dev, "pde11 event for slv port id %d, func %d event: %d\n",
			(slv_port_id + 1), function_number, event);

	switch (event) {
	case SND_SOC_DAPM_PRE_PMU:
		/* Set Usage mode for the Function */
		usage_mode = qmp_get_usage_mode(qmp, function_number);
		regmap_write(qmp->regmap,
				SDW_SDCA_CTL(function_number, QMP_SDCA_ENT_IT11,
					QMP_SDCA_CTL_IT_USAGE, QMP_SDCA_CTL_NUM0),
				usage_mode);

		/* Set PDE11 control */
		regmap_write(qmp->regmap,
			SDW_SDCA_CTL(function_number, QMP_SDCA_ENT_PDE11,
				QMP_SDCA_CTL_PDE_REQ_PS, QMP_SDCA_CTL_NUM0),
			ps0);

		ret = wait_for_pde_state(qmp, ps0, function_number);
		if (!ret)
			dev_dbg(component->dev, "success! function %d, actual ps %d",
					function_number, ps0);
		break;
	case SND_SOC_DAPM_POST_PMD:
		/* Set PDE11 control */
		regmap_write(qmp->regmap,
			SDW_SDCA_CTL(function_number, QMP_SDCA_ENT_PDE11,
				QMP_SDCA_CTL_PDE_REQ_PS, QMP_SDCA_CTL_NUM0),
			ps3);
		ret = wait_for_pde_state(qmp, ps3, function_number);
		if (!ret)
			dev_dbg(component->dev, "success! function %d, actual ps %d",
					function_number, ps3);
		break;
	}

	return ret;
}

static const struct snd_soc_dapm_widget qmp_dmic_dapm_widgets[] = {
	SND_SOC_DAPM_INPUT("QMP_DMIC Function1"),
	SND_SOC_DAPM_INPUT("QMP_DMIC Function2"),

	SND_SOC_DAPM_MIXER_E("FU1 PDE11", SND_SOC_NOPM, QMP_SDCA_NORMAL_PORT, 0,
			qmp_dmic_normal_switch, ARRAY_SIZE(qmp_dmic_normal_switch),
			qmp_dmic_pde11_event, SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_MIXER_E("FU2 PDE11", SND_SOC_NOPM, QMP_SDCA_LP_PORT, 0,
			qmp_dmic_lp_switch, ARRAY_SIZE(qmp_dmic_lp_switch),
			qmp_dmic_pde11_event, SND_SOC_DAPM_PRE_PMU | SND_SOC_DAPM_POST_PMD),

	SND_SOC_DAPM_OUT_DRV_E("Normal Port Enable", SND_SOC_NOPM,
					QMP_SDCA_NORMAL_PORT, 0, NULL, 0, qmp_dmic_port_enable,
					SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),

	SND_SOC_DAPM_OUT_DRV_E("LP Port Enable", SND_SOC_NOPM,
					QMP_SDCA_LP_PORT, 0, NULL, 0, qmp_dmic_port_enable,
					SND_SOC_DAPM_POST_PMU | SND_SOC_DAPM_PRE_PMD),

	SND_SOC_DAPM_OUTPUT("NORMAL_OUTPUT"),
	SND_SOC_DAPM_OUTPUT("LP_OUTPUT"),
	SND_SOC_DAPM_MIC("QMP Digital Mic", NULL),
};

static const struct snd_soc_dapm_route qmp_dmic_audio_map[] = {
	{"QMP_DMIC Function1", NULL, "QMP Digital Mic"},
	{"QMP_DMIC Function2", NULL, "QMP Digital Mic"},
	{"FU1 PDE11", "Enable", "QMP_DMIC Function1"},
	{"Normal Port Enable", NULL, "FU1 PDE11"},
	{"NORMAL_OUTPUT", NULL, "Normal Port Enable"},
	{"FU2 PDE11", "Enable", "QMP_DMIC Function2"},
	{"LP Port Enable", NULL, "FU2 PDE11"},
	{"LP_OUTPUT", NULL, "LP Port Enable"},
};

static int qmp_dmic_component_probe(struct snd_soc_component *component)
{
	struct qmp_sdca_dmic_priv *qmp_dmic = snd_soc_component_get_drvdata(component);
	struct snd_soc_dapm_context *dapm = snd_soc_component_get_dapm(component);

	qmp_dmic = snd_soc_component_get_drvdata(component);

	if (!qmp_dmic)
		return -EINVAL;

	qmp_dmic->component = component;
	snd_soc_component_init_regmap(component, qmp_dmic->regmap);

	devm_regmap_qti_debugfs_register(qmp_dmic->dev, qmp_dmic->regmap);

	snd_soc_dapm_ignore_suspend(dapm, "QMP AIF1 Capture");
	snd_soc_dapm_ignore_suspend(dapm, "QMP AIF2 Capture");

	return 0;
}

static void qmp_dmic_component_remove(struct snd_soc_component *component)
{
	struct qmp_sdca_dmic_priv *qmp_dmic = snd_soc_component_get_drvdata(component);

	if (!qmp_dmic)
		return;

	devm_regmap_qti_debugfs_unregister(qmp_dmic->regmap);
	snd_soc_component_exit_regmap(component);
}

static const struct snd_soc_component_driver soc_codec_dev_qmp_dmic = {
	.name = NULL,
	.probe = qmp_dmic_component_probe,
	.remove = qmp_dmic_component_remove,
	.controls = qmp_dmic_snd_controls,
	.num_controls = ARRAY_SIZE(qmp_dmic_snd_controls),
	.dapm_widgets = qmp_dmic_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(qmp_dmic_dapm_widgets),
	.dapm_routes = qmp_dmic_audio_map,
	.num_dapm_routes = ARRAY_SIZE(qmp_dmic_audio_map),
};

/* qcom,swr-tx-port-params = <OFFSET1_VAL0 LANE1>, <OFFSET1_VAL5 LANE0>, *UC0*
 *			<OFFSET1_VAL0 LANE1>, <OFFSET1_VAL2 LANE0>, *UC1*
 *			<OFFSET1_VAL1 LANE0>, <OFFSET1_VAL1 LANE0>, *UC2*
 *			<OFFSET1_VAL1 LANE0>, <OFFSET1_VAL1 LANE0>, *UC3
 */
static int qmp_sdca_dmic_parse_port_params(struct device *dev, char *prop)
{
	int i, j;
	u32 *dt_array, map_size, max_uc;
	int ret = 0;
	u32 cnt = 0;
	struct swr_port_params (*map)[SWR_UC_MAX][QMP_SDCA_DMIC_MAX_PORTS];
	struct swr_dev_frame_config (*map_uc)[SWR_UC_MAX];
	struct qmp_sdca_dmic_priv *priv = dev_get_drvdata(dev);

	map = &priv->tx_port_params;
	map_uc = &priv->swr_tx_port_params;

	if (!of_find_property(dev->of_node, prop, &map_size)) {
		dev_err(dev, "missing port mapping property %s\n", prop);
		ret = -EINVAL;
		goto err_port_map;
	}

	max_uc = map_size / (QMP_SDCA_DMIC_MAX_PORTS * SWR_PORT_PARAMS * sizeof(u32));

	if (max_uc != SWR_UC_MAX) {
		dev_err(dev,
			"%s:port params not provided for all usecases\n", __func__);
		ret = -EINVAL;
		goto err_port_map;
	}
	dt_array = kzalloc(map_size, GFP_KERNEL);
	if (!dt_array) {
		ret = -ENOMEM;
		goto err_alloc;
	}
	ret = of_property_read_u32_array(dev->of_node, prop, dt_array,
				QMP_SDCA_DMIC_MAX_PORTS * SWR_PORT_PARAMS * max_uc);
	if (ret) {
		dev_err(dev, "Failed to read port mapping from prop %s\n", prop);
		goto err_pdata_fail;
	}

	for (i = 0; i < max_uc; i++) {
		for (j = 0; j < QMP_SDCA_DMIC_MAX_PORTS; j++) {
			cnt = (i * QMP_SDCA_DMIC_MAX_PORTS + j) * SWR_PORT_PARAMS;
			(*map)[i][j].offset1 = dt_array[cnt];
			(*map)[i][j].lane_ctrl = dt_array[cnt + 1];
			dev_err(dev, "%s: port %d, uc: %d, offset1:%d, lane: %d\n",
				__func__, j, i, dt_array[cnt], dt_array[cnt + 1]);
		}
		(*map_uc)[i].pp = &(*map)[i][0];
	}
	kfree(dt_array);
	return 0;

err_pdata_fail:
	kfree(dt_array);
err_alloc:
err_port_map:
	return ret;
}

static int qmp_sdca_dmic_init(struct device *dev, struct regmap *regmap,
							  struct swr_device *peripheral)
{
	struct qmp_sdca_dmic_priv *qmp_dmic;
	int ret, i;
	const char *qmp_dmic_codec_name_of = NULL;
	int dev_index = -1;

	qmp_dmic = devm_kzalloc(dev, sizeof(*qmp_dmic), GFP_KERNEL);
	if (!qmp_dmic)
		return -ENOMEM;

	dev_set_drvdata(dev, qmp_dmic);
	qmp_dmic->swr_slave = peripheral;
	qmp_dmic->regmap = regmap;
	qmp_dmic->dev = dev;
	qmp_dmic->clk_freq = MCLK_9P6MHZ;

	qmp_dmic->slave_vdd = devm_regulator_get(dev, "qmp-vdd");
	if (IS_ERR(qmp_dmic->slave_vdd)) {
		ret = PTR_ERR(qmp_dmic->slave_vdd);
		if (ret != -EPROBE_DEFER)
			dev_err(dev, "%s: get qmp-vdd-supply failed, ret=%d\n",
					__func__, ret);
		goto err;
	}
	ret = of_property_read_string(dev->of_node, "qcom,codec-name", &qmp_dmic_codec_name_of);
	if (ret) {
		dev_err(dev, "Looking up %s property in node %s failed\n",
		"qcom,codec-name", dev->of_node->full_name);
		goto err;
	}

	ret = qmp_sdca_dmic_parse_port_params(dev, "qcom,swr-tx-port-params");
	if (ret) {
		dev_err(dev, "Parsing %s failed in node %s\n",
			"qcom,swr-tx-port-params", dev->of_node->full_name);
		goto err;
	}

	qmp_dmic->driver = devm_kzalloc(dev,
			sizeof(const struct snd_soc_component_driver), GFP_KERNEL);
	if (!qmp_dmic->driver) {
		ret = -ENOMEM;
		goto err;
	}

	memcpy(qmp_dmic->driver, &soc_codec_dev_qmp_dmic,
		sizeof(const struct snd_soc_component_driver));

	for (i = 0; i < ARRAY_SIZE(codec_name_list); i++) {
		if (!strcmp(qmp_dmic_codec_name_of, codec_name_list[i])) {
			dev_index = i;
			break;
		}
	}
	if (dev_index < 0 || dev_index >= ARRAY_SIZE(codec_name_list)) {
		ret = -EINVAL;
		goto err;
	}
	qmp_dmic->driver->name = codec_name_list[dev_index];

	qmp_dmic->dai_driver = get_dai_driver(dev, dev_index);
	if (!qmp_dmic->dai_driver) {
		ret = -EINVAL;
		goto err;
	}
	ret = devm_snd_soc_register_component(dev, qmp_dmic->driver,
				qmp_dmic->dai_driver, ARRAY_SIZE(qmp_dmic_dai));
	if (ret) {
		dev_err(dev, "Codec component %s registration failed\n",
			qmp_dmic->driver->name);
	} else {
		dev_err(dev, "Codec component %s registration success!\n",
			qmp_dmic->driver->name);
		dev_err(dev, "Codec component:dai %s, %s registration success!\n",
			qmp_dmic->dai_driver[0].name, qmp_dmic->dai_driver[1].name);
	}

err:
	return ret;
}

static int qmp_sdca_dmic_suspend(struct device *dev)
{
	dev_dbg(dev, "%s: system suspend\n", __func__);
	return 0;
}

static int qmp_sdca_dmic_resume(struct device *dev)
{
	struct qmp_sdca_dmic_priv *qmp_priv = swr_get_dev_data(to_swr_device(dev));

	if (!qmp_priv) {
		dev_err_ratelimited(dev, "%s: qmp private data is NULL\n", __func__);
		return -EINVAL;
	}
	dev_dbg(dev, "%s: system resume\n", __func__);
	return 0;
}

static int qmp_sdca_dmic_probe(struct swr_device *peripheral)
{
	struct regmap *regmap;

	peripheral->paging_support = true;
	/* Regmap Initialization */
	regmap = devm_regmap_init_swr(peripheral, &qmp_sdca_dmic_regmap);
	if (IS_ERR(regmap))
		return PTR_ERR(regmap);

	return qmp_sdca_dmic_init(&peripheral->dev, regmap, peripheral);
}

static int qmp_sdca_dmic_remove(struct swr_device *pdev)
{

	return 0;
}

static const struct dev_pm_ops qmp_sdca_dmic_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(qmp_sdca_dmic_suspend, qmp_sdca_dmic_resume)
};

static const struct of_device_id qmp_sdca_dmic_dt_match[] = {
	{
		.compatible = "qcom,qmp-sdca-dmic",
	},
	{}
};

static const struct swr_device_id qmp_sdca_dmic_id[] = {
	{"qmp-sdca-dmic", 0},
	{}
};

static struct swr_driver qmp_sdca_dmic_driver = {
	.driver = {
		.name = "qmp-sdca-dmic",
		.owner = THIS_MODULE,
		.pm = &qmp_sdca_dmic_pm_ops,
		.of_match_table = qmp_sdca_dmic_dt_match,
	},
	.probe = qmp_sdca_dmic_probe,
	.remove = qmp_sdca_dmic_remove,
	.id_table = qmp_sdca_dmic_id,
};

static int __init qmp_sdca_dmic_swr_init(void)
{
	return swr_driver_register(&qmp_sdca_dmic_driver);
}

static void __exit qmp_sdca_dmic_swr_exit(void)
{
	swr_driver_unregister(&qmp_sdca_dmic_driver);
}

module_init(qmp_sdca_dmic_swr_init);
module_exit(qmp_sdca_dmic_swr_exit);

MODULE_DESCRIPTION("ASoC QMP SDCA DMIC driver");
MODULE_LICENSE("GPL");
