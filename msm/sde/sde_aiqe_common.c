// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include "sde_kms.h"
#include "sde_aiqe_common.h"
#include "sde_hw_catalog.h"
#include "sde_hw_mdss.h"

#define AIQE_VER_1_0 0x00010000

void (*aiqe_get_common_values_func)(struct sde_hw_cp_cfg *cfg,
		struct sde_aiqe_top_level *aiqe_top, struct aiqe_reg_common *aiqe_cmn);
static void aiqe_get_common_values_v1(struct sde_hw_cp_cfg *cfg,
					struct sde_aiqe_top_level *aiqe_top,
					struct aiqe_reg_common *aiqe_cmn);

void aiqe_init(u32 aiqe_version, struct sde_aiqe_top_level *aiqe_top)
{
	if (!aiqe_top)
		return;

	mutex_lock(&aiqe_top->aiqe_mutex);
	switch (aiqe_version) {
	case AIQE_VER_1_0:
		aiqe_get_common_values_func = &aiqe_get_common_values_v1;
		break;
	default:
		break;
	}
	mutex_unlock(&aiqe_top->aiqe_mutex);
}

void aiqe_register_client(enum aiqe_features feature_id, struct sde_aiqe_top_level *aiqe_top)
{
	if (!aiqe_top || feature_id >= AIQE_FEATURE_MAX)
		return;

	SDE_EVT32(feature_id);
	mutex_lock(&aiqe_top->aiqe_mutex);
	aiqe_top->aiqe_mask |= 1 << feature_id;
	mutex_unlock(&aiqe_top->aiqe_mutex);
}

void aiqe_deregister_client(enum aiqe_features feature_id, struct sde_aiqe_top_level *aiqe_top)
{
	if (!aiqe_top || feature_id >= AIQE_FEATURE_MAX)
		return;

	SDE_EVT32(feature_id);
	mutex_lock(&aiqe_top->aiqe_mutex);
	aiqe_top->aiqe_mask &= ~(1 << feature_id);
	mutex_unlock(&aiqe_top->aiqe_mutex);
}

void aiqe_get_common_values(struct sde_hw_cp_cfg *cfg, struct sde_aiqe_top_level *aiqe_top,
				struct aiqe_reg_common *aiqe_cmn)
{
	if (aiqe_get_common_values_func == NULL) {
		DRM_ERROR("Get common values function is invalid!");
		return;
	}

	if (!cfg || !aiqe_top || !aiqe_cmn) {
		DRM_ERROR("Invalid params!\n");
		return;
	}

	(*aiqe_get_common_values_func)(cfg, aiqe_top, aiqe_cmn);
}

static void aiqe_get_common_values_v1(struct sde_hw_cp_cfg *cfg,
					struct sde_aiqe_top_level *aiqe_top,
					struct aiqe_reg_common *aiqe_cmn)
{
	struct sde_hw_mixer *hw_lm = NULL;

	hw_lm = cfg->mixer_info;
	mutex_lock(&aiqe_top->aiqe_mutex);
	if (aiqe_top->aiqe_mask == 0)
		aiqe_cmn->config &= ~BIT(0);
	else
		aiqe_cmn->config |= BIT(0);

	if (hw_lm->idx == LM_0) {
		aiqe_cmn->config &= ~BIT(1);
	} else if (hw_lm->idx == LM_2) {
		aiqe_cmn->config |= BIT(1);
	} else {
		DRM_DEBUG_DRIVER("AIQE not supported on LM idx %d", hw_lm->idx);
		mutex_unlock(&aiqe_top->aiqe_mutex);
		return;
	}

	if (cfg->num_of_mixers == 1) {
		aiqe_cmn->merge = SINGLE_MODE;
	} else if (cfg->num_of_mixers == 2) {
		aiqe_cmn->merge = DUAL_MODE;
	} else if (cfg->num_of_mixers == 4) {
		aiqe_cmn->merge = QUAD_MODE;
	} else {
		DRM_ERROR("Invalid number of mixers %d", cfg->num_of_mixers);
		mutex_unlock(&aiqe_top->aiqe_mutex);
		return;
	}

	aiqe_cmn->height = cfg->panel_height;
	aiqe_cmn->width = cfg->panel_width;
	mutex_unlock(&aiqe_top->aiqe_mutex);
}

bool mdnie_art_in_progress(struct sde_aiqe_top_level *aiqe_top)
{
	bool status = false;

	if (!aiqe_top)
		return status;

	mutex_lock(&aiqe_top->aiqe_mutex);
	status = ((1 << FEATURE_MDNIE_ART) & aiqe_top->aiqe_mask) >> FEATURE_MDNIE_ART;
	mutex_unlock(&aiqe_top->aiqe_mutex);
	return status;
}

void aiqe_deinit(struct sde_aiqe_top_level *aiqe_top)
{
}

int sde_cp_crtc_check_ssip_fuse(struct sde_kms *sde_kms, bool *allowed)
{
	struct drm_device *dev;
	struct platform_device *pdev;
	int rc = -EINVAL;
	uint32_t fuse = 0;
	bool disable = false, polarity = false;

	*allowed = false;
	dev = sde_kms->dev;
	if (!dev || !dev->dev) {
		DRM_ERROR("invalid device\n");
		return rc;
	}

	pdev = to_platform_device(dev->dev);
	rc = sde_parse_fuse_configuration(pdev, "ssip_config", &fuse);
	if (rc) {
		DRM_DEBUG("failed to read ssip config for ss_config %d\n", rc);
		*allowed = false;
		return 0;
	}

	disable = (fuse & BIT(1)) >> 1;
	polarity = fuse & BIT(0);

	DRM_INFO("ssip: disable = %d polarity = %d\n", disable, polarity);
	if (disable && polarity)
		*allowed = true;
	else if (!disable && !polarity)
		*allowed = true;

	return rc;
}
