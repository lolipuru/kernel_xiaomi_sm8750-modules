// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <drm/msm_drm_aiqe.h>
#include "sde_kms.h"
#include "sde_crtc.h"
#include "sde_hw_dspp.h"
#include "sde_hw_mdss.h"
#include "sde_color_processing.h"
#include "sde_color_proc_property_helper.h"
#include "sde_color_processing_aiqe.h"
#include "sde_aiqe_common.h"


void _aiqe_caps_update(struct sde_crtc *crtc, struct sde_kms_info *info)
{
	struct sde_mdss_cfg *catalog = get_kms(&crtc->base)->catalog;
	u32 i, aiqe_idx = 0, num_mixers = crtc->num_mixers;
	char blk_name[256];

	if (!catalog->aiqe_count || num_mixers > catalog->aiqe_count)
		return;

	for (i = 0; i < num_mixers; i++) {
		struct sde_hw_dspp *dspp = crtc->mixers[i].hw_dspp;

		if (aiqe_idx >= catalog->aiqe_count)
			break;

		if (!dspp || !dspp->cap->sblk->aiqe.base)
			continue;

		snprintf(blk_name, sizeof(blk_name), "aiqe%u", aiqe_idx++);
		sde_kms_info_add_keyint(info, blk_name, 1);
	}
}

void _dspp_aiqe_install_property(struct drm_crtc *crtc)
{
	struct sde_crtc *sde_crtc = NULL;
	struct sde_kms *kms = NULL;
	struct sde_mdss_cfg *catalog = NULL;
	u32 major_version, version;

	kms = get_kms(crtc);
	catalog = kms->catalog;
	version = catalog->dspp[0].sblk->aiqe.version;
	major_version = version >> 16;
	switch (major_version) {
	case 1:
		if (catalog->dspp[0].sblk->aiqe.mdnie_supported) {
			_sde_cp_crtc_install_range_property(crtc, "SDE_DSPP_AIQE_MDNIE_V1",
				SDE_CP_CRTC_DSPP_MDNIE, 0, U64_MAX, 0);
			_sde_cp_create_local_blob(crtc, SDE_CP_CRTC_DSPP_MDNIE,
				sizeof(struct drm_msm_mdnie));

			_sde_cp_crtc_install_range_property(crtc, "SDE_DSPP_AIQE_MDNIE_ART_V1",
				SDE_CP_CRTC_DSPP_MDNIE_ART, 0, U64_MAX, 0);
			_sde_cp_create_local_blob(crtc, SDE_CP_CRTC_DSPP_MDNIE_ART,
				sizeof(struct drm_msm_mdnie_art));
		}

		if (catalog->dspp[0].sblk->aiqe.copr_supported) {
			_sde_cp_crtc_install_range_property(crtc, "SDE_DSPP_AIQE_COPR_V1",
				SDE_CP_CRTC_DSPP_COPR, 0, U64_MAX, 0);
			_sde_cp_create_local_blob(crtc, SDE_CP_CRTC_DSPP_COPR,
				sizeof(struct drm_msm_copr));
		}
		break;
	default:
		DRM_ERROR("version %d not supported\n", version);
		break;
	}

	sde_crtc = to_sde_crtc(crtc);
	if (!sde_crtc) {
		DRM_ERROR("invalid sde_crtc %pK\n", sde_crtc);
		return;
	}

	aiqe_init(version, &sde_crtc->aiqe_top_level);
}

int set_mdnie_feature(struct sde_hw_dspp *hw_dspp,
				   struct sde_hw_cp_cfg *hw_cfg,
				   struct sde_crtc *hw_crtc)
{
	int ret = 0;

	if (!hw_dspp || !hw_dspp->ops.setup_mdnie)
		ret = -EINVAL;
	else
		hw_dspp->ops.setup_mdnie(hw_dspp, hw_cfg, &hw_crtc->aiqe_top_level);

	return ret;
}

int set_mdnie_art_feature(struct sde_hw_dspp *hw_dspp,
				   struct sde_hw_cp_cfg *hw_cfg,
				   struct sde_crtc *hw_crtc)
{
	int ret = 0;

	if (!hw_dspp || !hw_dspp->ops.setup_mdnie_art)
		ret = -EINVAL;
	else
		hw_dspp->ops.setup_mdnie_art(hw_dspp, hw_cfg, &hw_crtc->aiqe_top_level);

	return ret;
}

int set_copr_feature(struct sde_hw_dspp *hw_dspp,
				   struct sde_hw_cp_cfg *hw_cfg,
				   struct sde_crtc *hw_crtc)
{
	int ret = 0;

	if (!hw_dspp || !hw_dspp->ops.setup_copr)
		ret = -EINVAL;
	else
		hw_dspp->ops.setup_copr(hw_dspp, hw_cfg, &hw_crtc->aiqe_top_level);

	return ret;
}

int sde_dspp_mdnie_read_art_done(struct sde_hw_dspp *hw_dspp, u32 *art_done)
{
	int rc;

	if (!art_done || !hw_dspp || !hw_dspp->ops.read_mdnie_art_done)
		return -EINVAL;

	rc = hw_dspp->ops.read_mdnie_art_done(hw_dspp, art_done);
	if (rc)
		SDE_ERROR("invalid art read %d", rc);

	return rc;
}

int sde_dspp_copr_read_status(struct sde_hw_dspp *hw_dspp,
		struct drm_msm_copr_status *copr_status)
{
	int rc;

	if (!copr_status || !hw_dspp || !hw_dspp->ops.read_copr_status)
		return -EINVAL;

	rc = hw_dspp->ops.read_copr_status(hw_dspp, copr_status);
	if (rc)
		SDE_ERROR("invalid status read %d", rc);

	return rc;
}

void sde_set_mdnie_psr(struct sde_crtc *sde_crtc)
{
	struct sde_hw_dspp *hw_dspp = NULL;
	u32 num_mixers = sde_crtc->num_mixers;
	int i;

	hw_dspp = sde_crtc->mixers[0].hw_dspp;

	if (!sde_crtc || !hw_dspp)
		return;

	for (i = 0; i < num_mixers; i++)
		hw_dspp->ops.setup_mdnie_psr(hw_dspp);
}
