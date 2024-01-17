// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <drm/msm_drm_aiqe.h>
#include "sde_hw_util.h"
#include "sde_reg_dma.h"
#include "sde_dbg.h"
#include "sde_hw_reg_dma_v1_color_proc.h"
#include "sde_hw_color_proc_aiqe_v1.h"
#include "sde_aiqe_common.h"
#include "sde_crtc.h"


static void sde_setup_aiqe_common_v1(struct sde_hw_dspp *ctx, void *cfg,
					struct sde_aiqe_top_level *aiqe_top)
{
	struct aiqe_reg_common aiqe_common;
	struct sde_hw_cp_cfg *hw_cfg = cfg;
	u32 aiqe_base = ctx->cap->sblk->aiqe.base;

	aiqe_get_common_values(hw_cfg, aiqe_top, &aiqe_common);

	SDE_REG_WRITE(&ctx->hw, aiqe_base, aiqe_common.config);
	SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x4, aiqe_common.merge);
	SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x14,
			((aiqe_common.width & 0xFFF) << 16) | (aiqe_common.height & 0xFFF));
}

static int _reg_dmav1_aiqe_write_top_level_v1(struct sde_reg_dma_setup_ops_cfg *dma_cfg,
		struct sde_hw_dspp *ctx, struct sde_hw_cp_cfg *hw_cfg,
		struct sde_hw_reg_dma_ops *dma_ops,
		struct sde_aiqe_top_level *aiqe_top)
{
	struct aiqe_reg_common aiqe_common;
	u32 values[3];
	u32 base = ctx->hw.blk_off + ctx->cap->sblk->aiqe.base;
	int rc = 0;

	aiqe_get_common_values(hw_cfg, aiqe_top, &aiqe_common);

	values[0] = aiqe_common.config;
	values[1] = aiqe_common.merge;
	values[2] = ((aiqe_common.width & 0xFFF) << 16) | (aiqe_common.height & 0xFFF);
	REG_DMA_SETUP_OPS(*dma_cfg, base,
			&values[0], 2 * sizeof(u32), REG_BLK_WRITE_SINGLE, 0, 0, 0);
	rc = dma_ops->setup_payload(dma_cfg);
	if (rc) {
		DRM_ERROR("write top part 1 failed ret %d\n", rc);
		return rc;
	}

	REG_DMA_SETUP_OPS(*dma_cfg, base + 0x14,
			&values[2], sizeof(u32), REG_SINGLE_WRITE, 0, 0, 0);
	rc = dma_ops->setup_payload(dma_cfg);
	if (rc)
		DRM_ERROR("write top part 2 failed ret %d\n", rc);

	return rc;
}

void sde_reset_mdnie_art(struct sde_hw_dspp *ctx)
{
	u32 aiqe_base = 0;

	if (!ctx) {
		DRM_ERROR("invalid parameters ctx %pK\n", ctx);
		return;
	}

	aiqe_base = ctx->cap->sblk->aiqe.base;
	if (!aiqe_base) {
		DRM_DEBUG_DRIVER("AIQE not supported on DSPP idx %d", ctx->idx);
		return;
	}

	SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x3dc, 0x10);
	SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x100, 0);
}

int sde_read_mdnie_art_done(struct sde_hw_dspp *ctx, uint32_t *art_done)
{
	uint32_t art_off;

	if (!ctx || !art_done)
		return -EINVAL;

	art_off = ctx->cap->sblk->aiqe.base + 0x3d8;
	*art_done = (SDE_REG_READ(&ctx->hw, art_off) & BIT(4)) >> 4;

	SDE_EVT32(*art_done);
	return 0;
}

int sde_read_copr_status(struct sde_hw_dspp *ctx, struct drm_msm_copr_status *copr_status)
{
	uint32_t status_off;
	int i;

	if (!ctx || !copr_status)
		return -EINVAL;

	status_off = ctx->cap->sblk->aiqe.base + 0x344;
	for (i = 0; i < AIQE_COPR_STATUS_LEN; i++)
		copr_status->status[i] = SDE_REG_READ(&ctx->hw, status_off + 4 * i);

	return 0;
}


void sde_setup_mdnie_art_v1(struct sde_hw_dspp *ctx, void *cfg, void *aiqe_top)
{
	struct sde_hw_cp_cfg *hw_cfg = cfg;
	struct drm_msm_mdnie_art *mdnie_art = NULL;
	u32 art_value, art_id, aiqe_base = 0;

	if (!ctx || !cfg) {
		DRM_ERROR("invalid parameters ctx %pK cfg %pK\n", ctx, cfg);
		return;
	}

	aiqe_base = ctx->cap->sblk->aiqe.base;
	if (!aiqe_base) {
		DRM_ERROR("AIQE not supported on DSPP idx %d", ctx->idx);
		return;
	}

	mdnie_art = (struct drm_msm_mdnie_art *)(hw_cfg->payload);
	if (mdnie_art && hw_cfg->len != sizeof(struct drm_msm_mdnie_art)) {
		DRM_ERROR("invalid size of payload len %d exp %zd\n",
				hw_cfg->len, sizeof(struct drm_msm_mdnie_art));
		return;
	}

	if (!mdnie_art || !(mdnie_art->param & BIT(0))) {
		DRM_DEBUG_DRIVER("Disable MDNIE ART feature\n");
		sde_setup_aiqe_common_v1(ctx, hw_cfg, aiqe_top);
		SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x100, 0);
		LOG_FEATURE_OFF;
		return;
	}

	sde_setup_aiqe_common_v1(ctx, hw_cfg, aiqe_top);
	art_id = ~((SDE_REG_READ(&ctx->hw, aiqe_base + 0x100) & BIT(1)) >> 1) & BIT(0);
	art_value = (mdnie_art->param & 0xFFFFFF01) | (art_id << 1);
	SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x100, art_value);
	LOG_FEATURE_ON;
}

void sde_setup_copr_v1(struct sde_hw_dspp *ctx, void *cfg, void *aiqe_top)
{
	struct sde_hw_cp_cfg *hw_cfg = cfg;
	struct drm_msm_copr *copr_data = NULL;
	u32 data, i, aiqe_base = 0;

	if (!ctx || !cfg) {
		DRM_ERROR("invalid parameters ctx %pK cfg %pK\n", ctx, cfg);
		return;
	}

	aiqe_base = ctx->cap->sblk->aiqe.base;
	if (!aiqe_base) {
		DRM_DEBUG_DRIVER("AIQE not supported on DSPP idx %d", ctx->idx);
		return;
	}

	copr_data = (struct drm_msm_copr *)(hw_cfg->payload);
	if (copr_data && hw_cfg->len != sizeof(struct drm_msm_copr)) {
		DRM_ERROR("invalid size of payload len %d exp %zd\n",
				hw_cfg->len, sizeof(struct drm_msm_copr));
		return;
	}

	if (!copr_data || !(copr_data->param[0] & BIT(0))) {
		DRM_DEBUG_DRIVER("Disable COPR feature\n");
		sde_setup_aiqe_common_v1(ctx, hw_cfg, aiqe_top);
		SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x300, 0);
		LOG_FEATURE_OFF;
		return;
	}

	sde_setup_aiqe_common_v1(ctx, hw_cfg, aiqe_top);
	for (i = 0; i < AIQE_COPR_PARAM_LEN; i++) {
		data = copr_data->param[i];
		SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x300 + (i * 4), data);
	}
	LOG_FEATURE_ON;
}

void sde_setup_mdnie_psr(struct sde_hw_dspp *ctx)
{
	u32 aiqe_base = 0;

	if (!ctx) {
		DRM_ERROR("invalid parameters ctx %pK\n", ctx);
		return;
	}

	aiqe_base = ctx->cap->sblk->aiqe.base;
	if (!aiqe_base) {
		DRM_DEBUG_DRIVER("AIQE not supported on DSPP idx %d", ctx->idx);
		return;
	}

	SDE_REG_WRITE(&ctx->hw, aiqe_base + 0x3f4, 1);
}

static void _mdnie_disable_v1(struct sde_reg_dma_setup_ops_cfg *dma_cfg,
		struct sde_hw_dspp *ctx, struct sde_hw_cp_cfg *hw_cfg,
		struct sde_hw_reg_dma_ops *dma_ops,
		struct sde_aiqe_top_level *aiqe_top)
{
	int rc = 0;
	u32 value = 0;
	u32 base = ctx->hw.blk_off + ctx->cap->sblk->aiqe.base;
	struct sde_reg_dma_kickoff_cfg dma_kickoff;

	rc = _reg_dmav1_aiqe_write_top_level_v1(dma_cfg, ctx, hw_cfg, dma_ops, aiqe_top);
	if (rc)
		return;

	REG_DMA_SETUP_OPS(*dma_cfg, base + 0x104,
		&value, sizeof(u32), REG_SINGLE_WRITE, 0, 0, 0);
	rc = dma_ops->setup_payload(dma_cfg);
	if (rc) {
		DRM_ERROR("write decode select failed ret %d\n", rc);
		return;
	}

	REG_DMA_SETUP_KICKOFF(dma_kickoff, hw_cfg->ctl, dma_cfg->dma_buf,
			REG_DMA_WRITE, DMA_CTL_QUEUE0,
			WRITE_IMMEDIATE, AIQE_MDNIE);
	rc = dma_ops->kick_off(&dma_kickoff, ctx->dpu_idx);
	if (rc)
		DRM_ERROR("failed to kick off ret %d\n", rc);
	else
		LOG_FEATURE_OFF;
}

void reg_dmav1_setup_mdnie_v1(struct sde_hw_dspp *ctx, void *cfg, void *aiqe_top)
{
	struct drm_msm_mdnie *mdnie_data;
	struct sde_hw_cp_cfg *hw_cfg = cfg;
	struct sde_hw_reg_dma_ops *dma_ops;
	struct sde_reg_dma_setup_ops_cfg dma_write_cfg;
	struct sde_reg_dma_kickoff_cfg kick_off;
	int rc = 0;
	u32 aiqe_base = 0;

	if (!ctx || !cfg) {
		DRM_ERROR("invalid parameters ctx %pK cfg %pK\n", ctx, cfg);
		return;
	}

	if (!ctx->cap->sblk->aiqe.base) {
		DRM_DEBUG_DRIVER("AIQE not supported on DSPP idx %d", ctx->idx);
		return;
	}

	rc = reg_dma_dspp_check(ctx, cfg, AIQE_MDNIE);
	if (rc)
		return;

	aiqe_base = ctx->hw.blk_off + ctx->cap->sblk->aiqe.base;
	dma_ops = sde_reg_dma_get_ops(ctx->dpu_idx);
	dma_ops->reset_reg_dma_buf(dspp_buf[AIQE_MDNIE][ctx->idx][ctx->dpu_idx]);
	REG_DMA_INIT_OPS(dma_write_cfg, MDSS, AIQE_MDNIE,
		dspp_buf[AIQE_MDNIE][ctx->idx][ctx->dpu_idx]);
	REG_DMA_SETUP_OPS(dma_write_cfg, 0, NULL, 0, HW_BLK_SELECT, 0, 0, 0);
	rc = dma_ops->setup_payload(&dma_write_cfg);
	if (rc) {
		DRM_ERROR("write decode select failed ret %d\n", rc);
		return;
	}

	mdnie_data = hw_cfg->payload;
	if (mdnie_data && hw_cfg->len != sizeof(struct drm_msm_mdnie)) {
		DRM_ERROR("invalid sz of payload len %d exp %zd\n",
				hw_cfg->len, sizeof(struct drm_msm_mdnie));
		return;
	}

	if (!mdnie_data || !(mdnie_data->param[0] & BIT(0))) {
		DRM_DEBUG_DRIVER("Disable MDNIE feature\n");
		_mdnie_disable_v1(&dma_write_cfg, ctx, hw_cfg, dma_ops, aiqe_top);
		return;
	}

	rc = _reg_dmav1_aiqe_write_top_level_v1(&dma_write_cfg, ctx, hw_cfg, dma_ops, aiqe_top);
	if (rc)
		return;

	REG_DMA_SETUP_OPS(dma_write_cfg, aiqe_base + 0x104, mdnie_data->param,
			AIQE_MDNIE_PARAM_LEN * sizeof(u32), REG_BLK_WRITE_SINGLE, 0, 0, 0);
	rc = dma_ops->setup_payload(&dma_write_cfg);
	if (rc) {
		SDE_ERROR("mdnie dma write failed ret %d\n", rc);
		return;
	}

	REG_DMA_SETUP_KICKOFF(kick_off, hw_cfg->ctl,
			dspp_buf[AIQE_MDNIE][ctx->idx][ctx->dpu_idx],
			REG_DMA_WRITE, DMA_CTL_QUEUE0, WRITE_IMMEDIATE,
			AIQE_MDNIE);

	rc = dma_ops->kick_off(&kick_off, ctx->dpu_idx);
	if (rc) {
		DRM_ERROR("failed to kick off ret %d\n", rc);
		return;
	}

	LOG_FEATURE_ON;
}

#define PRIMARY_SSRC_EXPECTED_SIZE 1281
#define SECONDARY_SSRC_EXPECTED_SIZE 2049
int sde_validate_aiqe_ssrc_data_v1(struct sde_hw_dspp *ctx, void *cfg, void *aiqe_top)
{
	int rc = 0;
	struct drm_msm_ssrc_data *data;
	struct sde_aiqe_top_level *aiqe_tl = aiqe_top;
	struct sde_hw_cp_cfg *hw_cfg = cfg;
	struct aiqe_reg_common aiqe_common;
	size_t region_count = 0, index = 0;
	size_t max_size = 0, max_regions = 0;

	if (!hw_cfg || !ctx || !aiqe_tl)
		return -EINVAL;
	else if (!hw_cfg->payload || ctx->idx != hw_cfg->dspp[0]->idx)
		return 0;

	data = hw_cfg->payload;
	if (data->data_size == 0) {
		DRM_ERROR("Data size must be greater than 0\n");
		return -EINVAL;
	} else if (data->data_size > AIQE_SSRC_DATA_LEN) {
		DRM_ERROR("Data size exceeds max data size. Max - %d\t Actual - %u",
				AIQE_SSRC_DATA_LEN, data->data_size);
		return -EINVAL;
	}

	aiqe_get_common_values(hw_cfg, aiqe_tl, &aiqe_common);
	if (aiqe_common.config & BIT(1)) {
		max_size = SECONDARY_SSRC_EXPECTED_SIZE;
		max_regions = 2;
	} else {
		max_size = PRIMARY_SSRC_EXPECTED_SIZE;
		max_regions = 4;
	}

	while (index < data->data_size) {
		size_t region_size = data->data[index];

		region_count++;
		index += region_size + 1;
		if (region_size > max_size) {
			DRM_ERROR("Region size exceeds max size. Max - %zu\t Actual - %zu",
					max_size, region_size);
			rc = -EINVAL;
			break;
		} else if (region_count > max_regions) {
			DRM_ERROR("Region count exceeds max. Max - %zu\t Actual - %zu",
					max_regions, region_count);
			rc = -EINVAL;
			break;
		}
	}

	if (index > data->data_size) {
		DRM_ERROR("Region data exceeds reported size. Reported - %u\t Actual - %zu",
				data->data_size, index);
		rc = -EINVAL;
	}

	return rc;
}

static void _aiqe_ssrc_config_off_v1(struct sde_reg_dma_setup_ops_cfg *dma_cfg,
		struct sde_hw_dspp *ctx, struct sde_hw_cp_cfg *hw_cfg,
		struct sde_hw_reg_dma_ops *dma_ops,
		struct sde_aiqe_top_level *aiqe_top)
{
	int rc = 0;
	u32 value = 0;
	u32 base = ctx->hw.blk_off + ctx->cap->sblk->aiqe.base;
	struct sde_reg_dma_kickoff_cfg dma_kickoff;

	// Error message handled in function
	rc = _reg_dmav1_aiqe_write_top_level_v1(dma_cfg, ctx, hw_cfg, dma_ops, aiqe_top);
	if (rc)
		return;

	REG_DMA_SETUP_OPS(*dma_cfg, base + 0x380,
		&value, sizeof(u32), REG_SINGLE_WRITE, 0, 0, 0);
	rc = dma_ops->setup_payload(dma_cfg);
	if (rc) {
		DRM_ERROR("write SSRC off failed ret %d\n", rc);
		return;
	}

	REG_DMA_SETUP_KICKOFF(dma_kickoff, hw_cfg->ctl, dma_cfg->dma_buf,
			REG_DMA_WRITE, DMA_CTL_QUEUE0,
			WRITE_IMMEDIATE, AIQE_SSRC_CONFIG);
	rc = dma_ops->kick_off(&dma_kickoff, ctx->dpu_idx);
	if (rc)
		DRM_ERROR("failed to kick off ret %d\n", rc);
	else
		LOG_FEATURE_OFF;
}

void reg_dmav1_setup_aiqe_ssrc_config_v1(struct sde_hw_dspp *ctx, void *cfg, void *aiqe_top)
{
	struct drm_msm_ssrc_config *ssrc_config;
	struct sde_aiqe_top_level *aiqe_tl = aiqe_top;
	struct sde_hw_cp_cfg *hw_cfg = cfg;
	struct sde_hw_reg_dma_ops *dma_ops;
	struct sde_reg_dma_buffer *buf;
	struct sde_reg_dma_setup_ops_cfg dma_cfg;
	struct sde_reg_dma_kickoff_cfg dma_kickoff;
	int rc = -EINVAL;
	u32 base;

	rc = reg_dma_dspp_check(ctx, cfg, AIQE_SSRC_CONFIG);
	if (rc)
		return;

	if (!ctx->cap->sblk->aiqe.base) {
		DRM_DEBUG_DRIVER("AIQE not present on DSPP idx %d", ctx->idx);
		return;
	}

	base = ctx->hw.blk_off + ctx->cap->sblk->aiqe.base;
	dma_ops = sde_reg_dma_get_ops(ctx->dpu_idx);
	buf = dspp_buf[AIQE_SSRC_CONFIG][ctx->idx][ctx->dpu_idx];
	dma_ops->reset_reg_dma_buf(buf);
	REG_DMA_INIT_OPS(dma_cfg, MDSS, AIQE_SSRC_CONFIG, buf);
	REG_DMA_SETUP_OPS(dma_cfg, 0, NULL, 0, HW_BLK_SELECT, 0, 0, 0);
	rc = dma_ops->setup_payload(&dma_cfg);
	if (rc) {
		DRM_ERROR("write decode select failed ret %d\n", rc);
		return;
	}

	ssrc_config = hw_cfg->payload;
	if (!ssrc_config || (ssrc_config->config[0] & BIT(0)) == 0) {
		_aiqe_ssrc_config_off_v1(&dma_cfg, ctx, hw_cfg, dma_ops, aiqe_tl);
		return;
	}

	// Error message handled in function
	rc = _reg_dmav1_aiqe_write_top_level_v1(&dma_cfg, ctx, hw_cfg, dma_ops, aiqe_tl);
	if (rc)
		return;

	REG_DMA_SETUP_OPS(dma_cfg, base + 0x380,
		ssrc_config->config, AIQE_SSRC_PARAM_LEN * sizeof(u32),
		REG_BLK_WRITE_SINGLE, 0, 0, 0);
	rc = dma_ops->setup_payload(&dma_cfg);
	if (rc) {
		DRM_ERROR("write config failed ret %d\n", rc);
		return;
	}

	REG_DMA_SETUP_KICKOFF(dma_kickoff, hw_cfg->ctl, dma_cfg.dma_buf,
			REG_DMA_WRITE, DMA_CTL_QUEUE0,
			WRITE_IMMEDIATE, AIQE_SSRC_CONFIG);
	rc = dma_ops->kick_off(&dma_kickoff, ctx->dpu_idx);
	if (rc)
		DRM_ERROR("failed to kick off ret %d\n", rc);
	else
		LOG_FEATURE_ON;
}

void reg_dmav1_setup_aiqe_ssrc_data_v1(struct sde_hw_dspp *ctx, void *cfg, void *aiqe_top)
{
	struct drm_msm_ssrc_data *ssrc_data;
	struct sde_hw_cp_cfg *hw_cfg = cfg;
	struct sde_hw_reg_dma_ops *dma_ops;
	struct sde_reg_dma_buffer *buf;
	struct sde_reg_dma_setup_ops_cfg dma_cfg;
	struct sde_reg_dma_kickoff_cfg dma_kickoff;
	int rc = -EINVAL;
	size_t index = 0;
	u32 base;

	rc = reg_dma_dspp_check(ctx, cfg, AIQE_SSRC_DATA);
	if (rc)
		return;

	if (!ctx->cap->sblk->aiqe.base) {
		DRM_DEBUG_DRIVER("MDNIE not present on DSPP idx %d", ctx->idx);
		return;
	}

	base = ctx->hw.blk_off + ctx->cap->sblk->aiqe.base;
	dma_ops = sde_reg_dma_get_ops(ctx->dpu_idx);
	buf = dspp_buf[AIQE_SSRC_DATA][ctx->idx][ctx->dpu_idx];
	dma_ops->reset_reg_dma_buf(buf);
	REG_DMA_INIT_OPS(dma_cfg, MDSS, AIQE_SSRC_DATA, buf);
	REG_DMA_SETUP_OPS(dma_cfg, 0, NULL, 0, HW_BLK_SELECT, 0, 0, 0);
	rc = dma_ops->setup_payload(&dma_cfg);
	if (rc) {
		DRM_ERROR("write decode select failed ret %d\n", rc);
		return;
	}

	ssrc_data = hw_cfg->payload;
	if (!ssrc_data) {
		LOG_FEATURE_OFF;
		return;
	}

	while (index < ssrc_data->data_size) {
		size_t region_size = ssrc_data->data[index++];

		REG_DMA_SETUP_OPS(dma_cfg, base + 0x0C,
				&ssrc_data->data[index], sizeof(u32), REG_SINGLE_WRITE, 0, 0, 0);
		rc = dma_ops->setup_payload(&dma_cfg);
		if (rc) {
			DRM_ERROR("write data phase 1 failed ret %d\n", rc);
			return;
		}

		REG_DMA_SETUP_OPS(dma_cfg, base + 0x10,
				&ssrc_data->data[index + 1], (region_size - 1) * sizeof(u32),
				REG_BLK_WRITE_INC, 0, 0, 0);
		rc = dma_ops->setup_payload(&dma_cfg);
		if (rc) {
			DRM_ERROR("write data phase 2 failed ret %d\n", rc);
			return;
		}

		index += region_size;
	}

	REG_DMA_SETUP_KICKOFF(dma_kickoff, hw_cfg->ctl, buf,
			REG_DMA_WRITE, DMA_CTL_QUEUE0, WRITE_IMMEDIATE, AIQE_SSRC_DATA);
	rc = dma_ops->kick_off(&dma_kickoff, ctx->dpu_idx);
	if (rc)
		DRM_ERROR("failed to kick off ret %d\n", rc);
	else
		LOG_FEATURE_ON;
}
