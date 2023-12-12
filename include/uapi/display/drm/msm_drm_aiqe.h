/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#ifndef _MSM_DRM_AIQE_H_
#define _MSM_DRM_AIQE_H_

#include <drm/drm.h>

#define AIQE_MDNIE_SUPPORTED
#define AIQE_MDNIE_PARAM_LEN 118
/**
 * struct drm_msm_mdnie - mDNIe feature structure
 * @flags - Setting flags for mDNIe feature
 * @param - Parameters for mDNIe feature
 */
struct drm_msm_mdnie {
	__u64 flags;
	__u32 param[AIQE_MDNIE_PARAM_LEN];
};

/**
 * struct drm_msm_mdnie_art - mDNIe ART feature structure
 * @flags - Setting flags for mDNIe ART feature
 * @param - mDNIe ART parameter
 */
struct drm_msm_mdnie_art {
	__u64 flags;
	__u32 param;
};

/**
 * struct drm_msm_mdnie_art_done - mDNIe ART INTR structure
 * @art_done - mDNIe ART done parameter
 */
struct drm_msm_mdnie_art_done {
	__u32 art_done;
};

#define AIQE_COPR_PARAM_LEN 17
/**
 * struct drm_msm_copr - COPR feature structure
 * @flags - Setting flags for COPR feature
 * @param - Parameters for COPR feature
 */
struct drm_msm_copr {
	__u64 flags;
	__u32 param[AIQE_COPR_PARAM_LEN];
};

#define AIQE_COPR_STATUS_LEN 10
/**
 * struct drm_msm_copr_status - COPR read only status structure
 * @status - Parameters for COPR statistics read registers
 */
struct drm_msm_copr_status {
	__u32 status[AIQE_COPR_STATUS_LEN];
};

#endif /* _MSM_DRM_AIQE_H_ */
