ENABLE_EVA_KERNEL := true
ifeq ($(TARGET_KERNEL_DLKM_DISABLE), true)
ifneq ($(TARGET_KERNEL_DLKM_EVA_OVERRIDE), true)
ENABLE_EVA_KERNEL := false
endif
endif
ifeq ($(TARGET_BOARD_PLATFORM),pineapple)
ENABLE_EVA_KERNEL := false
endif
ifeq ($(ENABLE_EVA_KERNEL), true)
PRODUCT_PACKAGES += msm-eva.ko
endif
