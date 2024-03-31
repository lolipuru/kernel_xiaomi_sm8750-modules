// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#include <linux/elf.h>
#include <linux/ipc_logging.h>
#include <linux/soc/qcom/smem.h>
#include <soc/qcom/qcom_ramdump.h>
#include "ipa_elf_dump.h"



/* For Pakala and Lanai, the minidump id for modem is 3. Need to change for other targets */
#define minidump_id 3


static struct mutex region_list_mutex;
char *dmesg_buf;
char *ipc_buf;
static struct elf_ssr_driver_dump_entry
dump_entry_list[MAX_ELF_REGIONS];

static size_t num_of_regions_registered;


static void ipa_host_ramdump_dev_release(struct device *dev)
{
	IPADBG("free host ramdump device\n");
	kfree(dev);
}

/* Helper functions to check if minidump enabled, to help with
 * fetching and browsing through ipc logs and dmesg logs
 */
bool ipa_minidump_enabled(void)
{
	struct minidump_subsystem *subsystem;
	struct minidump_global_toc *toc;
	int ret = true;

	IPADBG("Checking if minidump enabled\n");
	/* Get Global minidump ToC*/
	toc = qcom_smem_get(QCOM_SMEM_HOST_ANY, SBL_MINIDUMP_SMEM_ID, NULL);

	/* check if global table pointer exists and init is set */
	if (IS_ERR(toc) || !toc->status) {
		IPAERR("Minidump TOC not found in SMEM\n");
		ret = false;
		goto stop;
	}

	/* Get subsystem table of contents using the minidump id */
	subsystem = &toc->subsystems[minidump_id];

	/**
	 * Collect minidump if SS ToC is valid and segment table
	 * is initialized in memory and encryption status is set.
	 */
	IPADBG("baseptr: %llu, status: %d, enabled : %d, equal: %d\n",
			subsystem->regions_baseptr, le32_to_cpu(subsystem->status),
			le32_to_cpu(subsystem->enabled), le32_to_cpu(subsystem->enabled)
			 == MD_SS_ENABLED);

	if (subsystem->regions_baseptr == 0 ||
		le32_to_cpu(subsystem->status) != 1 ||
		le32_to_cpu(subsystem->enabled) != MD_SS_ENABLED) {
		return false;
	}

stop:
	return ret;
}

struct ipc_log_page *get_next_page(struct ipc_log_context *ilctxt,
							struct ipc_log_page *cur_pg)
{
	struct ipc_log_page_header *p_pghdr;
	struct ipc_log_page *pg = NULL;

	if (!ilctxt || !cur_pg)
		return NULL;

	if (ilctxt->last_page == cur_pg)
		return NULL;

	p_pghdr = list_first_entry(&cur_pg->hdr.list,
			struct ipc_log_page_header, list);
	pg = container_of(p_pghdr, struct ipc_log_page, hdr);

	return pg;
}

int retrieve_ipc_logs(int buf_size, char *buffer, void *ctxt)
{
	size_t len_out;

	len_out = ipc_log_extract(ctxt, buffer, buf_size);
	if (len_out > 0) {
		IPADBG("Successfully got ipc logs len: %zu\n", len_out);
		return len_out;
	}
	IPAERR("ipc log failed.  No logs\n");
	return -1;
}

int retrieve_dmesg_logs(int buf_size, char *buffer)
{
	struct kmsg_dump_iter k_iter;
	size_t len_out;

	k_iter.cur_seq = 0;
	k_iter.next_seq = -1;
	if (kmsg_dump_get_buffer(&k_iter, false, buffer, buf_size, &len_out)) {
		IPADBG("Successfully got kmsg len: %zu\n", len_out);
		return len_out;
	}
	IPAERR("kmsg_get_buffer failed, no logs\n");
	return -1;
}

/* The IPA ELF SSR logic, which will facilitate stringing of all
 * the buffers we need to be dumped, so that they can be given to
 * the qcom_elf_dump API
 */
int ipa_ssr_driver_dump_init(void)
{
	mutex_init(&region_list_mutex);
	num_of_regions_registered = 0;
	dmesg_buf = NULL;
	ipc_buf = NULL;
	memset(dump_entry_list, 0, sizeof(dump_entry_list));
	return 0;
}

int ipa_ssr_driver_dump_deinit(void)
{
	mutex_destroy(&region_list_mutex);

	if (num_of_regions_registered > 0)
		IPADBG("deiniting with regions still registered");
	num_of_regions_registered = 0;
	return 0;
}

static struct elf_ssr_driver_dump_entry *
ipa_ssr_driver_dump_find_next_free_entry(void)
{
	int i;

	for (i = 0; i < MAX_ELF_REGIONS; i++) {
		if (!dump_entry_list[i].buffer_pointer)
			return &dump_entry_list[i];
	}
	return NULL;
}

static struct elf_ssr_driver_dump_entry *
ipa_ssr_driver_dump_find_entry_by_name(char *region_name)
{
	int i;

	for (i = 0; i < MAX_ELF_REGIONS; i++) {
		if (!strcmp(dump_entry_list[i].region_name, region_name) &&
				dump_entry_list[i].buffer_pointer) {
			return &dump_entry_list[i];
		}
	}

	return NULL;
}

int ipa_ssr_driver_dump_register_region(char *region_name,
					void *region_buffer, size_t region_size)
{
	int status = 0;
	struct elf_ssr_driver_dump_entry *entry;

	if (!region_buffer || !region_name) {
		IPAERR("null region pointer or region_name");
		return -EFAULT;
	}
	mutex_lock(&region_list_mutex);

	entry = ipa_ssr_driver_dump_find_entry_by_name(region_name);
	if (entry) {
		IPAERR("duplicate registration of %s", region_name);
		status = -EFAULT;
		goto ret;
	}

	entry = ipa_ssr_driver_dump_find_next_free_entry();
	if (!entry) {
		IPAERR("too many entries: %zu, cannot insert %s",
				num_of_regions_registered, region_name);
		status = -EFAULT;
		goto ret;
	}

	entry->buffer_pointer = region_buffer;
	entry->buffer_size = region_size;
	if (strcmp("ipc_logs", region_name) == 0)
		entry->buffer_size = sizeof(struct ipc_log_context);
	strscpy(entry->region_name, region_name, sizeof(entry->region_name));
	num_of_regions_registered++;

ret:
	mutex_unlock(&region_list_mutex);
	return status;
}

int ipa_ssr_driver_dump_unregister_region(char *region_name)
{
	int status = 0;
	struct elf_ssr_driver_dump_entry *entry;

	if (!region_name) {
		IPAERR("null region_name");
		return -EFAULT;
	}

	mutex_lock(&region_list_mutex);

	entry = ipa_ssr_driver_dump_find_entry_by_name(region_name);
	if (!entry) {
		IPAERR("couldn't find entry: %s", region_name);
		status = -EFAULT;
		goto ret;
	}

	entry->buffer_pointer = NULL;
	num_of_regions_registered--;

ret:
	mutex_unlock(&region_list_mutex);
	return status;
}

int ipa_ssr_driver_dump_retrieve_regions(struct elf_ssr_driver_dump_entry *
						input_array, size_t *num_entries_loaded)
{
	int status = 0;
	int i, len_out;
	int input_index = 0;
	int dmesg_buffer_size = DMESG_BUF_SIZE;
	int ipc_buffer_size = IPC_BUF_SIZE;
	bool ipc_done = false;

	if (!input_array || !num_entries_loaded) {
		IPAERR("null input_array or num_entries_loaded");
		goto fail;
	}

	mutex_lock(&region_list_mutex);
	for (i = 0; i < MAX_ELF_REGIONS; i++) {
		if (dump_entry_list[i].buffer_pointer) {
			memcpy(&input_array[input_index],
					&dump_entry_list[i],
					sizeof(dump_entry_list[i]));
			if (strcmp("ipc_logs", input_array[input_index].region_name) == 0
			 && !ipc_done) {
				/* Found the ipc context pointer.
				 * Extract IPC logs from this. And register the
				 * extracted buffer too.
				 */
				ipc_buf = kmalloc(ipc_buffer_size, GFP_KERNEL);
				if (ipc_buf) {
					len_out = retrieve_ipc_logs(ipc_buffer_size, ipc_buf,
					 input_array[input_index].buffer_pointer);
					if (len_out > 0) {
						input_index++;
						IPADBG("retrieved ipc logs. len out: %d\n",
						 len_out);
						input_array[input_index].buffer_pointer = ipc_buf;
						input_array[input_index].buffer_size = len_out;
						strscpy(input_array[input_index].region_name,
						 "ipc_logs", 11);
						input_array[input_index].entry_num = 2;
						ipc_done = true;
					} else {
						IPAERR("Didn't get any ipc logs len_out %d\n",
						 len_out);
					}
				} else {
					IPAERR("Could not allocate buffer for ipc logs\n");
				}
			}
			input_index++;
		}
	}
	dmesg_buf = kmalloc(dmesg_buffer_size, GFP_KERNEL);
	if (dmesg_buf) {
		len_out = retrieve_dmesg_logs(dmesg_buffer_size, dmesg_buf);
		if (len_out > 0) {
			if (input_index < MAX_ELF_REGIONS) {
				input_array[input_index].buffer_pointer = dmesg_buf;
				input_array[input_index].buffer_size = len_out;
				strscpy(input_array[input_index].region_name,
					 "dmesg_logs", 11);
				input_array[input_index++].entry_num = 2;
			} else {
				IPAERR("unable to register dmesg, full length reached %d\n",
				 input_index);
				goto fail;
			}
		}
	} else {
		IPAERR("Could not allocate buffer for dmesg logs\n");
	}

	IPADBG("input index %d, no of regions registered:%zu\n",
		 input_index, num_of_regions_registered);
	/* 2 here to account for extra ipc and dmesg log
	 * buffers that we allocate here
	 */
	if (input_index - num_of_regions_registered > 2) {
		IPAERR("num entries mismatch index:%d num reg registered:%zu",
				input_index, num_of_regions_registered);
		status = -EFAULT;
		goto fail;
	}
	*num_entries_loaded = input_index;

	mutex_unlock(&region_list_mutex);
	return status;

fail:
	mutex_unlock(&region_list_mutex);
	return status;
}


int ipa_do_host_ramdump(struct elf_ssr_driver_dump_entry *ssr_entry,
						size_t num_entries_loaded)
{
	struct ipa_qcom_dump_segment *seg;
	struct ipa_host_dump_meta_info *meta_info;
	struct list_head head;
	int dev_ret = 0;
	struct device *new_device;
	static const char * const ipa_str[] = {
		[IPA_HOST_DUMP_IPA_CTX] = "ipa_ctx",
		[IPA_HOST_DUMP_IPC_LOGS] = "ipc_logs",
		[IPA_HOST_DUMP_DMESG_LOGS] = "dmesg_logs",
	};
	int i;
	int ret = 0;
	enum ipa_host_dump_type j;

	meta_info = kcalloc(1, sizeof(struct ipa_host_dump_meta_info), GFP_KERNEL);
	if (!meta_info) {
		IPAERR("Failed to alloc memory for meta info\n");
		return -ENOMEM;
	}
	memset(meta_info, 0, sizeof(struct ipa_host_dump_meta_info));
	IPADBG("In host ramdump\n");
	new_device = kcalloc(1, sizeof(*new_device), GFP_KERNEL);
	if (!new_device) {
		IPAERR("Failed to alloc device mem\n");
		return -ENOMEM;
	}

	new_device->release = ipa_host_ramdump_dev_release;
	device_initialize(new_device);
	dev_set_name(new_device, "ipa_driver");
	dev_ret = device_add(new_device);
	if (dev_ret) {
		IPAERR("Failed to add new device\n");
		goto put_device;
	}
	IPADBG("new device added\n");
	INIT_LIST_HEAD(&head);
	for (i = 0; i < num_entries_loaded; i++) {
		meta_info->entry[i].type = -1;
		seg = kcalloc(1, sizeof(*seg), GFP_KERNEL);
		if (!seg) {
			seg = kcalloc(1, sizeof(*seg), GFP_KERNEL);
			if (!seg) {
				IPAERR("Failed to alloc seg entry %d\n", i);
				goto skip_host_dump;
			}
		}
		seg->va = ssr_entry[i].buffer_pointer;
		seg->da = (dma_addr_t)ssr_entry[i].buffer_pointer;
		seg->size = ssr_entry[i].buffer_size;

		for (j = 0; j < IPA_HOST_DUMP_MAX; j++) {
			if (strcmp(ssr_entry[i].region_name, ipa_str[j]) == 0)
				meta_info->entry[i].type = j;
		}
		meta_info->entry[i].entry_start = i + 1;
		meta_info->entry[i].entry_num = ssr_entry[i].entry_num;
		IPADBG("meta_info.entry[%d].type:%d, size:%zu, entry_num %d\n"
			, i, meta_info->entry[i].type, ssr_entry[i].buffer_size,
		 meta_info->entry[i].entry_num);
		list_add_tail(&seg->node, &head);
	}

	seg = kcalloc(1, sizeof(*seg), GFP_KERNEL);
	IPADBG("Segment list prepared\n");

	if (!seg) {
		IPAERR("Failed to allocate mem for host dump seg\n");
		goto skip_host_dump;
	}

	meta_info->magic = IPA_RAMDUMP_MAGIC;
	meta_info->version = IPA_RAMDUMP_VERSION;
	meta_info->chipset = 3728;
	meta_info->total_entries = num_entries_loaded;
	seg->va = meta_info;
	seg->da = (dma_addr_t)meta_info;
	seg->size = sizeof(*meta_info);
	list_add(&seg->node, &head);
	IPADBG("before elf dump\n");
	ret = qcom_elf_dump(&head, new_device, ELF_CLASS);
	IPADBG("after elf dump\n");
skip_host_dump:
	while (!list_empty(&head)) {
		seg = list_first_entry(&head, struct ipa_qcom_dump_segment, node);
		list_del(&seg->node);
		kfree(seg);
	}
	kfree(meta_info);
	device_del(new_device);
put_device:
	put_device(new_device);
	kfree(new_device);
	IPADBG("host ramdump result %d\n", ret);
	return ret;
}


int ipa_retrieve_and_dump(void)
{
	size_t num_entries_loaded;
	struct elf_ssr_driver_dump_entry *ssr_entry;
	int status = 0;

	ssr_entry = kmalloc(((num_of_regions_registered+1)*
	sizeof(struct elf_ssr_driver_dump_entry)), GFP_KERNEL);
	if (!ssr_entry) {
		IPAERR("Memory not allocated\n");
		status = -1;
		goto ret;
	}
	IPADBG("ELF DUMP\n");
	if (ipa_ssr_driver_dump_retrieve_regions(ssr_entry, &num_entries_loaded)) {
		IPADBG("Error retrieving the regions\n");
		status = -1;
		goto ret;
	}
	IPADBG("ELF regions retrieved %zu\n", num_entries_loaded);
	ipa_do_host_ramdump(ssr_entry, num_entries_loaded);
	status = 0;

ret:
	kfree(ipc_buf);
	kfree(dmesg_buf);
	kfree(ssr_entry);
	return status;
}
