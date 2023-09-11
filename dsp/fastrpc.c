// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (c) 2018, Linaro Limited
 * Copyright (c) 2022-2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#include <linux/completion.h>
#include <linux/device.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-resv.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of.h>
#include <linux/sort.h>
#include <linux/of_platform.h>
#include <linux/iommu.h>
#include <linux/msm_dma_iommu_mapping.h>
#include <linux/genalloc.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/qcom_scm.h>
#include <linux/pm_qos.h>
#include "../include/uapi/misc/fastrpc.h"
#include <linux/of_reserved_mem.h>
#include <linux/cred.h>
#include <linux/arch_topology.h>
#include <linux/soc/qcom/pdr.h>
#include "fastrpc_shared.h"

static inline int64_t getnstimediff(struct timespec64 *start)
{
	int64_t ns;
	struct timespec64 ts, b;

	ktime_get_real_ts64(&ts);
	b = timespec64_sub(ts, *start);
	ns = timespec64_to_ns(&b);
	return ns;
}

static void fastrpc_free_map(struct kref *ref)
{
	struct fastrpc_map *map;

	map = container_of(ref, struct fastrpc_map, refcount);

	if (map->table) {
		if (map->attr & FASTRPC_ATTR_SECUREMAP) {
			struct qcom_scm_vmperm perm;
			int vmid = map->fl->cctx->vmperms[0].vmid;
			u64 src_perms = BIT(QCOM_SCM_VMID_HLOS) | BIT(vmid);
			int err = 0;

			perm.vmid = QCOM_SCM_VMID_HLOS;
			perm.perm = QCOM_SCM_PERM_RWX;
			err = qcom_scm_assign_mem(map->phys, map->size,
				&src_perms, &perm, 1);
			if (err) {
				dev_err(map->fl->sctx->dev, "Failed to assign memory phys 0x%llx size 0x%llx err %d",
						map->phys, map->size, err);
				return;
			}
		}
		dma_buf_unmap_attachment(map->attach, map->table,
					 DMA_BIDIRECTIONAL);
		dma_buf_detach(map->buf, map->attach);
		dma_buf_put(map->buf);
	}

	if (map->fl) {
		spin_lock(&map->fl->lock);
		list_del(&map->node);
		spin_unlock(&map->fl->lock);
		map->fl = NULL;
	}

	kfree(map);
}

static void fastrpc_map_put(struct fastrpc_map *map)
{
	if (map)
		kref_put(&map->refcount, fastrpc_free_map);
}

static int fastrpc_map_get(struct fastrpc_map *map)
{
	if (!map)
		return -ENOENT;

	return kref_get_unless_zero(&map->refcount) ? 0 : -ENOENT;
}


static int fastrpc_map_lookup(struct fastrpc_user *fl, int fd,
			    u64 va, u64 len,
			    struct fastrpc_map **ppmap, bool take_ref)
{
	struct fastrpc_session_ctx *sess = fl->sctx;
	struct fastrpc_map *map = NULL;
	int ret = -ENOENT;

	spin_lock(&fl->lock);
	list_for_each_entry(map, &fl->maps, node) {
		if (map->fd != fd || va < (u64)map->va || va + len > (u64)map->va + map->size)
			continue;

		if (take_ref) {
			ret = fastrpc_map_get(map);
			if (ret) {
				dev_dbg(sess->dev, "%s: Failed to get map fd=%d ret=%d\n",
					__func__, fd, ret);
				break;
			}
		}

		*ppmap = map;
		ret = 0;
		break;
	}
	spin_unlock(&fl->lock);

	return ret;
}

static bool fastrpc_get_persistent_buf(struct fastrpc_user *fl,
		size_t size, int buf_type, struct fastrpc_buf **obuf)
{
	u32 i = 0;
	bool found = false;
	struct fastrpc_buf *buf = NULL;

	spin_lock(&fl->lock);
	/*
	 * Persistent header buffer can be used only if
	 * metadata length is less than 1 page size.
	 */
	if (!fl->num_pers_hdrs || buf_type != METADATA_BUF || size > PAGE_SIZE) {
		spin_unlock(&fl->lock);
		return found;
	}

	for (i = 0; i < fl->num_pers_hdrs; i++) {
		buf = &fl->hdr_bufs[i];
		/* If buffer not in use, then assign it for requested alloc */
		if (!buf->in_use) {
			buf->in_use = true;
			*obuf = buf;
			found = true;
			break;
		}
	}
	spin_unlock(&fl->lock);
	return found;
}

static void __fastrpc_buf_free(struct fastrpc_buf *buf)
{
	dma_free_coherent(buf->dev, buf->size, buf->virt,
			  FASTRPC_PHYS(buf->phys));
	kfree(buf);
}

static void fastrpc_cached_buf_list_add(struct fastrpc_buf *buf)
{
	struct fastrpc_user *fl = buf->fl;

	if (buf->size < FASTRPC_MAX_CACHE_BUF_SIZE) {
		spin_lock(&fl->lock);
		if (fl->num_cached_buf > FASTRPC_MAX_CACHED_BUFS) {
			spin_unlock(&fl->lock);
			goto skip_buf_cache;
		}

		list_add_tail(&buf->node, &fl->cached_bufs);
		fl->num_cached_buf++;
		buf->type = -1;
		spin_unlock(&fl->lock);
		return;
	}

skip_buf_cache:
	__fastrpc_buf_free(buf);
	return;
}

static void fastrpc_buf_free(struct fastrpc_buf *buf, bool cache)
{
	struct fastrpc_user *fl = buf->fl;

	if (buf->in_use) {
		/* Don't free persistent header buf. Just mark as available */
		spin_lock(&fl->lock);
		buf->in_use = false;
		spin_unlock(&fl->lock);
		return;
	}
	if (cache)
		fastrpc_cached_buf_list_add(buf);
	else
		__fastrpc_buf_free(buf);
}

static inline bool fastrpc_get_cached_buf(struct fastrpc_user *fl,
		size_t size, int buf_type, struct fastrpc_buf **obuf)
{
	bool found = false;
	struct fastrpc_buf *buf, *n, *cbuf = NULL;

	if (buf_type == USER_BUF)
		return found;

	/* find the smallest buffer that fits in the cache */
	spin_lock(&fl->lock);
	list_for_each_entry_safe(buf, n, &fl->cached_bufs, node) {
		if (buf->size >= size && (!cbuf || cbuf->size > buf->size))
			cbuf = buf;
	}
	if (cbuf) {
		list_del_init(&cbuf->node);
		fl->num_cached_buf--;
	}
	spin_unlock(&fl->lock);
	if (cbuf) {
		cbuf->type = buf_type;
		*obuf = cbuf;
		found = true;
	}

	return found;
}

static void fastrpc_cached_buf_list_free(struct fastrpc_user *fl)
{
	struct fastrpc_buf *buf, *n, *free;

	do {
		free = NULL;
		spin_lock(&fl->lock);
		list_for_each_entry_safe(buf, n, &fl->cached_bufs, node) {
			list_del(&buf->node);
			fl->num_cached_buf--;
			free = buf;
			break;
		}
		spin_unlock(&fl->lock);
		if (free)
			fastrpc_buf_free(free, false);
	} while (free);
}

static int __fastrpc_buf_alloc(struct fastrpc_user *fl, struct device *dev,
			     u64 size, struct fastrpc_buf **obuf, u32 buf_type)
{
	struct fastrpc_buf *buf;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	INIT_LIST_HEAD(&buf->attachments);
	INIT_LIST_HEAD(&buf->node);
	mutex_init(&buf->lock);

	buf->fl = fl;
	buf->virt = NULL;
	buf->phys = 0;
	buf->size = size;
	buf->dev = dev;
	buf->raddr = 0;
	buf->type = buf_type;

	buf->virt = dma_alloc_coherent(dev, buf->size, (dma_addr_t *)&buf->phys,
				       GFP_KERNEL);
	if (!buf->virt) {
		mutex_destroy(&buf->lock);
		kfree(buf);
		return -ENOMEM;
	}

	*obuf = buf;

	return 0;
}

static int fastrpc_buf_alloc(struct fastrpc_user *fl, struct device *dev,
			     u64 size, u32 buf_type, struct fastrpc_buf **obuf)
{
	int ret;
	struct fastrpc_buf *buf;

	if (fastrpc_get_persistent_buf(fl, size, buf_type, obuf))
		return 0;
	if (fastrpc_get_cached_buf(fl, size, buf_type, obuf))
		return 0;
	ret = __fastrpc_buf_alloc(fl, dev, size, obuf, buf_type);
	if (ret == -ENOMEM) {
		fastrpc_cached_buf_list_free(fl);
		ret = __fastrpc_buf_alloc(fl, dev, size, obuf, buf_type);
		if (ret)
			return ret;
	}
	buf = *obuf;

	if (fl->sctx && fl->sctx->sid)
		buf->phys += ((u64)fl->sctx->sid << 32);

	return 0;
}

static int fastrpc_remote_heap_alloc(struct fastrpc_user *fl, struct device *dev,
				     u64 size, int buf_type, struct fastrpc_buf **obuf)
{
	struct device *rdev = fl->cctx->dev;

	return __fastrpc_buf_alloc(fl, rdev, size, obuf, buf_type);
}

static void fastrpc_channel_ctx_free(struct kref *ref)
{
	struct fastrpc_channel_ctx *cctx;

	cctx = container_of(ref, struct fastrpc_channel_ctx, refcount);

	kfree(cctx);
}

static void fastrpc_channel_ctx_get(struct fastrpc_channel_ctx *cctx)
{
	kref_get(&cctx->refcount);
}

void fastrpc_channel_ctx_put(struct fastrpc_channel_ctx *cctx)
{
	kref_put(&cctx->refcount, fastrpc_channel_ctx_free);
}

static void fastrpc_context_free(struct kref *ref)
{
	struct fastrpc_invoke_ctx *ctx;
	struct fastrpc_channel_ctx *cctx;
	unsigned long flags;
	int i;

	ctx = container_of(ref, struct fastrpc_invoke_ctx, refcount);
	cctx = ctx->cctx;

	for (i = 0; i < ctx->nbufs; i++)
		fastrpc_map_put(ctx->maps[i]);

	if (ctx->buf)
		fastrpc_buf_free(ctx->buf, true);

	if (ctx->fl->profile)
		kfree(ctx->perf);

	spin_lock_irqsave(&cctx->lock, flags);
	idr_remove(&cctx->ctx_idr, ctx->ctxid >> 4);
	spin_unlock_irqrestore(&cctx->lock, flags);

	kfree(ctx->maps);
	kfree(ctx->olaps);
	kfree(ctx);

	fastrpc_channel_ctx_put(cctx);
}

// static void fastrpc_context_get(struct fastrpc_invoke_ctx *ctx)
// {
	// kref_get(&ctx->refcount);
// }

static void fastrpc_context_put(struct fastrpc_invoke_ctx *ctx)
{
	kref_put(&ctx->refcount, fastrpc_context_free);
}

// static void fastrpc_context_put_wq(struct work_struct *work)
// {
	// struct fastrpc_invoke_ctx *ctx =
			// container_of(work, struct fastrpc_invoke_ctx, put_work);

	// fastrpc_context_put(ctx);
// }

#define CMP(aa, bb) ((aa) == (bb) ? 0 : (aa) < (bb) ? -1 : 1)

static u32 sorted_lists_intersection(u32 *listA,
		u32 lenA, u32 *listB, u32 lenB)
{
	u32 i = 0, j = 0;

	while (i < lenA && j < lenB) {
		if (listA[i] < listB[j])
			i++;
		else if (listA[i] > listB[j])
			j++;
		else
			return listA[i];
	}
	return 0;
}

static int uint_cmp_func(const void *p1, const void *p2)
{
	u32 a1 = *((u32 *)p1);
	u32 a2 = *((u32 *)p2);

	return CMP(a1, a2);
}

static int olaps_cmp(const void *a, const void *b)
{
	struct fastrpc_buf_overlap *pa = (struct fastrpc_buf_overlap *)a;
	struct fastrpc_buf_overlap *pb = (struct fastrpc_buf_overlap *)b;
	/* sort with lowest starting buffer first */
	int st = CMP(pa->start, pb->start);
	/* sort with highest ending buffer first */
	int ed = CMP(pb->end, pa->end);

	return st == 0 ? ed : st;
}

static void fastrpc_get_buff_overlaps(struct fastrpc_invoke_ctx *ctx)
{
	u64 max_end = 0;
	int i;

	for (i = 0; i < ctx->nbufs; ++i) {
		ctx->olaps[i].start = ctx->args[i].ptr;
		ctx->olaps[i].end = ctx->olaps[i].start + ctx->args[i].length;
		ctx->olaps[i].raix = i;
	}

	sort(ctx->olaps, ctx->nbufs, sizeof(*ctx->olaps), olaps_cmp, NULL);

	for (i = 0; i < ctx->nbufs; ++i) {
		/* Falling inside previous range */
		if (ctx->olaps[i].start < max_end) {
			ctx->olaps[i].mstart = max_end;
			ctx->olaps[i].mend = ctx->olaps[i].end;
			ctx->olaps[i].offset = max_end - ctx->olaps[i].start;

			if (ctx->olaps[i].end > max_end) {
				max_end = ctx->olaps[i].end;
			} else {
				ctx->olaps[i].mend = 0;
				ctx->olaps[i].mstart = 0;
			}

		} else  {
			ctx->olaps[i].mend = ctx->olaps[i].end;
			ctx->olaps[i].mstart = ctx->olaps[i].start;
			ctx->olaps[i].offset = 0;
			max_end = ctx->olaps[i].end;
		}
	}
}

static struct fastrpc_invoke_ctx *fastrpc_context_alloc(
			struct fastrpc_user *user, u32 kernel, u32 sc,
			struct fastrpc_enhanced_invoke *invoke)
{
	struct fastrpc_channel_ctx *cctx = user->cctx;
	struct fastrpc_invoke_ctx *ctx = NULL;
	unsigned long flags;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&ctx->node);
	ctx->fl = user;
	ctx->nscalars = REMOTE_SCALARS_LENGTH(sc);
	ctx->nbufs = REMOTE_SCALARS_INBUFS(sc) +
		     REMOTE_SCALARS_OUTBUFS(sc);

	if (ctx->nscalars) {
		ctx->maps = kcalloc(ctx->nscalars,
				    sizeof(*ctx->maps), GFP_KERNEL);
		if (!ctx->maps) {
			kfree(ctx);
			return ERR_PTR(-ENOMEM);
		}
		ctx->olaps = kcalloc(ctx->nscalars,
				    sizeof(*ctx->olaps), GFP_KERNEL);
		if (!ctx->olaps) {
			kfree(ctx->maps);
			kfree(ctx);
			return ERR_PTR(-ENOMEM);
		}
		ctx->args = (struct fastrpc_invoke_args *)invoke->inv.args;
		fastrpc_get_buff_overlaps(ctx);
	}

	/* Released in fastrpc_context_put() */
	fastrpc_channel_ctx_get(cctx);

	ctx->crc = (u32 *)(uintptr_t)invoke->crc;
	ctx->perf_dsp = (u64 *)(uintptr_t)invoke->perf_dsp;
	ctx->perf_kernel = (u64 *)(uintptr_t)invoke->perf_kernel;
	if (ctx->fl->profile) {
		ctx->perf = kzalloc(sizeof(*(ctx->perf)), GFP_KERNEL);
		if (!ctx->perf)
			return ERR_PTR(-ENOMEM);
		ctx->perf->tid = ctx->fl->tgid;
	}
	ctx->sc = sc;
	ctx->retval = -1;
	ctx->pid = current->pid;
	ctx->tgid = user->tgid;
	ctx->cctx = cctx;
	ctx->rsp_flags = NORMAL_RESPONSE;
	ctx->is_work_done = false;
	init_completion(&ctx->work);
	// INIT_WORK(&ctx->put_work, fastrpc_context_put_wq);

	spin_lock(&user->lock);
	list_add_tail(&ctx->node, &user->pending);
	spin_unlock(&user->lock);

	spin_lock_irqsave(&cctx->lock, flags);
	ret = idr_alloc_cyclic(&cctx->ctx_idr, ctx, 1,
			       FASTRPC_CTX_MAX, GFP_ATOMIC);
	if (ret < 0) {
		spin_unlock_irqrestore(&cctx->lock, flags);
		goto err_idr;
	}
	ctx->ctxid = ret << 4;
	spin_unlock_irqrestore(&cctx->lock, flags);

	kref_init(&ctx->refcount);

	return ctx;
err_idr:
	spin_lock(&user->lock);
	list_del(&ctx->node);
	spin_unlock(&user->lock);
	fastrpc_channel_ctx_put(cctx);
	kfree(ctx->maps);
	kfree(ctx->olaps);
	kfree(ctx);

	return ERR_PTR(ret);
}

static struct fastrpc_invoke_ctx *fastrpc_context_restore_interrupted(
			struct fastrpc_user *fl, struct fastrpc_invoke *inv)
{
	struct fastrpc_invoke_ctx *ctx = NULL, *ictx = NULL, *n;

	spin_lock(&fl->lock);
	list_for_each_entry_safe(ictx, n, &fl->interrupted, node) {
		if (ictx->pid == current->pid) {
			if (inv->sc != ictx->sc || ictx->fl != fl) {
				dev_err(ictx->fl->sctx->dev,
					"interrupted sc (0x%x) or fl (%pK) does not match with invoke sc (0x%x) or fl (%pK)\n",
					ictx->sc, ictx->fl, inv->sc, fl);
				spin_unlock(&fl->lock);
				return ERR_PTR(-EINVAL);
			} else {
				ctx = ictx;
				list_del(&ctx->node);
				list_add_tail(&ctx->node, &fl->pending);
			}
			break;
		}
	}
	spin_unlock(&fl->lock);
	return ctx;
}

static void fastrpc_context_save_interrupted(
			struct fastrpc_invoke_ctx *ctx)
{
	spin_lock(&ctx->fl->lock);
	list_del(&ctx->node);
	list_add_tail(&ctx->node, &ctx->fl->interrupted);
	spin_unlock(&ctx->fl->lock);
}

static struct sg_table *
fastrpc_map_dma_buf(struct dma_buf_attachment *attachment,
		    enum dma_data_direction dir)
{
	struct fastrpc_dma_buf_attachment *a = attachment->priv;
	struct sg_table *table;
	int ret;

	table = &a->sgt;

	ret = dma_map_sgtable(attachment->dev, table, dir, 0);
	if (ret)
		table = ERR_PTR(ret);
	return table;
}

static void fastrpc_unmap_dma_buf(struct dma_buf_attachment *attach,
				  struct sg_table *table,
				  enum dma_data_direction dir)
{
	dma_unmap_sgtable(attach->dev, table, dir, 0);
}

static void fastrpc_release(struct dma_buf *dmabuf)
{
	struct fastrpc_buf *buffer = dmabuf->priv;

	fastrpc_buf_free(buffer, false);
}

static int fastrpc_dma_buf_attach(struct dma_buf *dmabuf,
				  struct dma_buf_attachment *attachment)
{
	struct fastrpc_dma_buf_attachment *a;
	struct fastrpc_buf *buffer = dmabuf->priv;
	int ret;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	ret = dma_get_sgtable(buffer->dev, &a->sgt, buffer->virt,
			      FASTRPC_PHYS(buffer->phys), buffer->size);
	if (ret < 0) {
		dev_err(buffer->dev, "failed to get scatterlist from DMA API\n");
		kfree(a);
		return -EINVAL;
	}

	a->dev = attachment->dev;
	INIT_LIST_HEAD(&a->node);
	attachment->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->node, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void fastrpc_dma_buf_detatch(struct dma_buf *dmabuf,
				    struct dma_buf_attachment *attachment)
{
	struct fastrpc_dma_buf_attachment *a = attachment->priv;
	struct fastrpc_buf *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->node);
	mutex_unlock(&buffer->lock);
	sg_free_table(&a->sgt);
	kfree(a);
}

static int fastrpc_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
{
	struct fastrpc_buf *buf = dmabuf->priv;

	iosys_map_set_vaddr(map, buf->virt);

	return 0;
}

static int fastrpc_mmap(struct dma_buf *dmabuf,
			struct vm_area_struct *vma)
{
	struct fastrpc_buf *buf = dmabuf->priv;
	size_t size = vma->vm_end - vma->vm_start;

	return dma_mmap_coherent(buf->dev, vma, buf->virt,
				 FASTRPC_PHYS(buf->phys), size);
}

static const struct dma_buf_ops fastrpc_dma_buf_ops = {
	.attach = fastrpc_dma_buf_attach,
	.detach = fastrpc_dma_buf_detatch,
	.map_dma_buf = fastrpc_map_dma_buf,
	.unmap_dma_buf = fastrpc_unmap_dma_buf,
	.mmap = fastrpc_mmap,
	.vmap = fastrpc_vmap,
	.release = fastrpc_release,
};

static void fastrpc_pm_awake(struct fastrpc_user *fl,
					u32 is_secure_channel)
{
	struct fastrpc_channel_ctx *cctx = fl->cctx;
	struct wakeup_source *wake_source = NULL;

	/*
	 * Vote with PM to abort any suspend in progress and
	 * keep system awake for specified timeout
	 */
	if (is_secure_channel)
		wake_source = cctx->wake_source_secure;
	else
		wake_source = cctx->wake_source;

	if (wake_source)
		pm_wakeup_ws_event(wake_source, fl->ws_timeout, true);
}

static void fastrpc_pm_relax(struct fastrpc_user *fl,
					u32 is_secure_channel)
{
	struct fastrpc_channel_ctx *cctx = fl->cctx;
	struct wakeup_source *wake_source = NULL;

	if (!fl->wake_enable)
		return;

	if (is_secure_channel)
		wake_source = cctx->wake_source_secure;
	else
		wake_source = cctx->wake_source;

	if (wake_source)
		__pm_relax(wake_source);
}

static int fastrpc_map_create(struct fastrpc_user *fl, int fd, u64 va,
			      u64 len, u32 attr, struct fastrpc_map **ppmap,
				  bool take_ref)
{
	struct fastrpc_session_ctx *sess = fl->sctx;
	struct fastrpc_map *map = NULL;
	struct scatterlist *sgl = NULL;
	struct sg_table *table;
	int err = 0, sgl_index = 0;

	if (!fastrpc_map_lookup(fl, fd, va, len, ppmap, take_ref))
		return 0;

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return -ENOMEM;

	INIT_LIST_HEAD(&map->node);
	kref_init(&map->refcount);

	map->fl = fl;
	map->fd = fd;
	map->buf = dma_buf_get(fd);
	if (IS_ERR(map->buf)) {
		err = PTR_ERR(map->buf);
		goto get_err;
	}

	map->attach = dma_buf_attach(map->buf, sess->dev);
	if (IS_ERR(map->attach)) {
		dev_err(sess->dev, "Failed to attach dmabuf\n");
		err = PTR_ERR(map->attach);
		goto attach_err;
	}

	table = dma_buf_map_attachment(map->attach, DMA_BIDIRECTIONAL);
	if (IS_ERR(table)) {
		err = PTR_ERR(table);
		goto map_err;
	}
	map->table = table;

	if (attr & FASTRPC_ATTR_SECUREMAP) {
		map->phys = sg_phys(map->table->sgl);
	} else {
		map->phys = sg_dma_address(map->table->sgl);
		map->phys += ((u64)fl->sctx->sid << 32);
	}
	for_each_sg(map->table->sgl, sgl, map->table->nents,
		sgl_index)
		map->size += sg_dma_len(sgl);
	map->va = sg_virt(map->table->sgl);
	map->len = len;

	if (attr & FASTRPC_ATTR_SECUREMAP) {
		/*
		 * If subsystem VMIDs are defined in DTSI, then do
		 * hyp_assign from HLOS to those VM(s)
		 */
		u64 src_perms = BIT(QCOM_SCM_VMID_HLOS);
		struct qcom_scm_vmperm dst_perms[2] = {0};

		dst_perms[0].vmid = QCOM_SCM_VMID_HLOS;
		dst_perms[0].perm = QCOM_SCM_PERM_RW;
		dst_perms[1].vmid = fl->cctx->vmperms[0].vmid;
		dst_perms[1].perm = QCOM_SCM_PERM_RWX;
		map->attr = attr;
		err = qcom_scm_assign_mem(map->phys, (u64)map->size, &src_perms, dst_perms, 2);
		if (err) {
			dev_err(sess->dev, "Failed to assign memory with phys 0x%llx size 0x%llx err %d",
					map->phys, map->size, err);
			goto map_err;
		}
	}
	spin_lock(&fl->lock);
	list_add_tail(&map->node, &fl->maps);
	spin_unlock(&fl->lock);
	*ppmap = map;

	return 0;

map_err:
	dma_buf_detach(map->buf, map->attach);
attach_err:
	dma_buf_put(map->buf);
get_err:
	fastrpc_map_put(map);

	return err;
}

/*
 * Fastrpc payload buffer with metadata looks like:
 *
 * >>>>>>  START of METADATA <<<<<<<<<
 * +---------------------------------+
 * |           Arguments             |
 * | type:(union fastrpc_remote_arg)|
 * |             (0 - N)             |
 * +---------------------------------+
 * |         Invoke Buffer list      |
 * | type:(struct fastrpc_invoke_buf)|
 * |           (0 - N)               |
 * +---------------------------------+
 * |         Page info list          |
 * | type:(struct fastrpc_phy_page)  |
 * |             (0 - N)             |
 * +---------------------------------+
 * |         Optional info           |
 * |(can be specific to SoC/Firmware)|
 * +---------------------------------+
 * >>>>>>>>  END of METADATA <<<<<<<<<
 * +---------------------------------+
 * |         Inline ARGS             |
 * |            (0-N)                |
 * +---------------------------------+
 */

static int fastrpc_get_meta_size(struct fastrpc_invoke_ctx *ctx)
{
	int size = 0;

	size = (sizeof(struct fastrpc_remote_buf) +
		sizeof(struct fastrpc_invoke_buf) +
		sizeof(struct fastrpc_phy_page)) * ctx->nscalars +
		sizeof(u64) * FASTRPC_MAX_FDLIST +
		sizeof(u32) * FASTRPC_MAX_CRCLIST +
		sizeof(u32) + sizeof(u64) * FASTRPC_DSP_PERF_LIST;

	return size;
}

static u64 fastrpc_get_payload_size(struct fastrpc_invoke_ctx *ctx, int metalen)
{
	u64 size = 0;
	int oix;

	size = ALIGN(metalen, FASTRPC_ALIGN);
	for (oix = 0; oix < ctx->nbufs; oix++) {
		int i = ctx->olaps[oix].raix;

		if (ctx->args[i].fd == 0 || ctx->args[i].fd == -1) {

			if (ctx->olaps[oix].offset == 0)
				size = ALIGN(size, FASTRPC_ALIGN);

			size += (ctx->olaps[oix].mend - ctx->olaps[oix].mstart);
		}
	}

	return size;
}

static int fastrpc_create_maps(struct fastrpc_invoke_ctx *ctx)
{
	struct device *dev = ctx->fl->sctx->dev;
	int i, err;

	for (i = 0; i < ctx->nscalars; ++i) {
		bool take_ref = true;

		if (ctx->args[i].fd == 0 || ctx->args[i].fd == -1 ||
		    ctx->args[i].length == 0)
			continue;

		if (i >= ctx->nbufs)
			take_ref = false;
		err = fastrpc_map_create(ctx->fl, ctx->args[i].fd, (u64)ctx->args[i].ptr,
			 ctx->args[i].length, ctx->args[i].attr, &ctx->maps[i], take_ref);
		if (err) {
			dev_err(dev, "Error Creating map %d\n", err);
			return -EINVAL;
		}

	}
	return 0;
}

static struct fastrpc_invoke_buf *fastrpc_invoke_buf_start(union fastrpc_remote_arg *pra, int len)
{
	return (struct fastrpc_invoke_buf *)(&pra[len]);
}

static struct fastrpc_phy_page *fastrpc_phy_page_start(struct fastrpc_invoke_buf *buf, int len)
{
	return (struct fastrpc_phy_page *)(&buf[len]);
}

static int fastrpc_get_args(u32 kernel, struct fastrpc_invoke_ctx *ctx)
{
	struct device *dev = ctx->fl->sctx->dev;
	union fastrpc_remote_arg *rpra;
	struct fastrpc_invoke_buf *list;
	struct fastrpc_phy_page *pages;
	int inbufs, i, oix, err = 0;
	u64 len, rlen, pkt_size;
	u64 pg_start, pg_end;
	u64 *perf_counter = NULL;
	uintptr_t args;
	int metalen;

	if (ctx->fl->profile)
		perf_counter = (u64 *)ctx->perf + PERF_COUNT;

	inbufs = REMOTE_SCALARS_INBUFS(ctx->sc);
	metalen = fastrpc_get_meta_size(ctx);
	pkt_size = fastrpc_get_payload_size(ctx, metalen);

	PERF(ctx->fl->profile, GET_COUNTER(perf_counter, PERF_MAP),
	err = fastrpc_create_maps(ctx);
	if (err)
		return err;
	PERF_END);

	ctx->msg_sz = pkt_size;

	err = fastrpc_buf_alloc(ctx->fl, dev, pkt_size, METADATA_BUF, &ctx->buf);
	if (err)
		return err;

	memset(ctx->buf->virt, 0, pkt_size);
	rpra = ctx->buf->virt;
	list = fastrpc_invoke_buf_start(rpra, ctx->nscalars);
	pages = fastrpc_phy_page_start(list, ctx->nscalars);
	args = (uintptr_t)ctx->buf->virt + metalen;
	rlen = pkt_size - metalen;
	ctx->rpra = rpra;

	for (oix = 0; oix < ctx->nbufs; ++oix) {
		int mlen;

		i = ctx->olaps[oix].raix;
		len = ctx->args[i].length;

		rpra[i].buf.pv = 0;
		rpra[i].buf.len = len;
		list[i].num = len ? 1 : 0;
		list[i].pgidx = i;

		if (!len)
			continue;

		if (ctx->maps[i]) {
			struct vm_area_struct *vma = NULL;
			PERF(ctx->fl->profile, GET_COUNTER(perf_counter, PERF_MAP),

			rpra[i].buf.pv = (u64) ctx->args[i].ptr;
			pages[i].addr = ctx->maps[i]->phys;

			if (!(ctx->maps[i]->attr & FASTRPC_ATTR_NOVA)) {
				mmap_read_lock(current->mm);
				vma = find_vma(current->mm, ctx->args[i].ptr);
				if (vma)
					pages[i].addr += ctx->args[i].ptr -
							 vma->vm_start;
				mmap_read_unlock(current->mm);
			}

			pg_start = (ctx->args[i].ptr & PAGE_MASK) >> PAGE_SHIFT;
			pg_end = ((ctx->args[i].ptr + len - 1) & PAGE_MASK) >>
				  PAGE_SHIFT;
			pages[i].size = (pg_end - pg_start + 1) * PAGE_SIZE;
			PERF_END);
		} else {
			PERF(ctx->fl->profile, GET_COUNTER(perf_counter, PERF_COPY),
			if (ctx->olaps[oix].offset == 0) {
				rlen -= ALIGN(args, FASTRPC_ALIGN) - args;
				args = ALIGN(args, FASTRPC_ALIGN);
			}

			mlen = ctx->olaps[oix].mend - ctx->olaps[oix].mstart;

			if (rlen < mlen)
				goto bail;

			rpra[i].buf.pv = args - ctx->olaps[oix].offset;
			pages[i].addr = ctx->buf->phys -
					ctx->olaps[oix].offset +
					(pkt_size - rlen);
			pages[i].addr = pages[i].addr &	PAGE_MASK;

			pg_start = (args & PAGE_MASK) >> PAGE_SHIFT;
			pg_end = ((args + len - 1) & PAGE_MASK) >> PAGE_SHIFT;
			pages[i].size = (pg_end - pg_start + 1) * PAGE_SIZE;
			args = args + mlen;
			rlen -= mlen;
			PERF_END);
		}

		if (i < inbufs && !ctx->maps[i]) {
			void *dst = (void *)(uintptr_t)rpra[i].buf.pv;
			void *src = (void *)(uintptr_t)ctx->args[i].ptr;
			PERF(ctx->fl->profile, GET_COUNTER(perf_counter, PERF_COPY),

			if (!kernel) {
				if (copy_from_user(dst, (void __user *)src,
						   len)) {
					err = -EFAULT;
					goto bail;
				}
			} else {
				memcpy(dst, src, len);
			}
			PERF_END);
		}
	}

	for (i = ctx->nbufs; i < ctx->nscalars; ++i) {
		list[i].num = ctx->args[i].length ? 1 : 0;
		list[i].pgidx = i;
		if (ctx->maps[i]) {
			pages[i].addr = ctx->maps[i]->phys;
			pages[i].size = ctx->maps[i]->size;
		}
		rpra[i].dma.fd = ctx->args[i].fd;
		rpra[i].dma.len = ctx->args[i].length;
		rpra[i].dma.offset = (u64) ctx->args[i].ptr;
	}

bail:
	if (err)
		dev_err(dev, "Error: get invoke args failed:%d\n", err);

	return err;
}

static int fastrpc_put_args(struct fastrpc_invoke_ctx *ctx,
			    u32 kernel)
{
	union fastrpc_remote_arg *rpra = ctx->rpra;
	struct fastrpc_user *fl = ctx->fl;
	struct fastrpc_map *mmap = NULL;
	struct fastrpc_invoke_buf *list;
	struct fastrpc_phy_page *pages;
	u64 *fdlist, *perf_dsp_list;
	u32 *crclist, *poll;
	int i, inbufs, outbufs, handles, perferr;

	inbufs = REMOTE_SCALARS_INBUFS(ctx->sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(ctx->sc);
	handles = REMOTE_SCALARS_INHANDLES(ctx->sc) + REMOTE_SCALARS_OUTHANDLES(ctx->sc);
	list = fastrpc_invoke_buf_start(rpra, ctx->nscalars);
	pages = fastrpc_phy_page_start(list, ctx->nscalars);
	fdlist = (u64 *)(pages + inbufs + outbufs + handles);
	crclist = (u32 *)(fdlist + FASTRPC_MAX_FDLIST);
	poll = (u32 *)(crclist + FASTRPC_MAX_CRCLIST);
	perf_dsp_list = (u64 *)(poll + 1);

	for (i = inbufs; i < ctx->nbufs; ++i) {
		if (!ctx->maps[i]) {
			void *src = (void *)(uintptr_t)rpra[i].buf.pv;
			void *dst = (void *)(uintptr_t)ctx->args[i].ptr;
			u64 len = rpra[i].buf.len;

			if (!kernel) {
				if (copy_to_user((void __user *)dst, src, len))
					return -EFAULT;
			} else {
				memcpy(dst, src, len);
			}
		}
	}

	for (i = 0; i < FASTRPC_MAX_FDLIST; i++) {
		if (!fdlist[i])
			break;
		if (!fastrpc_map_lookup(fl, (int)fdlist[i], 0, 0, &mmap, false))
			fastrpc_map_put(mmap);
	}
	if (ctx->crc && crclist && rpra) {
		if (copy_to_user((void __user *)ctx->crc, crclist, FASTRPC_MAX_CRCLIST * sizeof(u32)))
			return -EFAULT;
	}
	if (ctx->perf_dsp && perf_dsp_list) {
		if (0 != (perferr = copy_to_user((void __user *)ctx->perf_dsp, perf_dsp_list, FASTRPC_DSP_PERF_LIST * sizeof(u64)))) {
			pr_err("failed to copy perf data %d\n", perferr);
		}
	}
	return 0;
}

static s64 get_timestamp_in_ns(void)
{
	s64 ns = 0;
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	ns = timespec64_to_ns(&ts);
	return ns;
}

static void fastrpc_update_txmsg_buf(struct fastrpc_channel_ctx *chan,
				struct fastrpc_msg *msg, int rpmsg_send_err, s64 ns)
{
	unsigned long flags = 0;
	u32 tx_index = 0;
	struct fastrpc_tx_msg *tx_msg = NULL;

	spin_lock_irqsave(&(chan->gmsg_log[chan->domain_id].tx_lock), flags);

	tx_index = chan->gmsg_log[chan->domain_id].tx_index;
	tx_msg = &(chan->gmsg_log[chan->domain_id].tx_msgs[tx_index]);

	memcpy(&tx_msg->msg, msg, sizeof(struct fastrpc_msg));
	tx_msg->rpmsg_send_err = rpmsg_send_err;
	tx_msg->ns = ns;

	tx_index++;
	chan->gmsg_log[chan->domain_id].tx_index =
		(tx_index > (GLINK_MSG_HISTORY_LEN - 1)) ? 0 : tx_index;

	spin_unlock_irqrestore(&(chan->gmsg_log[chan->domain_id].tx_lock), flags);
}

static void fastrpc_update_rxmsg_buf(struct fastrpc_channel_ctx *chan,
							u64 ctx, int retval, s64 ns)
{
	unsigned long flags = 0;
	u32 rx_index = 0;
	struct fastrpc_rx_msg *rx_msg = NULL;
	struct fastrpc_invoke_rsp *rsp = NULL;

	spin_lock_irqsave(&(chan->gmsg_log[chan->domain_id].rx_lock), flags);

	rx_index = chan->gmsg_log[chan->domain_id].rx_index;
	rx_msg = &(chan->gmsg_log[chan->domain_id].rx_msgs[rx_index]);
	rsp = &rx_msg->rsp;

	rsp->ctx = ctx;
	rsp->retval = retval;
	rx_msg->ns = ns;

	rx_index++;
	chan->gmsg_log[chan->domain_id].rx_index =
		(rx_index > (GLINK_MSG_HISTORY_LEN - 1)) ? 0 : rx_index;

	spin_unlock_irqrestore(&(chan->gmsg_log[chan->domain_id].rx_lock), flags);
}

static int fastrpc_invoke_send(struct fastrpc_session_ctx *sctx,
			       struct fastrpc_invoke_ctx *ctx,
			       u32 kernel, uint32_t handle)
{
	struct fastrpc_channel_ctx *cctx;
	struct fastrpc_user *fl = ctx->fl;
	struct fastrpc_msg *msg = &ctx->msg;
	int ret;

	cctx = fl->cctx;
	msg->pid = fl->tgid;
	msg->tid = current->pid;
	if (fl->sessionid)
		msg->tid |= SESSION_ID_MASK;

	if (kernel)
		msg->pid = 0;

	msg->ctx = ctx->ctxid | fl->pd;
	msg->handle = handle;
	msg->sc = ctx->sc;
	msg->addr = ctx->buf ? ctx->buf->phys : 0;
	msg->size = roundup(ctx->msg_sz, PAGE_SIZE);
	// fastrpc_context_get(ctx);

	ret = fastrpc_transport_send(cctx, (void *)msg, sizeof(*msg));

	// if (ret)
		// fastrpc_context_put(ctx);
	fastrpc_update_txmsg_buf(cctx, msg, ret, get_timestamp_in_ns());

	return ret;

}

static int poll_for_remote_response(struct fastrpc_invoke_ctx *ctx, u32 timeout)
{
	int err = -EIO, ii = 0, jj = 0;
	u32 sc = ctx->sc;
	struct fastrpc_invoke_buf *list;
	struct fastrpc_phy_page *pages;
	u64 *fdlist = NULL;
	u32 *crclist = NULL, *poll = NULL;
	unsigned int inbufs, outbufs, handles;

	/* calculate poll memory location */
	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	handles = REMOTE_SCALARS_INHANDLES(sc) + REMOTE_SCALARS_OUTHANDLES(sc);
	list = fastrpc_invoke_buf_start(ctx->rpra, ctx->nscalars);
	pages = fastrpc_phy_page_start(list, ctx->nscalars);
	fdlist = (u64 *)(pages + inbufs + outbufs + handles);
	crclist = (u32 *)(fdlist + FASTRPC_MAX_FDLIST);
	poll = (u32 *)(crclist + FASTRPC_MAX_CRCLIST);

	/* poll on memory for DSP response. Return failure on timeout */
	for (ii = 0, jj = 0; ii < timeout; ii++, jj++) {
		if (*poll == FASTRPC_EARLY_WAKEUP_POLL) {
			/* Remote processor sent early response */
			err = 0;
			break;
		} else if (*poll == FASTRPC_POLL_RESPONSE) {
			err = 0;
			ctx->is_work_done = true;
			ctx->retval = 0;
			break;
		}
		if (jj == FASTRPC_POLL_TIME_MEM_UPDATE) {
			/* Wait for DSP to finish updating poll memory */
			rmb();
			jj = 0;
		}
		udelay(1);
	}
	return err;
}

static inline int fastrpc_wait_for_response(struct fastrpc_invoke_ctx *ctx,
						u32 kernel)
{
	int interrupted = 0;

	if (kernel)
		wait_for_completion(&ctx->work);
	else
		interrupted = wait_for_completion_interruptible(&ctx->work);

	return interrupted;
}

static void fastrpc_wait_for_completion(struct fastrpc_invoke_ctx *ctx,
			int *ptr_interrupted, u32 kernel)
{
	int err = 0, jj = 0;
	bool wait_resp = false;
	u32 wTimeout = FASTRPC_USER_EARLY_HINT_TIMEOUT;
	u32 wakeTime = ctx->early_wake_time;

	do {
		switch (ctx->rsp_flags) {
		/* try polling on completion with timeout */
		case USER_EARLY_SIGNAL:
			/* try wait if completion time is less than timeout */
			/* disable preempt to avoid context switch latency */
			preempt_disable();
			jj = 0;
			wait_resp = false;
			for (; wakeTime < wTimeout && jj < wTimeout; jj++) {
				wait_resp = try_wait_for_completion(&ctx->work);
				if (wait_resp)
					break;
				udelay(1);
			}
			preempt_enable();
			if (!wait_resp) {
				*ptr_interrupted = fastrpc_wait_for_response(ctx, kernel);
				if (*ptr_interrupted || ctx->is_work_done)
					return;
			}
			break;
		/* busy poll on memory for actual job done */
		case EARLY_RESPONSE:
			err = poll_for_remote_response(ctx, FASTRPC_POLL_TIME);
			/* Mark job done if poll on memory successful */
			/* Wait for completion if poll on memory timeout */
			if (!err) {
				ctx->is_work_done = true;
				return;
			}
			if (!ctx->is_work_done) {
				*ptr_interrupted = fastrpc_wait_for_response(ctx, kernel);
				if (*ptr_interrupted || ctx->is_work_done)
					return;
			}
			break;
		case COMPLETE_SIGNAL:
		case NORMAL_RESPONSE:
			*ptr_interrupted = fastrpc_wait_for_response(ctx, kernel);
			if (*ptr_interrupted || ctx->is_work_done)
				return;
			break;
		case POLL_MODE:
			err = poll_for_remote_response(ctx, ctx->fl->poll_timeout);

			/* If polling timed out, move to normal response state */
			if (err)
				ctx->rsp_flags = NORMAL_RESPONSE;
			else
				*ptr_interrupted = 0;
			break;
		default:
			*ptr_interrupted = -EBADR;
			pr_err("unsupported response type:0x%x\n", ctx->rsp_flags);
			break;
		}
	} while (!ctx->is_work_done);
}

static void fastrpc_update_invoke_count(u32 handle, u64 *perf_counter,
					struct timespec64 *invoket)
{
	/* update invoke count for dynamic handles */
	u64 *invcount, *count;
	invcount = GET_COUNTER(perf_counter, PERF_INVOKE);
	if (invcount)
		*invcount += getnstimediff(invoket);

	count = GET_COUNTER(perf_counter, PERF_COUNT);
	if (count)
		*count += 1;
}

static int fastrpc_internal_invoke(struct fastrpc_user *fl,  u32 kernel,
				   struct fastrpc_enhanced_invoke *invoke)
{
	struct fastrpc_invoke_ctx *ctx = NULL;
	struct fastrpc_invoke *inv = &invoke->inv;
	u32 handle, sc;
	int err = 0, perferr = 0, interrupted = 0;
	u64 *perf_counter = NULL;
	struct timespec64 invoket = {0};

	if (fl->profile)
		ktime_get_real_ts64(&invoket);

	if (!fl->sctx)
		return -EINVAL;

	if (!fl->cctx->dev)
		return -EPIPE;

	handle = inv->handle;
	sc = inv->sc;
	if (handle == FASTRPC_INIT_HANDLE && !kernel) {
		dev_warn_ratelimited(fl->sctx->dev, "user app trying to send a kernel RPC message (%d)\n",  handle);
		return -EPERM;
	}
	if (!kernel) {
		ctx = fastrpc_context_restore_interrupted(fl, inv);
		if (IS_ERR(ctx))
			return PTR_ERR(ctx);
		if (ctx)
			goto wait;
	}

	ctx = fastrpc_context_alloc(fl, kernel, sc, invoke);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	if (fl->profile)
		perf_counter = (u64 *)ctx->perf + PERF_COUNT;
	PERF(fl->profile, GET_COUNTER(perf_counter, PERF_GETARGS),
	err = fastrpc_get_args(kernel, ctx);
	if (err)
		goto bail;
	PERF_END);

	/* make sure that all CPU memory writes are seen by DSP */
	dma_wmb();
	/* Send invoke buffer to remote dsp */
	PERF(fl->profile, GET_COUNTER(perf_counter, PERF_LINK),
	err = fastrpc_invoke_send(fl->sctx, ctx, kernel, handle);
	if (err)
		goto bail;
	PERF_END);

wait:
	fastrpc_wait_for_completion(ctx, &interrupted, kernel);
	if (interrupted != 0) {
		err = interrupted;
		goto bail;
	}
	if (!ctx->is_work_done) {
		err = -ETIMEDOUT;
		dev_err(fl->sctx->dev, "Error: Invalid workdone state for handle 0x%x, sc 0x%x\n",
			handle, sc);
		goto bail;
	}

	/* make sure that all memory writes by DSP are seen by CPU */
	dma_rmb();
	/* populate all the output buffers with results */
	PERF(fl->profile, GET_COUNTER(perf_counter, PERF_PUTARGS),
	err = fastrpc_put_args(ctx, kernel);
	if (err)
		goto bail;
	PERF_END);

	/* Check the response from remote dsp */
	err = ctx->retval;
	if (err)
		goto bail;

bail:
	if (ctx && interrupted == -ERESTARTSYS) {
		fastrpc_context_save_interrupted(ctx);
	} else if (ctx) {
		if (fl->profile && !interrupted)
			fastrpc_update_invoke_count(handle, perf_counter, &invoket);
		if (fl->profile && ctx->perf && ctx->perf_kernel) {
			if (0 != (perferr = copy_to_user((void __user *)ctx->perf_kernel, ctx->perf, FASTRPC_KERNEL_PERF_LIST * sizeof(u64)))) {
				pr_warn("failed to copy perf data err 0x%x\n", perferr);
			}
		}
		spin_lock(&fl->lock);
		list_del(&ctx->node);
		spin_unlock(&fl->lock);
		fastrpc_context_put(ctx);
	}

	if (err)
		dev_dbg(fl->sctx->dev, "Error: Invoke Failed %d\n", err);

	return err;
}

static int fastrpc_mem_map_to_dsp(struct fastrpc_user *fl, int fd, int offset,
				u32 flags, u32 va, u64 phys,
				size_t size, uintptr_t *raddr)
{
	struct fastrpc_invoke_args args[4] = { [0 ... 3] = { 0 } };
	struct fastrpc_enhanced_invoke ioctl;
	struct fastrpc_mem_map_req_msg req_msg = { 0 };
	struct fastrpc_mmap_rsp_msg rsp_msg = { 0 };
	struct fastrpc_phy_page pages = { 0 };
	struct device *dev = fl->sctx->dev;
	int err = 0;

	req_msg.pgid = fl->tgid;
	req_msg.fd = fd;
	req_msg.offset = offset;
	req_msg.vaddrin = va;
	req_msg.flags = flags;
	req_msg.num = sizeof(pages);
	req_msg.data_len = 0;

	args[0].ptr = (u64) (uintptr_t) &req_msg;
	args[0].length = sizeof(req_msg);

	pages.addr = phys;
	pages.size = size;

	args[1].ptr = (u64) (uintptr_t) &pages;
	args[1].length = sizeof(pages);

	args[2].ptr = (u64) (uintptr_t) &pages;
	args[2].length = 0;

	args[3].ptr = (u64) (uintptr_t) &rsp_msg;
	args[3].length = sizeof(rsp_msg);

	ioctl.inv.handle = FASTRPC_INIT_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_MEM_MAP, 3, 1);
	ioctl.inv.args = (__u64)args;
	err = fastrpc_internal_invoke(fl, true, &ioctl);
	if (err) {
		dev_err(dev, "mem mmap error, fd %d, vaddr %llx, size %lld\n",
			fd, va, size);
		return err;
	}
	*raddr = rsp_msg.vaddr;

	return 0;
}

static int fastrpc_create_persistent_headers(struct fastrpc_user *fl)
{
	int err = 0;
	int i = 0;
	u64 virtb = 0;
	struct device *dev = fl->sctx->dev;
	struct fastrpc_buf *hdr_bufs, *buf, *pers_hdr_buf = NULL;
	u32 num_pers_hdrs = 0;
	size_t hdr_buf_alloc_len = 0;

	/*
	 * Pre-allocate memory for persistent header buffers based
	 * on concurrency info passed by user. Upper limit enforced.
	 */
	num_pers_hdrs = FASTRPC_MAX_PERSISTENT_HEADERS;
	hdr_buf_alloc_len = num_pers_hdrs * PAGE_SIZE;
	err = fastrpc_buf_alloc(fl, dev, hdr_buf_alloc_len,
			METADATA_BUF, &pers_hdr_buf);
	if (err)
		return err;

	virtb = (u64) (uintptr_t)(pers_hdr_buf->virt);
	err = fastrpc_mem_map_to_dsp(fl, -1, 0,
				ADSP_MMAP_PERSIST_HDR, 0, (u64) (uintptr_t)(pers_hdr_buf->phys),
				pers_hdr_buf->size, &pers_hdr_buf->raddr);
	if (err)
		goto err_dsp_map;

	hdr_bufs = kcalloc(num_pers_hdrs, sizeof(struct fastrpc_buf),
				GFP_KERNEL);
	if (!hdr_bufs)
		return -ENOMEM;

	spin_lock(&fl->lock);
	fl->pers_hdr_buf = pers_hdr_buf;
	fl->num_pers_hdrs = num_pers_hdrs;
	fl->hdr_bufs = hdr_bufs;
	for (i = 0; i < num_pers_hdrs; i++) {
		buf = &fl->hdr_bufs[i];
		buf->fl = fl;
		buf->virt = (void *)(virtb + (i * PAGE_SIZE));
		buf->phys = pers_hdr_buf->phys + (i * PAGE_SIZE);
		buf->size = PAGE_SIZE;
		buf->type = pers_hdr_buf->type;
		buf->in_use = false;
	}
	spin_unlock(&fl->lock);

	return 0;
err_dsp_map:
	dev_err(dev, "Warning: failed to map len %zu, flags %d, num headers %u with err %d\n",
			hdr_buf_alloc_len, ADSP_MMAP_PERSIST_HDR,
			num_pers_hdrs, err);
	fastrpc_buf_free(pers_hdr_buf, 0);
	return err;
}

static bool is_session_rejected(struct fastrpc_user *fl, bool unsigned_pd_request)
{
	/* Check if the device node is non-secure and channel is secure*/
	if (!fl->is_secure_dev && fl->cctx->secure) {
		/*
		 * Allow untrusted applications to offload only to Unsigned PD when
		 * channel is configured as secure and block untrusted apps on channel
		 * that does not support unsigned PD offload
		 */
		if (!fl->cctx->unsigned_support || !unsigned_pd_request) {
			dev_err(fl->cctx->dev, "Error: Untrusted application trying to offload to signed PD");
			return true;
		}
	}

	return false;
}

static int fastrpc_get_process_gids(struct gid_list *gidlist)
{
	struct group_info *group_info = get_current_groups();
	int i, num_gids;
	u32 *gids = NULL;

	if (!group_info)
		return -EFAULT;

	num_gids = group_info->ngroups + 1;
	gids = kcalloc(num_gids, sizeof(u32), GFP_KERNEL);
	if (!gids)
		return -ENOMEM;

	/* Get the real GID */
	gids[0] = __kgid_val(current_gid());

	/* Get the supplemental GIDs */
	for (i = 1; i < num_gids; i++)
		gids[i] = __kgid_val(group_info->gid[i - 1]);

	sort(gids, num_gids, sizeof(*gids), uint_cmp_func, NULL);
	gidlist->gids = gids;
	gidlist->gidcount = num_gids;

	return 0;
}

static void fastrpc_check_privileged_process(struct fastrpc_user *fl,
				struct fastrpc_init_create *init)
{
	u32 gid = sorted_lists_intersection(fl->gidlist.gids,
			fl->gidlist.gidcount, fl->cctx->gidlist.gids,
			fl->cctx->gidlist.gidcount);

	/* disregard any privilege bits from userspace */
	init->attrs &= (~FASTRPC_MODE_PRIVILEGED);
	if (gid) {
		dev_info(fl->cctx->dev, "%s: %s (PID %d, GID %u) is a privileged process\n",
				__func__, current->comm, fl->tgid, gid);
		init->attrs |= FASTRPC_MODE_PRIVILEGED;
	}
}

int fastrpc_mmap_remove_ssr(struct fastrpc_channel_ctx *cctx)
{
	struct fastrpc_buf *buf, *b;
	int err = 0;
	unsigned long flags;

	spin_lock_irqsave(&cctx->lock, flags);
	list_for_each_entry_safe(buf, b, &cctx->gmaps, node) {
		if (cctx->vmcount) {
			u64 src_perms = 0;
			struct qcom_scm_vmperm dst_perms;
			u32 i;

			for (i = 0; i < cctx->vmcount; i++)
				src_perms |= BIT(cctx->vmperms[i].vmid);

			dst_perms.vmid = QCOM_SCM_VMID_HLOS;
			dst_perms.perm = QCOM_SCM_PERM_RWX;
			spin_unlock_irqrestore(&cctx->lock, flags);
			err = qcom_scm_assign_mem(buf->phys, (u64)buf->size,
							&src_perms, &dst_perms, 1);
			if (err) {
				dev_err(cctx->dev, "%s: Failed to assign memory with phys 0x%llx size 0x%llx err %d",
					__func__, buf->phys, buf->size, err);
				return err;
			}
			spin_lock_irqsave(&cctx->lock, flags);
		}
		list_del(&buf->node);
		fastrpc_buf_free(buf, false);
	}
	spin_unlock_irqrestore(&cctx->lock, flags);

	return 0;
}

static int fastrpc_mmap_remove_pdr(struct fastrpc_user *fl)
{
	int i, err = 0, session = -1;

	if (!fl)
		return -EBADF;

	for (i = 0; i < FASTRPC_MAX_SPD ; i++) {
		if (!fl->cctx->spd[i].servloc_name)
			continue;
		if (!strcmp(fl->servloc_name, fl->cctx->spd[i].servloc_name)) {
			session = i;
			break;
		}
	}

	if (i >= FASTRPC_MAX_SPD)
		return -EUSERS;

	if (atomic_read(&fl->cctx->spd[session].ispdup) == 0)
		return -ENOTCONN;

	if (fl->cctx->spd[session].pdrcount !=
		fl->cctx->spd[session].prevpdrcount) {
		err = fastrpc_mmap_remove_ssr(fl->cctx);
		if (err)
			pr_warn("failed to unmap remote heap (err %d)\n",
					err);
		fl->cctx->spd[session].prevpdrcount =
				fl->cctx->spd[session].pdrcount;
	}

	return err;
}

static int fastrpc_init_create_static_process(struct fastrpc_user *fl,
					      char __user *argp)
{
	struct fastrpc_init_create_static init;
	struct fastrpc_invoke_args *args;
	struct fastrpc_enhanced_invoke ioctl;
	struct fastrpc_phy_page pages[1];
	struct fastrpc_buf *buf = NULL;
	u64 phys = 0, size = 0;
	char *name;
	int err;
	bool scm_done = false;
	unsigned long flags;
	struct {
		int pgid;
		u32 namelen;
		u32 pageslen;
	} inbuf;

	args = kcalloc(FASTRPC_CREATE_STATIC_PROCESS_NARGS, sizeof(*args), GFP_KERNEL);
	if (!args)
		return -ENOMEM;

	if (copy_from_user(&init, argp, sizeof(init))) {
		err = -EFAULT;
		goto err;
	}

	if (init.namelen > INIT_FILE_NAMELEN_MAX) {
		err = -EINVAL;
		goto err;
	}

	name = kzalloc(init.namelen, GFP_KERNEL);
	if (!name) {
		err = -ENOMEM;
		goto err;
	}

	if (copy_from_user(name, (void __user *)(uintptr_t)init.name, init.namelen)) {
		err = -EFAULT;
		goto err_name;
	}

	fl->sctx = fastrpc_session_alloc(fl->cctx, fl->sharedcb);
	if (!fl->sctx) {
		dev_err(fl->cctx->dev, "No session available\n");
		return -EBUSY;
	}

	fl->servloc_name = AUDIO_PDR_SERVICE_LOCATION_CLIENT_NAME;

	if (!strcmp(name, "audiopd")) {
		/*
		 * Remove any previous mappings in case process is trying
		 * to reconnect after a PD restart on remote subsystem.
		 */
		err = fastrpc_mmap_remove_pdr(fl);
		if (err)
			goto err_name;
	}

	if (!fl->cctx->staticpd_status) {
		err = fastrpc_remote_heap_alloc(fl, fl->sctx->dev, init.memlen, REMOTEHEAP_BUF, &buf);
		if (err)
			goto err_name;

		phys = buf->phys;
		size = buf->size;
		/* Map if we have any heap VMIDs associated with this ADSP Static Process. */
		if (fl->cctx->vmcount) {
			u64 src_perms = BIT(QCOM_SCM_VMID_HLOS);

			err = qcom_scm_assign_mem(phys, (u64)size,
							&src_perms, fl->cctx->vmperms, fl->cctx->vmcount);
			if (err) {
				dev_err(fl->sctx->dev, "%s: Failed to assign memory with phys 0x%llx size 0x%llx err %d",
					__func__, phys, size, err);
				goto err_map;
			}
			scm_done = true;
		}
		fl->cctx->staticpd_status = true;
		spin_lock_irqsave(&fl->cctx->lock, flags);
		list_add_tail(&buf->node, &fl->cctx->gmaps);
		spin_unlock_irqrestore(&fl->cctx->lock, flags);
	}

	inbuf.pgid = fl->tgid;
	inbuf.namelen = init.namelen;
	inbuf.pageslen = 0;
	fl->pd = USER_PD;

	args[0].ptr = (u64)(uintptr_t)&inbuf;
	args[0].length = sizeof(inbuf);
	args[0].fd = -1;

	args[1].ptr = (u64)(uintptr_t)name;
	args[1].length = inbuf.namelen;
	args[1].fd = -1;

	pages[0].addr = phys;
	pages[0].size = size;

	args[2].ptr = (u64)(uintptr_t) pages;
	args[2].length = sizeof(*pages);
	args[2].fd = -1;

	ioctl.inv.handle = FASTRPC_INIT_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_CREATE_STATIC, 3, 0);
	ioctl.inv.args = (__u64)args;

	err = fastrpc_internal_invoke(fl, true, &ioctl);
	if (err)
		goto err_invoke;

	kfree(args);

	return 0;
err_invoke:
	if (fl->cctx->vmcount && scm_done) {
		u64 src_perms = 0;
		struct qcom_scm_vmperm dst_perms;
		u32 i;

		for (i = 0; i < fl->cctx->vmcount; i++)
			src_perms |= BIT(fl->cctx->vmperms[i].vmid);

		dst_perms.vmid = QCOM_SCM_VMID_HLOS;
		dst_perms.perm = QCOM_SCM_PERM_RWX;
		err = qcom_scm_assign_mem(phys, (u64)size,
						&src_perms, &dst_perms, 1);
		if (err)
			dev_err(fl->sctx->dev, "%s: Failed to assign memory phys 0x%llx size 0x%llx err %d",
				__func__, phys, size, err);
	}
err_map:
	fl->cctx->staticpd_status = false;
	spin_lock(&fl->lock);
	list_del(&buf->node);
	spin_unlock(&fl->lock);
	fastrpc_buf_free(buf, false);
err_name:
	kfree(name);
err:
	kfree(args);

	return err;
}

static int fastrpc_init_create_process(struct fastrpc_user *fl,
					char __user *argp)
{
	struct fastrpc_init_create init;
	struct fastrpc_invoke_args *args;
	struct fastrpc_enhanced_invoke ioctl;
	struct fastrpc_phy_page pages[1];
	struct fastrpc_map *map = NULL;
	struct fastrpc_buf *imem = NULL;
	int memlen;
	int err;
	struct {
		int pgid;
		u32 namelen;
		u32 filelen;
		u32 pageslen;
		u32 attrs;
		u32 siglen;
	} inbuf;

	args = kcalloc(FASTRPC_CREATE_PROCESS_NARGS, sizeof(*args), GFP_KERNEL);
	if (!args)
		return -ENOMEM;

	if (copy_from_user(&init, argp, sizeof(init))) {
		err = -EFAULT;
		goto err;
	}

	if (init.attrs & FASTRPC_MODE_UNSIGNED_MODULE)
		fl->is_unsigned_pd = true;

	if (is_session_rejected(fl, fl->is_unsigned_pd)) {
		err = -ECONNREFUSED;
		goto err;
	}

	if (init.filelen > INIT_FILELEN_MAX) {
		err = -EINVAL;
		goto err;
	}

	fl->sctx = fastrpc_session_alloc(fl->cctx, fl->sharedcb);
	if (!fl->sctx) {
		dev_err(fl->cctx->dev, "No session available\n");
		return -EBUSY;
	}

	fastrpc_get_process_gids(&fl->gidlist);

	inbuf.pgid = fl->tgid;
	inbuf.namelen = strlen(current->comm) + 1;
	inbuf.filelen = init.filelen;
	inbuf.pageslen = 1;
	inbuf.attrs = init.attrs;
	inbuf.siglen = init.siglen;
	fl->pd = USER_PD;

	if (init.filelen && init.filefd) {
		err = fastrpc_map_create(fl, init.filefd, init.file, init.filelen, 0, &map, true);
		if (err)
			goto err;
	}

	fastrpc_check_privileged_process(fl, &init);

	memlen = ALIGN(max(INIT_FILELEN_MAX, (int)init.filelen * 4),
		       1024 * 1024);
	err = fastrpc_buf_alloc(fl, fl->sctx->dev, memlen,
				INITMEM_BUF, &imem);
	if (err)
		goto err_alloc;

	fl->init_mem = imem;
	args[0].ptr = (u64)(uintptr_t)&inbuf;
	args[0].length = sizeof(inbuf);
	args[0].fd = -1;

	args[1].ptr = (u64)(uintptr_t)current->comm;
	args[1].length = inbuf.namelen;
	args[1].fd = -1;

	args[2].ptr = (u64) init.file;
	args[2].length = inbuf.filelen;
	args[2].fd = init.filefd;

	pages[0].addr = imem->phys;
	pages[0].size = imem->size;

	args[3].ptr = (u64)(uintptr_t) pages;
	args[3].length = 1 * sizeof(*pages);
	args[3].fd = -1;

	args[4].ptr = (u64)(uintptr_t)&inbuf.attrs;
	args[4].length = sizeof(inbuf.attrs);
	args[4].fd = -1;

	args[5].ptr = (u64)(uintptr_t) &inbuf.siglen;
	args[5].length = sizeof(inbuf.siglen);
	args[5].fd = -1;

	ioctl.inv.handle = FASTRPC_INIT_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_CREATE, 4, 0);
	if (init.attrs)
		ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_CREATE_ATTR, 4, 0);
	ioctl.inv.args = (__u64)args;

	err = fastrpc_internal_invoke(fl, true, &ioctl);
	if (err)
		goto err_invoke;

	if (fl->cctx->domain_id == CDSP_DOMAIN_ID) {
		fastrpc_create_persistent_headers(fl);
	}

	kfree(args);
	fastrpc_map_put(map);

	return 0;

err_invoke:
	fl->init_mem = NULL;
	fastrpc_buf_free(imem, false);
err_alloc:
	fastrpc_map_put(map);
err:
	kfree(args);

	return err;
}

static struct fastrpc_session_ctx *fastrpc_session_alloc(
					struct fastrpc_channel_ctx *cctx, bool sharedcb)
{
	struct fastrpc_session_ctx *session = NULL;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&cctx->lock, flags);
	for (i = 0; i < cctx->sesscount; i++) {
		if (!cctx->session[i].used && cctx->session[i].valid &&
				cctx->session[i].sharedcb == sharedcb) {
			cctx->session[i].used = true;
			session = &cctx->session[i];
			break;
		}
	}
	spin_unlock_irqrestore(&cctx->lock, flags);

	return session;
}

static void fastrpc_session_free(struct fastrpc_channel_ctx *cctx,
				 struct fastrpc_session_ctx *session)
{
	unsigned long flags;

	spin_lock_irqsave(&cctx->lock, flags);
	session->used = false;
	spin_unlock_irqrestore(&cctx->lock, flags);
}

static void fastrpc_context_list_free(struct fastrpc_user *fl)
{
	struct fastrpc_invoke_ctx *ctx, *n;

	list_for_each_entry_safe(ctx, n, &fl->interrupted, node) {
		spin_lock(&fl->lock);
		list_del(&ctx->node);
		spin_unlock(&fl->lock);
		fastrpc_context_put(ctx);
	}

	list_for_each_entry_safe(ctx, n, &fl->pending, node) {
		spin_lock(&fl->lock);
		list_del(&ctx->node);
		spin_unlock(&fl->lock);
		fastrpc_context_put(ctx);
	}
}

static int fastrpc_release_current_dsp_process(struct fastrpc_user *fl)
{
	struct fastrpc_invoke_args args[1];
	struct fastrpc_enhanced_invoke ioctl;
	int tgid = 0;

	tgid = fl->tgid;
	args[0].ptr = (u64)(uintptr_t) &tgid;
	args[0].length = sizeof(tgid);
	args[0].fd = -1;

	ioctl.inv.handle = FASTRPC_INIT_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_RELEASE, 1, 0);
	ioctl.inv.args = (__u64)args;

	return fastrpc_internal_invoke(fl, true, &ioctl);
}

static int fastrpc_device_release(struct inode *inode, struct file *file)
{
	struct fastrpc_user *fl = (struct fastrpc_user *)file->private_data;
	struct fastrpc_channel_ctx *cctx = fl->cctx;
	struct fastrpc_map *map, *m;
	struct fastrpc_buf *buf, *b;
	int i;
	unsigned long flags;

	fastrpc_release_current_dsp_process(fl);

	spin_lock_irqsave(&cctx->lock, flags);
	list_del(&fl->user);
	spin_unlock_irqrestore(&cctx->lock, flags);
	kfree(fl->gidlist.gids);

	spin_lock_irqsave(&fl->proc_state_notif.nqlock, flags);
	atomic_add(1, &fl->proc_state_notif.notif_queue_count);
	wake_up_interruptible(&fl->proc_state_notif.notif_wait_queue);
	spin_unlock_irqrestore(&fl->proc_state_notif.nqlock, flags);

	if (fl->init_mem)
		fastrpc_buf_free(fl->init_mem, false);

	fastrpc_context_list_free(fl);

	list_for_each_entry_safe(map, m, &fl->maps, node)
		fastrpc_map_put(map);

	list_for_each_entry_safe(buf, b, &fl->mmaps, node) {
		spin_lock(&fl->lock);
		list_del(&buf->node);
		spin_unlock(&fl->lock);
		fastrpc_buf_free(buf, false);
	}

	if (fl->pers_hdr_buf)
		fastrpc_buf_free(fl->pers_hdr_buf, false);
	kfree(fl->hdr_bufs);

	fastrpc_cached_buf_list_free(fl);
	if (fl->qos_request && fl->dev_pm_qos_req) {
		for (i = 0; i < cctx->lowest_capacity_core_count; i++) {
			if (!dev_pm_qos_request_active(&fl->dev_pm_qos_req[i]))
				continue;
			dev_pm_qos_remove_request(&fl->dev_pm_qos_req[i]);
		}
	}
	kfree(fl->dev_pm_qos_req);
	fastrpc_pm_relax(fl,cctx->secure);
	fastrpc_session_free(cctx, fl->sctx);
	fastrpc_channel_ctx_put(cctx);
	for (i = 0; i < (FASTRPC_DSPSIGNAL_NUM_SIGNALS /FASTRPC_DSPSIGNAL_GROUP_SIZE); i++)
		kfree(fl->signal_groups[i]);

	mutex_destroy(&fl->signal_create_mutex);
	mutex_destroy(&fl->mutex);
	kfree(fl);
	file->private_data = NULL;

	return 0;
}

static int fastrpc_device_open(struct inode *inode, struct file *filp)
{
	struct fastrpc_channel_ctx *cctx;
	struct fastrpc_device *fdevice;
	struct fastrpc_user *fl = NULL;
	unsigned long flags;

	fdevice = miscdev_to_fdevice(filp->private_data);
	cctx = fdevice->cctx;

	fl = kzalloc(sizeof(*fl), GFP_KERNEL);
	if (!fl)
		return -ENOMEM;

	/* Released in fastrpc_device_release() */
	fastrpc_channel_ctx_get(cctx);

	filp->private_data = fl;
	spin_lock_init(&fl->lock);
	mutex_init(&fl->mutex);
	spin_lock_init(&fl->dspsignals_lock);
	mutex_init(&fl->signal_create_mutex);
	INIT_LIST_HEAD(&fl->pending);
	INIT_LIST_HEAD(&fl->interrupted);
	INIT_LIST_HEAD(&fl->maps);
	INIT_LIST_HEAD(&fl->mmaps);
	INIT_LIST_HEAD(&fl->user);
	INIT_LIST_HEAD(&fl->cached_bufs);
	INIT_LIST_HEAD(&fl->notif_queue);
	init_waitqueue_head(&fl->proc_state_notif.notif_wait_queue);
	spin_lock_init(&fl->proc_state_notif.nqlock);
	fl->tgid = current->tgid;
	fl->cctx = cctx;
	fl->is_secure_dev = fdevice->secure;
	fl->sessionid = 0;

	if (cctx->lowest_capacity_core_count) {
		fl->dev_pm_qos_req = kzalloc((cctx->lowest_capacity_core_count) *
				sizeof(struct dev_pm_qos_request), GFP_KERNEL);
		if (!fl->dev_pm_qos_req)
			return -ENOMEM;
	}

	spin_lock_irqsave(&cctx->lock, flags);
	list_add_tail(&fl->user, &cctx->users);
	spin_unlock_irqrestore(&cctx->lock, flags);

	return 0;
}

static int fastrpc_dmabuf_alloc(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_alloc_dma_buf bp;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct fastrpc_buf *buf = NULL;
	int err;

	if (copy_from_user(&bp, argp, sizeof(bp)))
		return -EFAULT;

	err = fastrpc_buf_alloc(fl, fl->sctx->dev, bp.size, USER_BUF, &buf);
	if (err)
		return err;
	exp_info.ops = &fastrpc_dma_buf_ops;
	exp_info.size = bp.size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buf;
	buf->dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(buf->dmabuf)) {
		err = PTR_ERR(buf->dmabuf);
		fastrpc_buf_free(buf, false);
		return err;
	}

	bp.fd = dma_buf_fd(buf->dmabuf, O_ACCMODE);
	if (bp.fd < 0) {
		dma_buf_put(buf->dmabuf);
		return -EINVAL;
	}

	if (copy_to_user(argp, &bp, sizeof(bp))) {
		/*
		 * The usercopy failed, but we can't do much about it, as
		 * dma_buf_fd() already called fd_install() and made the
		 * file descriptor accessible for the current process. It
		 * might already be closed and dmabuf no longer valid when
		 * we reach this point. Therefore "leak" the fd and rely on
		 * the process exit path to do any required cleanup.
		 */
		return -EFAULT;
	}

	return 0;
}

static int fastrpc_send_cpuinfo_to_dsp(struct fastrpc_user *fl)
{
	int err = 0;
	u64 cpuinfo = 0;
	struct fastrpc_invoke_args args[1];
	struct fastrpc_enhanced_invoke ioctl;

	if (!fl) {
		return -EBADF;
	}

	cpuinfo = fl->cctx->cpuinfo_todsp;
	/* return success if already updated to remote processor */
	if (fl->cctx->cpuinfo_status)
		return 0;

	args[0].ptr = (u64)(uintptr_t)&cpuinfo;
	args[0].length = sizeof(cpuinfo);
	args[0].fd = -1;

	ioctl.inv.handle = FASTRPC_DSP_UTILITIES_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(1, 1, 0);
	ioctl.inv.args = (__u64)args;

	err = fastrpc_internal_invoke(fl, true, &ioctl);
	if (!err)
		fl->cctx->cpuinfo_status = true;

	return err;
}

static int fastrpc_init_attach(struct fastrpc_user *fl, int pd)
{
	struct fastrpc_invoke_args args[1];
	struct fastrpc_enhanced_invoke ioctl;
	int err, tgid = fl->tgid;

	fl->sctx = fastrpc_session_alloc(fl->cctx, fl->sharedcb);
	if (!fl->sctx) {
		dev_err(fl->cctx->dev, "No session available\n");
		return -EBUSY;
	}
	args[0].ptr = (u64)(uintptr_t) &tgid;
	args[0].length = sizeof(tgid);
	args[0].fd = -1;
	fl->pd = pd;
	if (pd == SENSORS_PD) {
		if (fl->cctx->domain_id == ADSP_DOMAIN_ID)
			fl->servloc_name = SENSORS_PDR_ADSP_SERVICE_LOCATION_CLIENT_NAME;
		else if (fl->cctx->domain_id == SDSP_DOMAIN_ID)
			fl->servloc_name = SENSORS_PDR_SLPI_SERVICE_LOCATION_CLIENT_NAME;
	}

	ioctl.inv.handle = FASTRPC_INIT_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_ATTACH, 1, 0);
	ioctl.inv.args = (__u64)args;

	err = fastrpc_internal_invoke(fl, true, &ioctl);
	if (err)
		return err;

	return 0;
}

static int fastrpc_invoke(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_invoke_args *args = NULL;
	struct fastrpc_enhanced_invoke ioctl;
	struct fastrpc_invoke inv;
	u32 nscalars;
	int err;

	if (copy_from_user(&inv, argp, sizeof(inv)))
		return -EFAULT;

	/* nscalars is truncated here to max supported value */
	nscalars = REMOTE_SCALARS_LENGTH(inv.sc);
	if (nscalars) {
		args = kcalloc(nscalars, sizeof(*args), GFP_KERNEL);
		if (!args)
			return -ENOMEM;

		if (copy_from_user(args, (void __user *)(uintptr_t)inv.args,
				   nscalars * sizeof(*args))) {
			kfree(args);
			return -EFAULT;
		}
	}

	ioctl.inv = inv;
	ioctl.inv.args = (__u64)args;

	err = fastrpc_internal_invoke(fl, false, &ioctl);
	kfree(args);

	return err;
}

static void fastrpc_queue_pd_status(struct fastrpc_user *fl, int domain, int status)
{
	struct fastrpc_notif_rsp *notif_rsp = NULL;
	unsigned long flags;

	notif_rsp = kzalloc(sizeof(*notif_rsp), GFP_ATOMIC);
	if (!notif_rsp) {
		dev_err(fl->sctx->dev, "Allocation failed for notif");
		return;
	}

	notif_rsp->status = status;
	notif_rsp->domain = domain;

	spin_lock_irqsave(&fl->proc_state_notif.nqlock, flags);
	list_add_tail(&notif_rsp->notifn, &fl->notif_queue);
	atomic_add(1, &fl->proc_state_notif.notif_queue_count);
	wake_up_interruptible(&fl->proc_state_notif.notif_wait_queue);
	spin_unlock_irqrestore(&fl->proc_state_notif.nqlock, flags);
}

static void fastrpc_notif_find_process(int domain, struct fastrpc_channel_ctx *cctx, struct dsp_notif_rsp *notif)
{
	bool is_process_found = false;
	unsigned long irq_flags = 0;
	struct fastrpc_user *user;

	spin_lock_irqsave(&cctx->lock, irq_flags);
	list_for_each_entry(user, &cctx->users, user) {
		if (user->tgid == notif->pid) {
			is_process_found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&cctx->lock, irq_flags);

	if (!is_process_found)
		return;
	fastrpc_queue_pd_status(user, domain, notif->status);
}

static int fastrpc_wait_on_notif_queue(
			struct fastrpc_internal_notif_rsp *notif_rsp,
			struct fastrpc_user *fl)
{
	int err = 0;
	unsigned long flags;
	struct fastrpc_notif_rsp *notif, *inotif, *n;

read_notif_status:
	err = wait_event_interruptible(fl->proc_state_notif.notif_wait_queue,
				atomic_read(&fl->proc_state_notif.notif_queue_count));
	if (err) {
		kfree(notif);
		return err;
	}

	spin_lock_irqsave(&fl->proc_state_notif.nqlock, flags);
	list_for_each_entry_safe(inotif, n, &fl->notif_queue, notifn) {
		list_del(&inotif->notifn);
		atomic_sub(1, &fl->proc_state_notif.notif_queue_count);
		notif = inotif;
		break;
	}
	spin_unlock_irqrestore(&fl->proc_state_notif.nqlock, flags);

	if (notif) {
		notif_rsp->status = notif->status;
		notif_rsp->domain = notif->domain;
	} else {// Go back to wait if ctx is invalid
		dev_err(fl->sctx->dev, "Invalid status notification response\n");
		goto read_notif_status;
	}

	kfree(notif);
	return err;
}

static int fastrpc_get_notif_response(
			struct fastrpc_internal_notif_rsp *notif,
			void *param, struct fastrpc_user *fl)
{
	int err = 0;
	err = fastrpc_wait_on_notif_queue(notif, fl);
	if (err)
		return err;

	if (copy_to_user((void __user *)param, notif,
			sizeof(struct fastrpc_internal_notif_rsp)))
		return -EFAULT;

	return 0;
}

static int fastrpc_manage_poll_mode(struct fastrpc_user *fl, u32 enable, u32 timeout)
{
	const unsigned int MAX_POLL_TIMEOUT_US = 10000;

	if ((fl->cctx->domain_id != CDSP_DOMAIN_ID) || (fl->pd != USER_PD)) {
		dev_err(fl->cctx->dev,"poll mode only allowed for dynamic CDSP process\n");
		return -EPERM;
	}
	if (timeout > MAX_POLL_TIMEOUT_US) {
		dev_err(fl->cctx->dev,"poll timeout %u is greater than max allowed value %u\n",
			timeout, MAX_POLL_TIMEOUT_US);
		return -EBADMSG;
	}
	spin_lock(&fl->lock);
	if (enable) {
		fl->poll_mode = true;
		fl->poll_timeout = timeout;
	} else {
		fl->poll_mode = false;
		fl->poll_timeout = 0;
	}
	spin_unlock(&fl->lock);
	dev_info(fl->cctx->dev,"updated poll mode to %d, timeout %u\n", enable, timeout);
	return 0;
}

static int fastrpc_internal_control(struct fastrpc_user *fl,
					struct fastrpc_internal_control *cp)
{
	int err = 0, ret = 0;
	struct fastrpc_channel_ctx *cctx = fl->cctx;
	u32 latency = 0, cpu = 0;

	if (!fl) {
		return -EBADF;
	}
	if (!cp) {
		return -EINVAL;
	}

	switch (cp->req) {
	case FASTRPC_CONTROL_LATENCY:
		if (cp->lp.enable)
			latency =  cctx->qos_latency;
		else
			latency = PM_QOS_RESUME_LATENCY_DEFAULT_VALUE;
		if (latency == 0)
			return -EINVAL;
		if (!(cctx->lowest_capacity_core_count && fl->dev_pm_qos_req)) {
			dev_err(fl->cctx->dev, "Skipping PM QoS latency voting, core count: %u\n",
						cctx->lowest_capacity_core_count);
			return -EINVAL;
		}
		/*
		 * Add voting request for all possible cores corresponding to cluster
		 * id 0. If DT property 'qcom,single-core-latency-vote' is enabled
		 * then add voting request for only one core of cluster id 0.
		 */
		 for (cpu = 0; cpu < cctx->lowest_capacity_core_count; cpu++) {
			if (!fl->qos_request) {
				ret = dev_pm_qos_add_request(
						get_cpu_device(cpu),
						&fl->dev_pm_qos_req[cpu],
						DEV_PM_QOS_RESUME_LATENCY,
						latency);
			} else {
				ret = dev_pm_qos_update_request(
						&fl->dev_pm_qos_req[cpu],
						latency);
			}
			if (ret < 0) {
				dev_err(fl->cctx->dev, "QoS with lat %u failed for CPU %d, err %d, req %d\n",
					latency, cpu, err, fl->qos_request);
				break;
			}
		}
		if (ret >= 0) {
			fl->qos_request = 1;
			err = 0;
		}
		break;
	case FASTRPC_CONTROL_SMMU:
		fl->sharedcb = cp->smmu.sharedcb;
		break;
	case FASTRPC_CONTROL_WAKELOCK:
		if (!fl->is_secure_dev) {
			dev_err(fl->cctx->dev,
				"PM voting not allowed for non-secure device node");
			err = -EPERM;
			return err;
		}
		fl->wake_enable = cp->wp.enable;
		break;
	case FASTRPC_CONTROL_PM:
		if (!fl->wake_enable)
			return -EACCES;
		if (cp->pm.timeout > FASTRPC_MAX_PM_TIMEOUT_MS)
			fl->ws_timeout = FASTRPC_MAX_PM_TIMEOUT_MS;
		else
			fl->ws_timeout = cp->pm.timeout;
		fastrpc_pm_awake(fl, fl->cctx->secure);
		break;
	case FASTRPC_CONTROL_DSPPROCESS_CLEAN:
		err = fastrpc_release_current_dsp_process(fl);
		if (!err)
			fastrpc_queue_pd_status(fl, fl->cctx->domain_id, FASTRPC_USERPD_FORCE_KILL);
		break;
	case FASTRPC_CONTROL_RPC_POLL:
		err = fastrpc_manage_poll_mode(fl, cp->lp.enable, cp->lp.latency);
		break;
	default:
		err = -EBADRQC;
		break;
	}
	return err;
}

static int fastrpc_dspsignal_signal(struct fastrpc_user *fl,
			     struct fastrpc_internal_dspsignal *fsig)
{
	int err = 0;
	struct fastrpc_channel_ctx *cctx = NULL;
	u64 msg = 0;
	u32 signal_id = fsig->signal_id;

	cctx = fl->cctx;

	if (!(signal_id < FASTRPC_DSPSIGNAL_NUM_SIGNALS))
		return -EINVAL;

	msg = (((uint64_t)fl->tgid) << 32) | ((uint64_t)fsig->signal_id);
	err = fastrpc_transport_send(cctx, (void *)&msg, sizeof(msg));

	return err;
}

int fastrpc_dspsignal_wait(struct fastrpc_user *fl,
			     struct fastrpc_internal_dspsignal *fsig)
{
	int err = 0;
	unsigned long timeout = usecs_to_jiffies(fsig->timeout_usec);
	u32 signal_id = fsig->signal_id;
	struct fastrpc_dspsignal *s = NULL;
	long ret = 0;
	unsigned long irq_flags = 0;

	if (!(signal_id <FASTRPC_DSPSIGNAL_NUM_SIGNALS))
		return -EINVAL;

	spin_lock_irqsave(&fl->dspsignals_lock, irq_flags);
	if (fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE] != NULL) {
		struct fastrpc_dspsignal *group =
			fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE];

		s = &group[signal_id %FASTRPC_DSPSIGNAL_GROUP_SIZE];
	}
	if ((s == NULL) || (s->state == DSPSIGNAL_STATE_UNUSED)) {
		spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
		dev_err(fl->cctx->dev, "Unknown signal id %u\n", signal_id);
		return -ENOENT;
	}
	if (s->state != DSPSIGNAL_STATE_PENDING) {
		if ((s->state == DSPSIGNAL_STATE_CANCELED) || (s->state == DSPSIGNAL_STATE_UNUSED))
			err = -EINTR;
		spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
		dev_dbg(fl->cctx->dev, "Signal %u in state %u, complete wait immediately",
				signal_id, s->state);
		return err;
	}
	spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);

	if (timeout != 0xffffffff)
		ret = wait_for_completion_interruptible_timeout(&s->comp, timeout);
	else
		ret = wait_for_completion_interruptible(&s->comp);

	if (ret == 0) {
		dev_dbg(fl->cctx->dev, "Wait for signal %u timed out\n", signal_id);
		return -ETIMEDOUT;
	} else if (ret < 0) {
		dev_err(fl->cctx->dev, "Wait for signal %u failed %d\n", signal_id, (int)ret);
		return ret;
	}

	spin_lock_irqsave(&fl->dspsignals_lock, irq_flags);
	if (s->state == DSPSIGNAL_STATE_SIGNALED) {
		s->state = DSPSIGNAL_STATE_PENDING;
	} else if ((s->state == DSPSIGNAL_STATE_CANCELED) || (s->state == DSPSIGNAL_STATE_UNUSED)) {
		dev_err(fl->cctx->dev, "Signal %u cancelled or destroyed\n", signal_id);
		err = -EINTR;
	}
	spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);

	return err;
}

static int fastrpc_dspsignal_create(struct fastrpc_user *fl,
			     struct fastrpc_internal_dspsignal *fsig)
{
	int err = 0;
	u32 signal_id = fsig->signal_id;
	struct fastrpc_dspsignal *group, *sig;
	unsigned long irq_flags = 0;

	if (!(signal_id <FASTRPC_DSPSIGNAL_NUM_SIGNALS))
		return -EINVAL;

	mutex_lock(&fl->signal_create_mutex);
	spin_lock_irqsave(&fl->dspsignals_lock, irq_flags);

	group = fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE];
	if (group == NULL) {
		int i;
		spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
		group = kzalloc(FASTRPC_DSPSIGNAL_GROUP_SIZE * sizeof(*group),
					     GFP_KERNEL);
		if (group == NULL) {
			mutex_unlock(&fl->signal_create_mutex);
			return -ENOMEM;
		}

		for (i = 0; i < FASTRPC_DSPSIGNAL_GROUP_SIZE; i++) {
			sig = &group[i];
			init_completion(&sig->comp);
			sig->state = DSPSIGNAL_STATE_UNUSED;
		}
		spin_lock_irqsave(&fl->dspsignals_lock, irq_flags);
		fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE] = group;
	}

	sig = &group[signal_id %FASTRPC_DSPSIGNAL_GROUP_SIZE];
	if (sig->state != DSPSIGNAL_STATE_UNUSED) {
		spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
		mutex_unlock(&fl->signal_create_mutex);
		dev_err(fl->cctx->dev,"Attempting to create signal %u already in use (state %u)\n",
			    signal_id, sig->state);
		return -EBUSY;
	}

	sig->state = DSPSIGNAL_STATE_PENDING;
	reinit_completion(&sig->comp);

	spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
	mutex_unlock(&fl->signal_create_mutex);

	return err;
}

static int fastrpc_dspsignal_destroy(struct fastrpc_user *fl,
			      struct fastrpc_internal_dspsignal *fsig)
{
	u32 signal_id = fsig->signal_id;
	struct fastrpc_dspsignal *s = NULL;
	unsigned long irq_flags = 0;

	if (!(signal_id <FASTRPC_DSPSIGNAL_NUM_SIGNALS))
		return -EINVAL;

	spin_lock_irqsave(&fl->dspsignals_lock, irq_flags);

	if (fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE] != NULL) {
		struct fastrpc_dspsignal *group =
			fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE];

		s = &group[signal_id % FASTRPC_DSPSIGNAL_GROUP_SIZE];
	}
	if ((s == NULL) || (s->state == DSPSIGNAL_STATE_UNUSED)) {
		spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
		dev_err(fl->cctx->dev,"Attempting to destroy unused signal %u\n", signal_id);
		return -ENOENT;
	}

	s->state = DSPSIGNAL_STATE_UNUSED;
	complete_all(&s->comp);

	spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);

	return 0;
}

static int fastrpc_dspsignal_cancel_wait(struct fastrpc_user *fl,
				  struct fastrpc_internal_dspsignal *fsig)
{
	u32 signal_id = fsig->signal_id;
	struct fastrpc_dspsignal *s = NULL;
	unsigned long irq_flags = 0;

	if (!(signal_id <FASTRPC_DSPSIGNAL_NUM_SIGNALS))
		return -EINVAL;

	spin_lock_irqsave(&fl->dspsignals_lock, irq_flags);

	if (fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE] != NULL) {
		struct fastrpc_dspsignal *group =
			fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE];

		s = &group[signal_id %FASTRPC_DSPSIGNAL_GROUP_SIZE];
	}
	if ((s == NULL) || (s->state == DSPSIGNAL_STATE_UNUSED)) {
		spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
		dev_err(fl->cctx->dev,"Attempting to cancel unused signal %u\n", signal_id);
		return -ENOENT;
	}

	if (s->state != DSPSIGNAL_STATE_CANCELED) {
		s->state = DSPSIGNAL_STATE_CANCELED;
		complete_all(&s->comp);
	}

	spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);

	return 0;
}

static int fastrpc_invoke_dspsignal(struct fastrpc_user *fl, struct fastrpc_internal_dspsignal *fsig)
{
	int err = 0;

	switch(fsig->req) {
	case FASTRPC_DSPSIGNAL_SIGNAL:
		err = fastrpc_dspsignal_signal(fl,fsig);
		break;
	case FASTRPC_DSPSIGNAL_WAIT :
		err = fastrpc_dspsignal_wait(fl,fsig);
		break;
	case FASTRPC_DSPSIGNAL_CREATE :
		err = fastrpc_dspsignal_create(fl,fsig);
		break;
	case FASTRPC_DSPSIGNAL_DESTROY :
		err = fastrpc_dspsignal_destroy(fl,fsig);
		break;
	case FASTRPC_DSPSIGNAL_CANCEL_WAIT :
		err = fastrpc_dspsignal_cancel_wait(fl,fsig);
		break;
	}
	return err;
}

static int fastrpc_multimode_invoke(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_enhanced_invoke inv2 ;
	struct fastrpc_invoke_args *args = NULL;
	struct fastrpc_ioctl_multimode_invoke invoke;
	struct fastrpc_internal_control cp = {0};
	struct fastrpc_internal_dspsignal *fsig = NULL;
	struct fastrpc_internal_notif_rsp notif;
	u32 nscalars;
	u32 multisession;
	u64 *perf_kernel;
	int err = 0;

	if (copy_from_user(&invoke, argp, sizeof(invoke)))
		return -EFAULT;
	switch (invoke.req) {
	case FASTRPC_INVOKE:
	case FASTRPC_INVOKE_ENHANCED:
		/* nscalars is truncated here to max supported value */
		if (copy_from_user(&inv2, (void __user *)(uintptr_t)invoke.invparam,
				   invoke.size))
			return -EFAULT;
		nscalars = REMOTE_SCALARS_LENGTH(inv2.inv.sc);
		if (nscalars) {
			args = kcalloc(nscalars, sizeof(*args), GFP_KERNEL);
			if (!args)
				return -ENOMEM;
			if (copy_from_user(args, (void __user *)(uintptr_t)inv2.inv.args,
					   nscalars * sizeof(*args))) {
				kfree(args);
				return -EFAULT;
			}
		}
		inv2.inv.args = (__u64)args;
		perf_kernel = (u64 *)(uintptr_t)inv2.perf_kernel;
		if (perf_kernel)
			fl->profile = true;
		err = fastrpc_internal_invoke(fl, false, &inv2);
		kfree(args);
		break;
	case FASTRPC_INVOKE_CONTROL:
		if (copy_from_user(&cp, (void __user *)(uintptr_t)invoke.invparam, sizeof(cp)))
			return  -EFAULT;

		err = fastrpc_internal_control(fl, &cp);
		break;
	case FASTRPC_INVOKE_DSPSIGNAL:
		if (invoke.size > sizeof(*fsig))
			return -EINVAL;
		fsig = kzalloc(invoke.size, GFP_KERNEL);
		if (!fsig)
			return -ENOMEM;
		if (copy_from_user(fsig, (void __user *)(uintptr_t)invoke.invparam,
				invoke.size)) {
			kfree(fsig);
			return -EFAULT;
		}
		err = fastrpc_invoke_dspsignal(fl, fsig);
		kfree(fsig);
		break;
	case FASTRPC_INVOKE_NOTIF:
		err = fastrpc_get_notif_response(&notif,
						(void *)invoke.invparam, fl);
		break;
	case FASTRPC_INVOKE_MULTISESSION:
		if (copy_from_user(&multisession, (void __user *)(uintptr_t)invoke.invparam, sizeof(multisession)))
			return  -EFAULT;
		fl->sessionid = 1;
		fl->tgid |= SESSION_ID_MASK;
		break;
	default:
		err = -ENOTTY;
		break;
	}
	return err;
}

static int fastrpc_get_info_from_dsp(struct fastrpc_user *fl, uint32_t *dsp_attr_buf,
				     uint32_t dsp_attr_buf_len)
{
	struct fastrpc_invoke_args args[2] = { 0 };
	struct fastrpc_enhanced_invoke ioctl;

	/* Capability filled in userspace */
	dsp_attr_buf[0] = 0;
	dsp_attr_buf_len -= 1;

	args[0].ptr = (u64)(uintptr_t)&dsp_attr_buf_len;
	args[0].length = sizeof(dsp_attr_buf_len);
	args[0].fd = -1;
	args[1].ptr = (u64)(uintptr_t)&dsp_attr_buf[1];
	args[1].length = dsp_attr_buf_len * sizeof(uint32_t);
	args[1].fd = -1;

	ioctl.inv.handle = FASTRPC_DSP_UTILITIES_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(0, 1, 1);
	ioctl.inv.args = (__u64)args;

	return fastrpc_internal_invoke(fl, true, &ioctl);
}

static int fastrpc_get_info_from_kernel(struct fastrpc_ioctl_capability *cap,
					struct fastrpc_user *fl)
{
	struct fastrpc_channel_ctx *cctx = fl->cctx;
	uint32_t attribute_id = cap->attribute_id;
	uint32_t *dsp_attributes;
	unsigned long flags;
	uint32_t domain = cap->domain;
	int err;

	spin_lock_irqsave(&cctx->lock, flags);
	/* check if we already have queried dsp for attributes */
	if (cctx->valid_attributes) {
		spin_unlock_irqrestore(&cctx->lock, flags);
		goto done;
	}
	spin_unlock_irqrestore(&cctx->lock, flags);

	dsp_attributes = kzalloc(FASTRPC_MAX_DSP_ATTRIBUTES_LEN, GFP_KERNEL);
	if (!dsp_attributes)
		return -ENOMEM;

	err = fastrpc_get_info_from_dsp(fl, dsp_attributes, FASTRPC_MAX_DSP_ATTRIBUTES);
	if (err == DSP_UNSUPPORTED_API) {
		dev_info(cctx->dev,
			 "Warning: DSP capabilities not supported on domain: %d\n", domain);
		kfree(dsp_attributes);
		return -EOPNOTSUPP;
	} else if (err) {
		dev_err(cctx->dev, "Error: dsp information is incorrect err: %d\n", err);
		kfree(dsp_attributes);
		return err;
	}

	spin_lock_irqsave(&cctx->lock, flags);
	memcpy(cctx->dsp_attributes, dsp_attributes, FASTRPC_MAX_DSP_ATTRIBUTES_LEN);
	cctx->valid_attributes = true;
	spin_unlock_irqrestore(&cctx->lock, flags);
	kfree(dsp_attributes);
done:
	cap->capability = cctx->dsp_attributes[attribute_id];
	return 0;
}

static int fastrpc_get_dsp_info(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_ioctl_capability cap = {0};
	int err = 0;

	if (copy_from_user(&cap, argp, sizeof(cap)))
		return  -EFAULT;

	cap.capability = 0;
	if (cap.domain >= FASTRPC_DEV_MAX) {
		dev_err(fl->cctx->dev, "Error: Invalid domain id:%d, err:%d\n",
			cap.domain, err);
		return -ECHRNG;
	}

	/* Fastrpc Capablities does not support modem domain */
	if (cap.domain == MDSP_DOMAIN_ID) {
		dev_err(fl->cctx->dev, "Error: modem not supported %d\n", err);
		return -ECHRNG;
	}

	if (cap.attribute_id >= FASTRPC_MAX_DSP_ATTRIBUTES) {
		dev_err(fl->cctx->dev, "Error: invalid attribute: %d, err: %d\n",
			cap.attribute_id, err);
		return -EOVERFLOW;
	}

	err = fastrpc_get_info_from_kernel(&cap, fl);
	if (err)
		return err;

	if (copy_to_user(argp, &cap, sizeof(cap)))
		return -EFAULT;

	return 0;
}

static int fastrpc_req_munmap_dsp(struct fastrpc_user *fl, uintptr_t raddr, u64 size) {

	struct fastrpc_invoke_args args[1] = { [0] = { 0 } };
	struct fastrpc_enhanced_invoke ioctl;
	struct fastrpc_munmap_req_msg req_msg;
	int err = 0;

	req_msg.pgid = fl->tgid;
	req_msg.size = size;
	req_msg.vaddr = raddr;

	args[0].ptr = (u64) (uintptr_t) &req_msg;
	args[0].length = sizeof(req_msg);

	ioctl.inv.handle = FASTRPC_INIT_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_MUNMAP, 1, 0);
	ioctl.inv.args = (__u64)args;

	err = fastrpc_internal_invoke(fl, true, &ioctl);
	/* error to be printed by caller function */
	return err;

}

static int fastrpc_req_munmap_impl(struct fastrpc_user *fl, struct fastrpc_buf *buf)
{
	struct device *dev = fl->sctx->dev;
	int err;

	err = fastrpc_req_munmap_dsp(fl, buf->raddr, buf->size);
	if (!err) {
		if (buf->type == REMOTEHEAP_BUF) {
			if (fl->cctx->vmcount) {
				u64 src_perms = 0;
				struct qcom_scm_vmperm dst_perms;
				u32 i;

				for (i = 0; i < fl->cctx->vmcount; i++)
					src_perms |= BIT(fl->cctx->vmperms[i].vmid);

				dst_perms.vmid = QCOM_SCM_VMID_HLOS;
				dst_perms.perm = QCOM_SCM_PERM_RWX;
				err = qcom_scm_assign_mem(buf->phys, (u64)buf->size,
								&src_perms, &dst_perms, 1);
				if (err) {
					dev_err(fl->sctx->dev, "%s: Failed to assign memory phys 0x%llx size 0x%llx err %d",
						__func__, buf->phys, buf->size, err);
					return err;
				}
			}
		}
		dev_dbg(dev, "unmmap\tpt 0x%09lx OK\n", buf->raddr);
		spin_lock(&fl->lock);
		list_del(&buf->node);
		spin_unlock(&fl->lock);
		fastrpc_buf_free(buf, false);
	} else {
		dev_err(dev, "unmmap\tpt 0x%09lx ERROR\n", buf->raddr);
	}

	return err;
}

static int fastrpc_req_munmap(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_buf *buf = NULL, *iter, *b;
	struct fastrpc_req_munmap req;
	struct fastrpc_map *map = NULL, *iterm, *m;
	struct device *dev = fl->sctx->dev;
	int err = 0;
	unsigned long flags;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	spin_lock(&fl->lock);
	list_for_each_entry_safe(iter, b, &fl->mmaps, node) {
		if ((iter->raddr == req.vaddrout) && (iter->size == req.size)) {
			buf = iter;
			break;
		}
	}
	spin_unlock(&fl->lock);

	if (buf) {
		err = fastrpc_req_munmap_impl(fl, buf);
		return err;
	}

	spin_lock_irqsave(&fl->cctx->lock, flags);
	list_for_each_entry_safe(iter, b, &fl->cctx->gmaps, node) {
		if ((iter->raddr == req.vaddrout) && (iter->size == req.size)) {
			buf = iter;
			break;
		}
	}
	spin_unlock_irqrestore(&fl->cctx->lock, flags);
	if (buf) {
		err = fastrpc_req_munmap_impl(fl, buf);
		return err;
	} 
	spin_lock(&fl->lock);
	list_for_each_entry_safe(iterm, m, &fl->maps, node) {
		if (iterm->raddr == req.vaddrout) {
			map = iterm;
			break;
		}
	}
	spin_unlock(&fl->lock);
	if (!map) {
		dev_err(dev, "buffer not in buf or map list\n");
		return -EINVAL;
	}

	err = fastrpc_req_munmap_dsp(fl, map->raddr, map->size);
	if (err)
		dev_err(dev, "unmmap\tpt fd = %d, 0x%09llx error\n",  map->fd, map->raddr);
	else
		fastrpc_map_put(map);

	return err;
}

static int fastrpc_req_mmap(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_invoke_args args[3] = { [0 ... 2] = { 0 } };
	struct fastrpc_enhanced_invoke ioctl;
	struct fastrpc_buf *buf = NULL;
	struct fastrpc_mmap_req_msg req_msg;
	struct fastrpc_mmap_rsp_msg rsp_msg;
	struct fastrpc_phy_page pages;
	struct fastrpc_req_mmap req;
	struct fastrpc_map *map = NULL;
	struct device *dev = fl->sctx->dev;
	int err;
	unsigned long flags;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	if (req.flags == ADSP_MMAP_ADD_PAGES || req.flags == ADSP_MMAP_REMOTE_HEAP_ADDR) {
		if (req.flags == ADSP_MMAP_REMOTE_HEAP_ADDR && fl->is_unsigned_pd) {
			dev_err(dev, "secure memory allocation is not supported in unsigned PD\n");
			return -EINVAL;
		}
		if (req.vaddrin && !fl->is_unsigned_pd) {
			dev_err(dev, "adding user allocated pages is not supported\n");
			return -EINVAL;
		}

		if (req.flags == ADSP_MMAP_REMOTE_HEAP_ADDR) {
			err = fastrpc_remote_heap_alloc(fl, dev, req.size, REMOTEHEAP_BUF, &buf);
		} else {
			err = fastrpc_buf_alloc(fl, fl->sctx->dev, req.size, USER_BUF, &buf);
		}

		if (err) {
			dev_err(dev, "failed to allocate buffer\n");
			return err;
		}

		req_msg.pgid = fl->tgid;
		req_msg.flags = req.flags;
		req_msg.vaddr = req.vaddrin;
		req_msg.num = sizeof(pages);

		args[0].ptr = (u64) (uintptr_t) &req_msg;
		args[0].length = sizeof(req_msg);

		pages.addr = buf->phys;
		pages.size = buf->size;

		args[1].ptr = (u64) (uintptr_t) &pages;
		args[1].length = sizeof(pages);

		args[2].ptr = (u64) (uintptr_t) &rsp_msg;
		args[2].length = sizeof(rsp_msg);

		ioctl.inv.handle = FASTRPC_INIT_HANDLE;
		ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_MMAP, 2, 1);
		ioctl.inv.args = (__u64)args;

		err = fastrpc_internal_invoke(fl, true, &ioctl);
		if (err) {
			dev_err(dev, "mmap error (len 0x%08llx)\n", buf->size);
			goto err_invoke;
		}

		/* update the buffer to be able to deallocate the memory on the DSP */
		buf->raddr = (uintptr_t) rsp_msg.vaddr;

		/* let the client know the address to use */
		req.vaddrout = rsp_msg.vaddr;

		/* Add memory to static PD pool, protection thru hypervisor */
		if (req.flags == ADSP_MMAP_REMOTE_HEAP_ADDR && fl->cctx->vmcount) {
			u64 src_perms = BIT(QCOM_SCM_VMID_HLOS);

			err = qcom_scm_assign_mem(buf->phys,(u64)buf->size,
				&src_perms, fl->cctx->vmperms, fl->cctx->vmcount);
			if (err) {
				dev_err(fl->sctx->dev, "Failed to assign memory phys 0x%llx size 0x%llx err %d",
						buf->phys, buf->size, err);
				goto err_assign;
			}
		}
		
		if (req.flags == ADSP_MMAP_REMOTE_HEAP_ADDR) {
			spin_lock_irqsave(&fl->cctx->lock, flags);
			list_add_tail(&buf->node, &fl->cctx->gmaps);
			spin_unlock_irqrestore(&fl->cctx->lock, flags);
		} else {
			spin_lock(&fl->lock);
			list_add_tail(&buf->node, &fl->mmaps);
			spin_unlock(&fl->lock);
		}

		if (copy_to_user((void __user *)argp, &req, sizeof(req))) {
			err = -EFAULT;
			goto err_assign;
		}
	} else {
		err = fastrpc_map_create(fl, req.fd, req.vaddrin, req.size, 0, &map, true);
		if (err) {
			dev_err(dev, "failed to map buffer, fd = %d\n", req.fd);
			return err;
		}

		req_msg.pgid = fl->tgid;
		req_msg.flags = req.flags;
		req_msg.vaddr = req.vaddrin;
		req_msg.num = sizeof(pages);

		args[0].ptr = (u64) (uintptr_t) &req_msg;
		args[0].length = sizeof(req_msg);

		pages.addr = map->phys;
		pages.size = map->size;

		args[1].ptr = (u64) (uintptr_t) &pages;
		args[1].length = sizeof(pages);

		args[2].ptr = (u64) (uintptr_t) &rsp_msg;
		args[2].length = sizeof(rsp_msg);

		ioctl.inv.handle = FASTRPC_INIT_HANDLE;
		ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_MMAP, 2, 1);
		ioctl.inv.args = (__u64)args;

		err = fastrpc_internal_invoke(fl, true, &ioctl);
		if (err) {
			dev_err(dev, "mmap error (len 0x%08llx)\n", map->size);
			goto err_invoke;
		}

		/* update the buffer to be able to deallocate the memory on the DSP */
		map->raddr = (uintptr_t) rsp_msg.vaddr;

		/* let the client know the address to use */
		req.vaddrout = rsp_msg.vaddr;

		if (copy_to_user((void __user *)argp, &req, sizeof(req))) {
			err = -EFAULT;
			goto err_assign;
		}
	}
	return 0;

err_assign:
	if (req.flags != ADSP_MMAP_ADD_PAGES && req.flags != ADSP_MMAP_REMOTE_HEAP_ADDR)
		fastrpc_map_put(map);
	else
		fastrpc_req_munmap_impl(fl, buf);

err_invoke:
	if (map)
		fastrpc_map_put(map);
	if (buf)
		fastrpc_buf_free(buf, false);

	return err;
}

static int fastrpc_req_mem_unmap_impl(struct fastrpc_user *fl, struct fastrpc_mem_unmap *req)
{
	struct fastrpc_invoke_args args[1] = { [0] = { 0 } };
	struct fastrpc_enhanced_invoke ioctl;
	struct fastrpc_map *map = NULL, *iter, *m;
	struct fastrpc_mem_unmap_req_msg req_msg = { 0 };
	int err = 0;
	struct device *dev = fl->sctx->dev;

	spin_lock(&fl->lock);
	list_for_each_entry_safe(iter, m, &fl->maps, node) {
		if ((req->fd < 0 || iter->fd == req->fd) && (iter->raddr == req->vaddr)) {
			map = iter;
			break;
		}
	}

	spin_unlock(&fl->lock);

	if (!map) {
		dev_err(dev, "map not in list\n");
		return -EINVAL;
	}

	req_msg.pgid = fl->tgid;
	req_msg.len = map->len;
	req_msg.vaddrin = map->raddr;
	req_msg.fd = map->fd;

	args[0].ptr = (u64) (uintptr_t) &req_msg;
	args[0].length = sizeof(req_msg);

	ioctl.inv.handle = FASTRPC_INIT_HANDLE;
	ioctl.inv.sc = FASTRPC_SCALARS(FASTRPC_RMID_INIT_MEM_UNMAP, 1, 0);
	ioctl.inv.args = (__u64)args;

	err = fastrpc_internal_invoke(fl, true, &ioctl);
	if (err) {
		dev_err(dev, "Unmap on DSP failed for fd:%d, addr:0x%09llx\n",  map->fd, map->raddr);
		return err;
	}
	fastrpc_map_put(map);

	return 0;
}

static int fastrpc_req_mem_unmap(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_mem_unmap req;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	return fastrpc_req_mem_unmap_impl(fl, &req);
}

static int fastrpc_req_mem_map(struct fastrpc_user *fl, char __user *argp)
{
	struct fastrpc_mem_unmap req_unmap = { 0 };
	struct fastrpc_mem_map req = {0};
	struct device *dev = fl->sctx->dev;
	struct fastrpc_map *map = NULL;
	int err;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	/* create SMMU mapping */
	err = fastrpc_map_create(fl, req.fd, req.vaddrin, req.length, 0, &map, true);
	if (err) {
		dev_err(dev, "failed to map buffer, fd = %d\n", req.fd);
		return err;
	}

	map->va = (void *) (uintptr_t) req.vaddrin;
	/* map to dsp, get virtual adrress for the user*/
	err = fastrpc_mem_map_to_dsp(fl, map->fd, req.offset,
					req.flags, req.vaddrin, map->phys,
					map->size, (uintptr_t *)&req.vaddrout);
	if (err) {
		dev_err(dev, "failed to map buffer on dsp, fd = %d\n", map->fd);
		goto err_invoke;
	}

	/* update the buffer to be able to deallocate the memory on the DSP */
	map->raddr = req.vaddrout;

	if (copy_to_user((void __user *)argp, &req, sizeof(req))) {
		/* unmap the memory and release the buffer */
		req_unmap.vaddr = (uintptr_t)req.vaddrout;
		req_unmap.length = map->size;
		fastrpc_req_mem_unmap_impl(fl, &req_unmap);
		return -EFAULT;
	}

	return 0;
err_invoke:
	fastrpc_map_put(map);

	return err;
}

static long fastrpc_device_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	struct fastrpc_user *fl = (struct fastrpc_user *)file->private_data;
	char __user *argp = (char __user *)arg;
	int err;

	switch (cmd) {
	case FASTRPC_IOCTL_INVOKE:
		err = fastrpc_invoke(fl, argp);
		break;
	case FASTRPC_IOCTL_MULTIMODE_INVOKE:
		err = fastrpc_multimode_invoke(fl, argp);
		break;
	case FASTRPC_IOCTL_INIT_ATTACH:
		err = fastrpc_init_attach(fl, ROOT_PD);
		fastrpc_send_cpuinfo_to_dsp(fl);
		break;
	case FASTRPC_IOCTL_INIT_ATTACH_SNS:
		err = fastrpc_init_attach(fl, SENSORS_PD);
		break;
	case FASTRPC_IOCTL_INIT_CREATE_STATIC:
		err = fastrpc_init_create_static_process(fl, argp);
		break;
	case FASTRPC_IOCTL_INIT_CREATE:
		err = fastrpc_init_create_process(fl, argp);
		break;
	case FASTRPC_IOCTL_ALLOC_DMA_BUFF:
		err = fastrpc_dmabuf_alloc(fl, argp);
		break;
	case FASTRPC_IOCTL_MMAP:
		err = fastrpc_req_mmap(fl, argp);
		break;
	case FASTRPC_IOCTL_MUNMAP:
		err = fastrpc_req_munmap(fl, argp);
		break;
	case FASTRPC_IOCTL_MEM_MAP:
		err = fastrpc_req_mem_map(fl, argp);
		break;
	case FASTRPC_IOCTL_MEM_UNMAP:
		err = fastrpc_req_mem_unmap(fl, argp);
		break;
	case FASTRPC_IOCTL_GET_DSP_INFO:
		err = fastrpc_get_dsp_info(fl, argp);
		break;
	default:
		err = -ENOTTY;
		break;
	}

	return err;
}

int fastrpc_init_privileged_gids(struct device *dev, char *prop_name,
						struct gid_list *gidlist)
{
	int err = 0;
	u32 len = 0, i;
	u32 *gids = NULL;

	if (!of_find_property(dev->of_node, prop_name, &len))
		return 0;
	if (len == 0)
		return 0;

	len /= sizeof(u32);
	gids = kcalloc(len, sizeof(u32), GFP_KERNEL);
	if (!gids)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		err = of_property_read_u32_index(dev->of_node, prop_name,
								i, &gids[i]);
		if (err) {
			dev_err(dev, "%s: failed to read GID %u\n",
					__func__, i);
			goto read_error;
		}
		dev_info(dev, "adsprpc: %s: privileged GID: %u\n", __func__, gids[i]);
	}
	sort(gids, len, sizeof(*gids), uint_cmp_func, NULL);
	gidlist->gids = gids;
	gidlist->gidcount = len;

	return 0;
read_error:
	kfree(gids);
	return err;
}

void fastrpc_notify_users(struct fastrpc_user *user)
{
	struct fastrpc_invoke_ctx *ctx;

	spin_lock(&user->lock);
	list_for_each_entry(ctx, &user->pending, node) {
		ctx->retval = -EPIPE;
		ctx->is_work_done = true;
		complete(&ctx->work);
	}
	list_for_each_entry(ctx, &user->interrupted, node) {
		ctx->retval = -EPIPE;
		ctx->is_work_done = true;
		complete(&ctx->work);
	}
	spin_unlock(&user->lock);
}

static void fastrpc_notify_pdr_drivers(struct fastrpc_channel_ctx *cctx,
		char *servloc_name)
{
	struct fastrpc_user *fl;
	unsigned long flags;

	spin_lock_irqsave(&cctx->lock, flags);
	list_for_each_entry(fl, &cctx->users, user) {
		if (fl->servloc_name && !strcmp(servloc_name, fl->servloc_name))
			fastrpc_notify_users(fl);
	}
	spin_unlock_irqrestore(&cctx->lock, flags);
}

static void fastrpc_pdr_cb(int state, char *service_path, void *priv)
{
	struct fastrpc_static_pd *spd = (struct fastrpc_static_pd *)priv;
	struct fastrpc_channel_ctx *cctx;
	unsigned long flags;

	if (!spd)
		return;

	cctx = spd->cctx;
	switch (state) {
	case SERVREG_SERVICE_STATE_DOWN:
		pr_info("fastrpc: %s: %s (%s) is down for PDR on %s\n",
			__func__, spd->spdname,
			spd->servloc_name,
			domains[cctx->domain_id]);
		spin_lock_irqsave(&cctx->lock, flags);
		spd->pdrcount++;
		atomic_set(&spd->ispdup, 0);
		spin_unlock_irqrestore(&cctx->lock, flags);
		if (!strcmp(spd->servloc_name,
				AUDIO_PDR_SERVICE_LOCATION_CLIENT_NAME))
			cctx->staticpd_status = false;

		fastrpc_notify_pdr_drivers(cctx, spd->servloc_name);
		break;
	case SERVREG_SERVICE_STATE_UP:
		pr_info("fastrpc: %s: %s (%s) is up for PDR on %s\n",
			__func__, spd->spdname,
			spd->servloc_name,
			domains[cctx->domain_id]);
		atomic_set(&spd->ispdup, 1);
		break;
	default:
		break;
	}
	return;
}

static const struct file_operations fastrpc_fops = {
	.open = fastrpc_device_open,
	.release = fastrpc_device_release,
	.unlocked_ioctl = fastrpc_device_ioctl,
	.compat_ioctl = fastrpc_device_ioctl,
};

static int fastrpc_cb_probe(struct platform_device *pdev)
{
	struct fastrpc_channel_ctx *cctx;
	struct fastrpc_session_ctx *sess;
	struct device *dev = &pdev->dev;
	int i, sessions = 0;
	unsigned long flags;
	int rc, err = 0;
	struct fastrpc_buf *buf = NULL;
	struct iommu_domain *domain = NULL;
	struct gen_pool *gen_pool = NULL;
	int frpc_gen_addr_pool[2] = {0, 0};
	struct sg_table sgt;

	cctx = get_current_channel_ctx(dev);

	if (IS_ERR_OR_NULL(cctx))
		return -EINVAL;

	of_property_read_u32(dev->of_node, "qcom,nsessions", &sessions);

	spin_lock_irqsave(&cctx->lock, flags);
	if (cctx->sesscount >= FASTRPC_MAX_SESSIONS) {
		dev_err(&pdev->dev, "too many sessions\n");
		spin_unlock_irqrestore(&cctx->lock, flags);
		return -ENOSPC;
	}
	sess = &cctx->session[cctx->sesscount++];
	sess->used = false;
	sess->valid = true;
	sess->dev = dev;
	dev_set_drvdata(dev, sess);

	if (of_property_read_u32(dev->of_node, "reg", &sess->sid))
		dev_info(dev, "FastRPC Session ID not specified in DT\n");

	if (sessions > 0) {
		struct fastrpc_session_ctx *dup_sess;

		sess->sharedcb = true;
		for (i = 1; i < sessions; i++) {
			if (cctx->sesscount >= FASTRPC_MAX_SESSIONS)
				break;
			dup_sess = &cctx->session[cctx->sesscount++];
			memcpy(dup_sess, sess, sizeof(*dup_sess));
		}
	}
	spin_unlock_irqrestore(&cctx->lock, flags);
	if (of_get_property(dev->of_node, "qrtr-gen-pool", NULL) != NULL) {

		err = of_property_read_u32_array(dev->of_node, "frpc-gen-addr-pool",
							frpc_gen_addr_pool, 2);
		if (err) {
			dev_err(&pdev->dev, "Error: parsing frpc-gen-addr-pool arguments failed for %s with err %d\n",
					dev_name(dev), err);
			goto bail;
		}
		sess->genpool_iova = frpc_gen_addr_pool[0];
		sess->genpool_size = frpc_gen_addr_pool[1];

		buf = kzalloc(sizeof(*buf), GFP_KERNEL);
		if (IS_ERR_OR_NULL(buf)) {
			err = -ENOMEM;
			dev_err(&pdev->dev, "allocation failed for size 0x%zx\n", sizeof(*buf));
			goto bail;
		}
		INIT_LIST_HEAD(&buf->attachments);
		INIT_LIST_HEAD(&buf->node);
		mutex_init(&buf->lock);
		buf->virt = NULL;
		buf->phys = 0;
		buf->size = frpc_gen_addr_pool[1];
		buf->dev = NULL;
		buf->raddr = 0;


		/* Allocate memory for adding to genpool */
		buf->virt = dma_alloc_coherent(sess->dev, buf->size,
					(dma_addr_t *)&buf->phys, GFP_KERNEL);

		if (IS_ERR_OR_NULL(buf->virt)) {
			dev_err(&pdev->dev, "dma_alloc failed for size 0x%zx, returned %pK\n",
				buf->size, buf->virt);
			err = -ENOBUFS;
			goto dma_alloc_bail;
		}

		err = dma_get_sgtable(sess->dev, &sgt, buf->virt,
				buf->phys, buf->size);
		if (err) {
			dev_err(&pdev->dev, "dma_get_sgtable_attrs failed with err %d", err);
				goto iommu_map_bail;
		}
		domain = iommu_get_domain_for_dev(sess->dev);
		if (!domain) {
			dev_err(&pdev->dev, "iommu_get_domain_for_dev failed ");
			goto iommu_map_bail;
		}

		/* Map the allocated memory with fixed IOVA and is shared to remote subsystem */
		err = iommu_map_sg(domain, frpc_gen_addr_pool[0], sgt.sgl,
				sgt.nents, IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE);
		if (err < 0) {
			dev_err(&pdev->dev, "iommu_map_sg failed with err %d", err);
			goto iommu_map_bail;
		}

		/* Create genpool using SMMU device */
		gen_pool = devm_gen_pool_create(sess->dev, 0, NUMA_NO_NODE, NULL);
		if (IS_ERR(gen_pool)) {
			err = PTR_ERR(gen_pool);
			dev_err(&pdev->dev, "devm_gen_pool_create failed with err %d", err);
			goto genpool_create_bail;
		}
		/* Add allocated memory to genpool */
		err = gen_pool_add_virt(gen_pool, (unsigned long)buf->virt,
				buf->phys, buf->size, NUMA_NO_NODE);
		if (err) {
				dev_err(&pdev->dev, "gen_pool_add_virt failed with err %d", err);
			goto genpool_add_bail;
		}
		sess->frpc_genpool = gen_pool;
		sess->frpc_genpool_buf = buf;
		dev_err(&pdev->dev, "fastrpc_cb_probe qrtr-gen-pool end\n");
	}
	rc = dma_set_mask(dev, DMA_BIT_MASK(32));
	if (rc) {
		dev_err(dev, "32-bit DMA enable failed\n");
		return rc;
	}

bail:
	return err;
genpool_add_bail:
	gen_pool_destroy(gen_pool);
genpool_create_bail:
	iommu_unmap(domain, sess->genpool_iova, sess->genpool_size);
iommu_map_bail:
	dma_free_coherent(sess->dev, buf->size, buf->virt, FASTRPC_PHYS(buf->phys));
dma_alloc_bail:
	kfree(buf);
	return err;
}

static int fastrpc_cb_remove(struct platform_device *pdev)
{
	struct fastrpc_channel_ctx *cctx = dev_get_drvdata(pdev->dev.parent);
	struct fastrpc_session_ctx *sess = dev_get_drvdata(&pdev->dev);
	unsigned long flags;
	int i;

	spin_lock_irqsave(&cctx->lock, flags);
	for (i = 1; i < FASTRPC_MAX_SESSIONS; i++) {
		if (cctx->session[i].sid == sess->sid) {
			cctx->session[i].valid = false;
			cctx->sesscount--;
		}
	}
	spin_unlock_irqrestore(&cctx->lock, flags);

	return 0;
}

static const struct of_device_id fastrpc_match_table[] = {
	{ .compatible = "qcom,fastrpc-compute-cb", },
	{}
};

static struct platform_driver fastrpc_cb_driver = {
	.probe = fastrpc_cb_probe,
	.remove = fastrpc_cb_remove,
	.driver = {
		.name = "qcom,fastrpc-cb",
		.of_match_table = fastrpc_match_table,
		.suppress_bind_attrs = true,
	},
};

int fastrpc_device_register(struct device *dev, struct fastrpc_channel_ctx *cctx,
				   bool is_secured, const char *domain)
{
	struct fastrpc_device *fdev;
	int err;

	fdev = devm_kzalloc(dev, sizeof(*fdev), GFP_KERNEL);
	if (!fdev)
		return -ENOMEM;

	fdev->secure = is_secured;
	fdev->cctx = cctx;
	cctx->dev = dev;
	fdev->miscdev.minor = MISC_DYNAMIC_MINOR;
	fdev->miscdev.fops = &fastrpc_fops;
	fdev->miscdev.name = devm_kasprintf(dev, GFP_KERNEL, "fastrpc-%s%s",
					    domain, is_secured ? "-secure" : "");
	if (!fdev->miscdev.name)
		return -ENOMEM;

	err = misc_register(&fdev->miscdev);
	if (!err) {
		if (is_secured)
			cctx->secure_fdevice = fdev;
		else
			cctx->fdevice = fdev;
	}

	return err;
}

void fastrpc_lowest_capacity_corecount(struct fastrpc_channel_ctx *cctx)
{
	u32 cpu = 0;

	cpu =  cpumask_first(cpu_possible_mask);
	for_each_cpu(cpu, cpu_possible_mask) {
		if (topology_cluster_id(cpu) == 0)
			cctx->lowest_capacity_core_count++;
	}
	dev_info(cctx->dev, "lowest capacity core count: %u\n",
					cctx->lowest_capacity_core_count);
}

int fastrpc_setup_service_locator(struct fastrpc_channel_ctx *cctx, char *client_name,
					char *service_name, char *service_path, int spd_session)
{
	int err = 0;
	struct pdr_handle *handle = NULL;
	struct pdr_service *service = NULL;

	/* Register the service locator's callback function */
	handle = pdr_handle_alloc(fastrpc_pdr_cb, &cctx->spd[spd_session]);
	if (IS_ERR(handle)) {
		err = PTR_ERR(handle);
		goto bail;
	}
	cctx->spd[spd_session].pdrhandle = handle;
	cctx->spd[spd_session].servloc_name = client_name;
	cctx->spd[spd_session].spdname = service_path;
	cctx->spd[spd_session].cctx = cctx;
	service = pdr_add_lookup(handle, service_name, service_path);
	if (IS_ERR(service)) {
		err = PTR_ERR(service);
		goto bail;
	}
	pr_info("fastrpc: %s: pdr_add_lookup enabled for %s (%s, %s)\n",
		__func__, service_name, client_name, service_path);

bail:
	if (err) {
		pr_err("fastrpc: %s: failed for %s (%s, %s)with err %d\n",
				__func__, service_name, client_name, service_path, err);
	}
	return err;
}

void fastrpc_register_wakeup_source(struct device *dev,
	const char *client_name, struct wakeup_source **device_wake_source)
{
	struct wakeup_source *wake_source = NULL;

	wake_source = wakeup_source_register(dev, client_name);
	if (IS_ERR_OR_NULL(wake_source)) {
		dev_err(dev, "wakeup_source_register failed for dev %s, client %s with err %ld\n",
		dev_name(dev), client_name, PTR_ERR(wake_source));
		return;
	}

	*device_wake_source = wake_source;
}

static void fastrpc_notify_user_ctx(struct fastrpc_invoke_ctx *ctx, int retval,
		u32 rsp_flags, u32 early_wake_time)
{
	ctx->retval = retval;
	ctx->rsp_flags = (enum fastrpc_response_flags)rsp_flags;
	switch (rsp_flags) {
	case NORMAL_RESPONSE:
	case COMPLETE_SIGNAL:
		/* normal and complete response with return value */
		ctx->is_work_done = true;
		complete(&ctx->work);
		break;
	case USER_EARLY_SIGNAL:
		/* user hint of approximate time of completion */
		ctx->early_wake_time = early_wake_time;
		break;
	case EARLY_RESPONSE:
		/* rpc framework early response with return value */
		complete(&ctx->work);
		break;
	default:
		break;
	}
}

static void fastrpc_handle_signal_rpmsg(uint64_t msg, struct fastrpc_channel_ctx *cctx)
{
	u32 pid = msg >> 32;
	u32 signal_id = msg & 0xffffffff;
	struct fastrpc_user *fl ;
	unsigned long irq_flags = 0;

	if (signal_id >=FASTRPC_DSPSIGNAL_NUM_SIGNALS)
		return;

	list_for_each_entry(fl, &cctx->users, user) {
		if(fl->tgid == pid)
			break;
	}

	spin_lock_irqsave(&fl->dspsignals_lock, irq_flags);
	if (fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE]) {
		struct fastrpc_dspsignal *group =
			fl->signal_groups[signal_id /FASTRPC_DSPSIGNAL_GROUP_SIZE];
		struct fastrpc_dspsignal *sig =
			&group[signal_id %FASTRPC_DSPSIGNAL_GROUP_SIZE];
		if ((sig->state == DSPSIGNAL_STATE_PENDING) ||
			(sig->state == DSPSIGNAL_STATE_SIGNALED)) {
			complete(&sig->comp);
			sig->state = DSPSIGNAL_STATE_SIGNALED;
		} else if (sig->state == DSPSIGNAL_STATE_UNUSED) {
			pr_err("Received unknown signal %u for PID %u\n",
					signal_id, pid);
		}
	} else {
		pr_err("Received unknown signal %u for PID %u\n",
				signal_id, pid);
	}
	spin_unlock_irqrestore(&fl->dspsignals_lock, irq_flags);
}

int fastrpc_handle_rpc_response(struct fastrpc_channel_ctx *cctx, void *data, int len)
{
	struct fastrpc_invoke_rsp *rsp = data;
	struct fastrpc_invoke_rspv2 *rspv2 = NULL;
	struct dsp_notif_rsp *notif = (struct dsp_notif_rsp *)data;
	struct fastrpc_invoke_ctx *ctx;
	unsigned long flags;
	unsigned long ctxid;
	u32 rsp_flags = 0;
	u32 early_wake_time = 0;

	if (len == sizeof(uint64_t)) {
		fastrpc_handle_signal_rpmsg(*((uint64_t *)data), cctx);
		return 0;
	}

	if (notif->ctx == FASTRPC_NOTIF_CTX_RESERVED) {
		if (notif->type == STATUS_RESPONSE && len >= sizeof(*notif)) {
			fastrpc_notif_find_process(cctx->domain_id, cctx, notif);
			return 0;
		} else {
			return -ENOENT;
		}
	}

	if (len < sizeof(*rsp))
		return -EINVAL;
	fastrpc_update_rxmsg_buf(cctx, rsp->ctx, rsp->retval, get_timestamp_in_ns());

	if (len >= sizeof(*rspv2)) {
		rspv2 = data;
		if (rspv2) {
			early_wake_time = rspv2->early_wake_time;
			rsp_flags = rspv2->flags;
		}
	}
	ctxid = ((rsp->ctx & FASTRPC_CTXID_MASK) >> 4);

	spin_lock_irqsave(&cctx->lock, flags);
	ctx = idr_find(&cctx->ctx_idr, ctxid);

	if (!ctx) {
		dev_info(cctx->dev, "Warning: No context ID matches response\n");
		spin_unlock_irqrestore(&cctx->lock, flags);
		return 0;
	}

	if (rspv2) {
		if (rspv2->version != FASTRPC_RSP_VERSION2) {
			dev_err(cctx->dev, "Incorrect response version %d\n", rspv2->version);
			spin_unlock_irqrestore(&cctx->lock, flags);
			return -EINVAL;
		}
	}
	fastrpc_notify_user_ctx(ctx, rsp->retval, rsp_flags, early_wake_time);
	spin_unlock_irqrestore(&cctx->lock, flags);
	/*
	 * The DMA buffer associated with the context cannot be freed in
	 * interrupt context so schedule it through a worker thread to
	 * avoid a kernel BUG.
	 */
	// schedule_work(&ctx->put_work);

	return 0;
}

static int fastrpc_init(void)
{
	int ret;

	ret = platform_driver_register(&fastrpc_cb_driver);
	if (ret < 0) {
		pr_err("fastrpc: failed to register cb driver\n");
		return ret;
	}

	ret = fastrpc_transport_init();
	if (ret < 0) {
		pr_err("fastrpc: failed to register rpmsg driver\n");
		platform_driver_unregister(&fastrpc_cb_driver);
		return ret;
	}

	return 0;
}
module_init(fastrpc_init);

static void fastrpc_exit(void)
{
	platform_driver_unregister(&fastrpc_cb_driver);
	fastrpc_transport_deinit();
}
module_exit(fastrpc_exit);

MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS(DMA_BUF);
