/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Copyright (c) 2024 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _COMPAT_SECKERNEL__H
#define _COMPAT_SECKERNEL__H


/* These types are common across all compat ABIs */
#ifndef compat_size_t
typedef __u32 compat_size_t;
#endif
#ifndef compat_ssize_t
typedef __s32 compat_ssize_t;
#endif
#ifndef compat_clock_t
typedef __s32 compat_clock_t;
#endif
#ifndef compat_pid_t
typedef __s32 compat_pid_t;
#endif
#ifndef compat_ino_t
typedef __u32 compat_ino_t;
#endif
#ifndef compat_off_t
typedef __s32 compat_off_t;
#endif
#ifndef compat_loff_t
typedef __s64 compat_loff_t;
#endif
#ifndef compat_daddr_t
typedef __s32 compat_daddr_t;
#endif
#ifndef compat_timer_t
typedef __s32 compat_timer_t;
#endif
#ifndef compat_key_t
typedef __s32 compat_key_t;
#endif
#ifndef compat_short_t
typedef __s16 compat_short_t;
#endif
#ifndef compat_int_t
typedef __s32 compat_int_t;
#endif
#ifndef compat_long_t
typedef __s32 compat_long_t;
#endif
#ifndef compat_ushort_t
typedef __u16 compat_ushort_t;
#endif
#ifndef compat_uint_t
typedef __u32 compat_uint_t;
#endif
#ifndef compat_ulong_t
typedef __u32 compat_ulong_t;
#endif
#ifndef compat_uptr_t
typedef __u32 compat_uptr_t;
#endif
#ifndef compat_caddr_t
typedef __u32 compat_caddr_t;
#endif
#ifndef compat_old_sigset_t
typedef __u32 compat_old_sigset_t;
#endif

#endif /* _COMPAT_SECKERNEL__H */
