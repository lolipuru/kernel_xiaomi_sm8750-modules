/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2024, Qualcomm Innovation Center, Inc. All rights reserved.
 */

#if !defined(_MSM_CVP_EVENTS_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _MSM_CVP_EVENTS_H_

#include <linux/types.h>
#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM msm_cvp

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE msm_cvp_events

// Since Chrome supports to parse the event “tracing_mark_write” by default
// so we can re-use this to display your own events in Chrome
// enable command as below:
// adb shell "echo 1 > /sys/kernel/tracing/events/msm_cvp/tracing_mark_write/enable"
TRACE_EVENT(tracing_mark_write,
	TP_PROTO(int pid, const char *name, bool trace_begin),
	TP_ARGS(pid, name, trace_begin),
	TP_STRUCT__entry(
		__field(int, pid)
		__string(trace_name, name)
		__field(bool, trace_begin)
	),
	TP_fast_assign(
		__entry->pid = pid;
		__assign_str(trace_name, name);
		__entry->trace_begin = trace_begin;
		),
	TP_printk("%s|%d|%s", __entry->trace_begin ? "B" : "E",
		__entry->pid, __get_str(trace_name))
)
#define CVPKERNEL_ATRACE_END(name) \
		trace_tracing_mark_write(current->tgid, name, 0)
#define CVPKERNEL_ATRACE_BEGIN(name) \
		trace_tracing_mark_write(current->tgid, name, 1)

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#include <trace/define_trace.h>
