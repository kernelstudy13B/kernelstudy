/*
 * This file contains shadow memory manipulation code.
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
 *
 * Some code borrowed from https://github.com/xairy/kasan-prototype by
 *        Andrey Konovalov <adech.fo@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#define DISABLE_BRANCH_PROFILING

#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/linkage.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include "kasan.h"
#include "../slab.h"

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 */
//addr에서 시작하는 size 바이트들을 위해 쉐도우메모리를 poison한다
static void kasan_poison_shadow(const void *address, size_t size, u8 value)
{
	//함수의 명칭은 poison 이지만 결국 value가 0이므로 unpoison
	void *shadow_start, *shadow_end;

	shadow_start = kasan_mem_to_shadow(address);
	shadow_end = kasan_mem_to_shadow(address + size);
	//주소마다 쉐도우 매핑.

	memset(shadow_start, value, shadow_end - shadow_start);
	//0으로 poison??????(결국은 unpoison)
}

void kasan_unpoison_shadow(const void *address, size_t size)
{
	kasan_poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
		//쉐도우 값을 넣을 주소를 먼저 찾음
		//유효성 검사를 하고 싶은 주소공간을 담음
		*shadow = size & KASAN_SHADOW_MASK;//이 마스크는 7
		//8바이트내에서 어떤 값이 유효한지를 파악... 찾은 주소에 비트마스킹 값을 삽입
		//마지막에 align되지 않는 비트에 대한처리
	}
}

static void __kasan_unpoison_stack(struct task_struct *task, void *sp)
{
	void *base = task_stack_page(task);
	size_t size = sp - base;//THREAD_SIZE가 됨??

	kasan_unpoison_shadow(base, size);
	//stack_canary는 런타임에서, 그러나 kasan은 컴파일단계에서 
	//poison : 검사를 위한 어떤 값을 넣는다?, 
	//unposion : 검사를 위한 어떤 값을 뺴는거?, 0으로 바꿈 즉 legal access로 바꿔줌
	//shadow : 일종의 테이블, 0이면 8바이트가 전부 엑세스가 가능, 1~7이면 엑세스 가능한 주소값의 갯수가 들어감
}

/* Unpoison the entire stack for a task. */
void kasan_unpoison_task_stack(struct task_struct *task)
{
	//kasan : 동적 메모리 에러 감지.
	//init_idle과 직접적인 연관이 있는건지??
	//메모리 접근 체크를 위한 컴파일 타임 작동에 사용
	__kasan_unpoison_stack(task, task_stack_page(task) + THREAD_SIZE);
}

/* Unpoison the stack for the current task beyond a watermark sp value. */
asmlinkage void kasan_unpoison_remaining_stack(void *sp)
{
	__kasan_unpoison_stack(current, sp);
}

/*
 * All functions below always inlined so compiler could
 * perform better optimizations in each of __asan_loadX/__assn_storeX
 * depending on memory access size X.
 */

static __always_inline bool memory_is_poisoned_1(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(shadow_value)) {
		s8 last_accessible_byte = addr & KASAN_SHADOW_MASK;
		return unlikely(last_accessible_byte >= shadow_value);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_2(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 1))
			return true;

		/*
		 * If single shadow byte covers 2-byte access, we don't
		 * need to do anything more. Otherwise, test the first
		 * shadow byte.
		 */
		if (likely(((addr + 1) & KASAN_SHADOW_MASK) != 0))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_4(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 3))
			return true;

		/*
		 * If single shadow byte covers 4-byte access, we don't
		 * need to do anything more. Otherwise, test the first
		 * shadow byte.
		 */
		if (likely(((addr + 3) & KASAN_SHADOW_MASK) >= 3))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_8(unsigned long addr)
{
	u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(*shadow_addr)) {
		if (memory_is_poisoned_1(addr + 7))
			return true;

		/*
		 * If single shadow byte covers 8-byte access, we don't
		 * need to do anything more. Otherwise, test the first
		 * shadow byte.
		 */
		if (likely(IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
			return false;

		return unlikely(*(u8 *)shadow_addr);
	}

	return false;
}

static __always_inline bool memory_is_poisoned_16(unsigned long addr)
{
	u32 *shadow_addr = (u32 *)kasan_mem_to_shadow((void *)addr);

	if (unlikely(*shadow_addr)) {
		u16 shadow_first_bytes = *(u16 *)shadow_addr;

		if (unlikely(shadow_first_bytes))
			return true;

		/*
		 * If two shadow bytes covers 16-byte access, we don't
		 * need to do anything more. Otherwise, test the last
		 * shadow byte.
		 */
		if (likely(IS_ALIGNED(addr, KASAN_SHADOW_SCALE_SIZE)))
			return false;

		return memory_is_poisoned_1(addr + 15);
	}

	return false;
}

static __always_inline unsigned long bytes_is_zero(const u8 *start,
					size_t size)
{
	while (size) {
		if (unlikely(*start))
			return (unsigned long)start;
		start++;
		size--;
	}

	return 0;
}

static __always_inline unsigned long memory_is_zero(const void *start,
						const void *end)
{
	unsigned int words;
	unsigned long ret;
	unsigned int prefix = (unsigned long)start % 8;

	if (end - start <= 16)
		return bytes_is_zero(start, end - start);

	if (prefix) {
		prefix = 8 - prefix;
		ret = bytes_is_zero(start, prefix);
		if (unlikely(ret))
			return ret;
		start += prefix;
	}

	words = (end - start) / 8;
	while (words) {
		if (unlikely(*(u64 *)start))
			return bytes_is_zero(start, 8);
		start += 8;
		words--;
	}

	return bytes_is_zero(start, (end - start) % 8);
}

static __always_inline bool memory_is_poisoned_n(unsigned long addr,
						size_t size)
{
	unsigned long ret;

	ret = memory_is_zero(kasan_mem_to_shadow((void *)addr),
			kasan_mem_to_shadow((void *)addr + size - 1) + 1);

	if (unlikely(ret)) {
		unsigned long last_byte = addr + size - 1;
		s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);

		if (unlikely(ret != (unsigned long)last_shadow ||
			((long)(last_byte & KASAN_SHADOW_MASK) >= *last_shadow)))
			return true;
	}
	return false;
}

static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
{
	if (__builtin_constant_p(size)) {
		switch (size) {
		case 1:
			return memory_is_poisoned_1(addr);
		case 2:
			return memory_is_poisoned_2(addr);
		case 4:
			return memory_is_poisoned_4(addr);
		case 8:
			return memory_is_poisoned_8(addr);
		case 16:
			return memory_is_poisoned_16(addr);
		default:
			BUILD_BUG();
		}
	}

	return memory_is_poisoned_n(addr, size);
}


static __always_inline void check_memory_region(unsigned long addr,
						size_t size, bool write)
{
	if (unlikely(size == 0))
		return;

	if (unlikely((void *)addr <
		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
		kasan_report(addr, size, write, _RET_IP_);
		return;
	}

	if (likely(!memory_is_poisoned(addr, size)))
		return;

	kasan_report(addr, size, write, _RET_IP_);
}

void __asan_loadN(unsigned long addr, size_t size);
void __asan_storeN(unsigned long addr, size_t size);

#undef memset
void *memset(void *addr, int c, size_t len)
{
	__asan_storeN((unsigned long)addr, len);

	return __memset(addr, c, len);
}

#undef memmove
void *memmove(void *dest, const void *src, size_t len)
{
	__asan_loadN((unsigned long)src, len);
	__asan_storeN((unsigned long)dest, len);

	return __memmove(dest, src, len);
}

#undef memcpy
void *memcpy(void *dest, const void *src, size_t len)
{
	__asan_loadN((unsigned long)src, len);
	__asan_storeN((unsigned long)dest, len);

	return __memcpy(dest, src, len);
}

void kasan_alloc_pages(struct page *page, unsigned int order)
{
	if (likely(!PageHighMem(page)))
		kasan_unpoison_shadow(page_address(page), PAGE_SIZE << order);
}

void kasan_free_pages(struct page *page, unsigned int order)
{
	if (likely(!PageHighMem(page)))
		kasan_poison_shadow(page_address(page),
				PAGE_SIZE << order,
				KASAN_FREE_PAGE);
}

#ifdef CONFIG_SLAB
/*
 * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
 * For larger allocations larger redzones are used.
 */
static size_t optimal_redzone(size_t object_size)
{
	int rz =
		object_size <= 64        - 16   ? 16 :
		object_size <= 128       - 32   ? 32 :
		object_size <= 512       - 64   ? 64 :
		object_size <= 4096      - 128  ? 128 :
		object_size <= (1 << 14) - 256  ? 256 :
		object_size <= (1 << 15) - 512  ? 512 :
		object_size <= (1 << 16) - 1024 ? 1024 : 2048;
	return rz;
}

void kasan_cache_create(struct kmem_cache *cache, size_t *size,
			unsigned long *flags)
{
	int redzone_adjust;
	/* Make sure the adjusted size is still less than
	 * KMALLOC_MAX_CACHE_SIZE.
	 * TODO: this check is only useful for SLAB, but not SLUB. We'll need
	 * to skip it for SLUB when it starts using kasan_cache_create().
	 */
	if (*size > KMALLOC_MAX_CACHE_SIZE -
	    sizeof(struct kasan_alloc_meta) -
	    sizeof(struct kasan_free_meta))
		return;
	*flags |= SLAB_KASAN;
	/* Add alloc meta. */
	cache->kasan_info.alloc_meta_offset = *size;
	*size += sizeof(struct kasan_alloc_meta);

	/* Add free meta. */
	if (cache->flags & SLAB_DESTROY_BY_RCU || cache->ctor ||
	    cache->object_size < sizeof(struct kasan_free_meta)) {
		cache->kasan_info.free_meta_offset = *size;
		*size += sizeof(struct kasan_free_meta);
	}
	redzone_adjust = optimal_redzone(cache->object_size) -
		(*size - cache->object_size);
	if (redzone_adjust > 0)
		*size += redzone_adjust;
	*size = min(KMALLOC_MAX_CACHE_SIZE,
		    max(*size,
			cache->object_size +
			optimal_redzone(cache->object_size)));
}
#endif

void kasan_poison_slab(struct page *page)
{
	kasan_poison_shadow(page_address(page),
			PAGE_SIZE << compound_order(page),
			KASAN_KMALLOC_REDZONE);
}

void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
{
	kasan_unpoison_shadow(object, cache->object_size);
}

void kasan_poison_object_data(struct kmem_cache *cache, void *object)
{
	kasan_poison_shadow(object,
			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
			KASAN_KMALLOC_REDZONE);
#ifdef CONFIG_SLAB
	if (cache->flags & SLAB_KASAN) {
		struct kasan_alloc_meta *alloc_info =
			get_alloc_info(cache, object);
		alloc_info->state = KASAN_STATE_INIT;
	}
#endif
}

#ifdef CONFIG_SLAB
static inline int in_irqentry_text(unsigned long ptr)
{
	return (ptr >= (unsigned long)&__irqentry_text_start &&
		ptr < (unsigned long)&__irqentry_text_end) ||
		(ptr >= (unsigned long)&__softirqentry_text_start &&
		 ptr < (unsigned long)&__softirqentry_text_end);
}

static inline void filter_irq_stacks(struct stack_trace *trace)
{
	int i;

	if (!trace->nr_entries)
		return;
	for (i = 0; i < trace->nr_entries; i++)
		if (in_irqentry_text(trace->entries[i])) {
			/* Include the irqentry function into the stack. */
			trace->nr_entries = i + 1;
			break;
		}
}

static inline depot_stack_handle_t save_stack(gfp_t flags)
{
	unsigned long entries[KASAN_STACK_DEPTH];
	struct stack_trace trace = {
		.nr_entries = 0,
		.entries = entries,
		.max_entries = KASAN_STACK_DEPTH,
		.skip = 0
	};

	save_stack_trace(&trace);
	filter_irq_stacks(&trace);
	if (trace.nr_entries != 0 &&
	    trace.entries[trace.nr_entries-1] == ULONG_MAX)
		trace.nr_entries--;

	return depot_save_stack(&trace, flags);
}

static inline void set_track(struct kasan_track *track, gfp_t flags)
{
	track->pid = current->pid;
	track->stack = save_stack(flags);
}

struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
					const void *object)
{
	BUILD_BUG_ON(sizeof(struct kasan_alloc_meta) > 32);
	return (void *)object + cache->kasan_info.alloc_meta_offset;
}

struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
				      const void *object)
{
	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
	return (void *)object + cache->kasan_info.free_meta_offset;
}
#endif

void kasan_slab_alloc(struct kmem_cache *cache, void *object, gfp_t flags)
{
	kasan_kmalloc(cache, object, cache->object_size, flags);
}

void kasan_slab_free(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->object_size;
	unsigned long rounded_up_size = round_up(size, KASAN_SHADOW_SCALE_SIZE);

	/* RCU slabs could be legally used after free within the RCU period */
	if (unlikely(cache->flags & SLAB_DESTROY_BY_RCU))
		return;

#ifdef CONFIG_SLAB
	if (cache->flags & SLAB_KASAN) {
		struct kasan_free_meta *free_info =
			get_free_info(cache, object);
		struct kasan_alloc_meta *alloc_info =
			get_alloc_info(cache, object);
		alloc_info->state = KASAN_STATE_FREE;
		set_track(&free_info->track, GFP_NOWAIT);
	}
#endif

	kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
}

void kasan_kmalloc(struct kmem_cache *cache, const void *object, size_t size,
		   gfp_t flags)
{
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (unlikely(object == NULL))
		return;

	redzone_start = round_up((unsigned long)(object + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = round_up((unsigned long)object + cache->object_size,
				KASAN_SHADOW_SCALE_SIZE);

	kasan_unpoison_shadow(object, size);
	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
		KASAN_KMALLOC_REDZONE);
#ifdef CONFIG_SLAB
	if (cache->flags & SLAB_KASAN) {
		struct kasan_alloc_meta *alloc_info =
			get_alloc_info(cache, object);

		alloc_info->state = KASAN_STATE_ALLOC;
		alloc_info->alloc_size = size;
		set_track(&alloc_info->track, flags);
	}
#endif
}
EXPORT_SYMBOL(kasan_kmalloc);

void kasan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
{
	struct page *page;
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (unlikely(ptr == NULL))
		return;

	page = virt_to_page(ptr);
	redzone_start = round_up((unsigned long)(ptr + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (unsigned long)ptr + (PAGE_SIZE << compound_order(page));

	kasan_unpoison_shadow(ptr, size);
	kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_start,
		KASAN_PAGE_REDZONE);
}

void kasan_krealloc(const void *object, size_t size, gfp_t flags)
{
	struct page *page;

	if (unlikely(object == ZERO_SIZE_PTR))
		return;

	page = virt_to_head_page(object);

	if (unlikely(!PageSlab(page)))
		kasan_kmalloc_large(object, size, flags);
	else
		kasan_kmalloc(page->slab_cache, object, size, flags);
}

void kasan_kfree(void *ptr)
{
	struct page *page;

	page = virt_to_head_page(ptr);

	if (unlikely(!PageSlab(page)))
		kasan_poison_shadow(ptr, PAGE_SIZE << compound_order(page),
				KASAN_FREE_PAGE);
	else
		kasan_slab_free(page->slab_cache, ptr);
}

void kasan_kfree_large(const void *ptr)
{
	struct page *page = virt_to_page(ptr);

	kasan_poison_shadow(ptr, PAGE_SIZE << compound_order(page),
			KASAN_FREE_PAGE);
}

int kasan_module_alloc(void *addr, size_t size)
{
	void *ret;
	size_t shadow_size;
	unsigned long shadow_start;

	shadow_start = (unsigned long)kasan_mem_to_shadow(addr);
	shadow_size = round_up(size >> KASAN_SHADOW_SCALE_SHIFT,
			PAGE_SIZE);

	if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
		return -EINVAL;

	ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
			shadow_start + shadow_size,
			GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
			PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
			__builtin_return_address(0));

	if (ret) {
		find_vm_area(addr)->flags |= VM_KASAN;
		kmemleak_ignore(ret);
		return 0;
	}

	return -ENOMEM;
}

void kasan_free_shadow(const struct vm_struct *vm)
{
	if (vm->flags & VM_KASAN)
		vfree(kasan_mem_to_shadow(vm->addr));
}

static void register_global(struct kasan_global *global)
{
	size_t aligned_size = round_up(global->size, KASAN_SHADOW_SCALE_SIZE);

	kasan_unpoison_shadow(global->beg, global->size);

	kasan_poison_shadow(global->beg + aligned_size,
		global->size_with_redzone - aligned_size,
		KASAN_GLOBAL_REDZONE);
}

void __asan_register_globals(struct kasan_global *globals, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		register_global(&globals[i]);
}
EXPORT_SYMBOL(__asan_register_globals);

void __asan_unregister_globals(struct kasan_global *globals, size_t size)
{
}
EXPORT_SYMBOL(__asan_unregister_globals);

#define DEFINE_ASAN_LOAD_STORE(size)				\
	void __asan_load##size(unsigned long addr)		\
	{							\
		check_memory_region(addr, size, false);		\
	}							\
	EXPORT_SYMBOL(__asan_load##size);			\
	__alias(__asan_load##size)				\
	void __asan_load##size##_noabort(unsigned long);	\
	EXPORT_SYMBOL(__asan_load##size##_noabort);		\
	void __asan_store##size(unsigned long addr)		\
	{							\
		check_memory_region(addr, size, true);		\
	}							\
	EXPORT_SYMBOL(__asan_store##size);			\
	__alias(__asan_store##size)				\
	void __asan_store##size##_noabort(unsigned long);	\
	EXPORT_SYMBOL(__asan_store##size##_noabort)

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);
DEFINE_ASAN_LOAD_STORE(16);

void __asan_loadN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, false);
}
EXPORT_SYMBOL(__asan_loadN);

__alias(__asan_loadN)
void __asan_loadN_noabort(unsigned long, size_t);
EXPORT_SYMBOL(__asan_loadN_noabort);

void __asan_storeN(unsigned long addr, size_t size)
{
	check_memory_region(addr, size, true);
}
EXPORT_SYMBOL(__asan_storeN);

__alias(__asan_storeN)
void __asan_storeN_noabort(unsigned long, size_t);
EXPORT_SYMBOL(__asan_storeN_noabort);

/* to shut up compiler complaints */
void __asan_handle_no_return(void) {}
EXPORT_SYMBOL(__asan_handle_no_return);

#ifdef CONFIG_MEMORY_HOTPLUG
static int kasan_mem_notifier(struct notifier_block *nb,
			unsigned long action, void *data)
{
	return (action == MEM_GOING_ONLINE) ? NOTIFY_BAD : NOTIFY_OK;
}

static int __init kasan_memhotplug_init(void)
{
	pr_err("WARNING: KASAN doesn't support memory hot-add\n");
	pr_err("Memory hot-add will be disabled\n");

	hotplug_memory_notifier(kasan_mem_notifier, 0);

	return 0;
}

module_init(kasan_memhotplug_init);
#endif
