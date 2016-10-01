/*
 *  linux/arch/arm/mm/mmu.c
 *
 *  Copyright (C) 1995-2005 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/memblock.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/sizes.h>

#include <asm/cp15.h>
#include <asm/cputype.h>
#include <asm/sections.h>
#include <asm/cachetype.h>
#include <asm/fixmap.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/tlb.h>
#include <asm/highmem.h>
#include <asm/system_info.h>
#include <asm/traps.h>
#include <asm/procinfo.h>
#include <asm/memory.h>

#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/pci.h>
#include <asm/fixmap.h>

#include "fault.h"
#include "mm.h"
#include "tcm.h"

/*
 * empty_zero_page is a special page that is used for
 * zero-initialized data and COW.
 */
struct page *empty_zero_page;
EXPORT_SYMBOL(empty_zero_page);

/*
 * The pmd table for the upper-most set of pages.
 */
pmd_t *top_pmd;

pmdval_t user_pmd_table = _PAGE_USER_TABLE;

#define CPOLICY_UNCACHED	0
#define CPOLICY_BUFFERED	1
#define CPOLICY_WRITETHROUGH	2
#define CPOLICY_WRITEBACK	3
#define CPOLICY_WRITEALLOC	4

static unsigned int cachepolicy __initdata = CPOLICY_WRITEBACK;
static unsigned int ecc_mask __initdata = 0;
pgprot_t pgprot_user;
pgprot_t pgprot_kernel;
pgprot_t pgprot_hyp_device;
pgprot_t pgprot_s2;
pgprot_t pgprot_s2_device;

EXPORT_SYMBOL(pgprot_user);
EXPORT_SYMBOL(pgprot_kernel);

struct cachepolicy {
	const char	policy[16];
	unsigned int	cr_mask;
	pmdval_t	pmd;
	pteval_t	pte;
	pteval_t	pte_s2;
};

#ifdef CONFIG_ARM_LPAE
#define s2_policy(policy)	policy
#else
#define s2_policy(policy)	0
#endif

static struct cachepolicy cache_policies[] __initdata = {
	{
		.policy		= "uncached",
		.cr_mask	= CR_W|CR_C,
		.pmd		= PMD_SECT_UNCACHED,
		.pte		= L_PTE_MT_UNCACHED,
		.pte_s2		= s2_policy(L_PTE_S2_MT_UNCACHED),
	}, {
		.policy		= "buffered",
		.cr_mask	= CR_C,
		.pmd		= PMD_SECT_BUFFERED,
		.pte		= L_PTE_MT_BUFFERABLE,
		.pte_s2		= s2_policy(L_PTE_S2_MT_UNCACHED),
	}, {
		.policy		= "writethrough",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WT,
		.pte		= L_PTE_MT_WRITETHROUGH,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITETHROUGH),
	}, {
		.policy		= "writeback",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WB,
		.pte		= L_PTE_MT_WRITEBACK,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITEBACK),
	}, {
		.policy		= "writealloc",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WBWA,
		.pte		= L_PTE_MT_WRITEALLOC,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITEBACK),
	}
};

#ifdef CONFIG_CPU_CP15
static unsigned long initial_pmd_value __initdata = 0;

/*
 * Initialise the cache_policy variable with the initial state specified
 * via the "pmd" value.  This is used to ensure that on ARMv6 and later,
 * the C code sets the page tables up with the same policy as the head
 * assembly code, which avoids an illegal state where the TLBs can get
 * confused.  See comments in early_cachepolicy() for more information.
 */
void __init init_default_cache_policy(unsigned long pmd)
{
	//pmd : 실제로 32비트에서는 pmd에 대한 할당이 존재하지 않음.
	//32비트 arm에서는 실제로 pgd, pte만 존재.

	//cachepolicy 전역변수에 아키텍처가 지원하는 1차페이지테이블의 캐시정책 값을 대입
	int i;

	initial_pmd_value = pmd;//(arm 32비트에서는 1차 페이지 테이블이 pmd)

	pmd &= PMD_SECT_TEX(1) | PMD_SECT_BUFFERABLE | PMD_SECT_CACHEABLE;
	//page table 포맷에서 사용되는 TEX필드와 C(cacheable), B(bufferable)의 비트인코딩	 //비트인코딩을 함으로서 page shareable에 대한 여부, 메모리타입
	//캐시의 descriptor에 대한 정의를 수행.

	//통상적으로 L1은 inner, L2는 outer로 정의되지만 메모리타입과 descriptor의 정의에 따라 별도로 설정이 가능.
	//

	for (i = 0; i < ARRAY_SIZE(cache_policies); i++)
		if (cache_policies[i].pmd == pmd) {
			cachepolicy = i;
			break;
		}
	//설정되어 있는 모든 cache policy들찾아 일치하는 pmd를 갖는 policy를 가질 경우
	//i에 따라 인덱싱.
	if (i == ARRAY_SIZE(cache_policies))
		pr_err("ERROR: could not find cache policy\n");
}

/*
 * These are useful for identifying cache coherency problems by allowing
 * the cache or the cache and writebuffer to be turned off.  (Note: the
 * write buffer should not be on and the cache off).
 */
static int __init early_cachepolicy(char *p)
{
	int i, selected = -1;

	for (i = 0; i < ARRAY_SIZE(cache_policies); i++) {
		int len = strlen(cache_policies[i].policy);

		if (memcmp(p, cache_policies[i].policy, len) == 0) {
			selected = i;
			break;
		}
	}

	if (selected == -1)
		pr_err("ERROR: unknown or unsupported cache policy\n");

	/*
	 * This restriction is partly to do with the way we boot; it is
	 * unpredictable to have memory mapped using two different sets of
	 * memory attributes (shared, type, and cache attribs).  We can not
	 * change these attributes once the initial assembly has setup the
	 * page tables.
	 */
	if (cpu_architecture() >= CPU_ARCH_ARMv6 && selected != cachepolicy) {
		pr_warn("Only cachepolicy=%s supported on ARMv6 and later\n",
			cache_policies[cachepolicy].policy);
		return 0;
	}

	if (selected != cachepolicy) {
		unsigned long cr = __clear_cr(cache_policies[selected].cr_mask);
		cachepolicy = selected;
		flush_cache_all();
		set_cr(cr);
	}
	return 0;
}
early_param("cachepolicy", early_cachepolicy);

static int __init early_nocache(char *__unused)
{
	char *p = "buffered";
	pr_warn("nocache is deprecated; use cachepolicy=%s\n", p);
	early_cachepolicy(p);
	return 0;
}
early_param("nocache", early_nocache);

static int __init early_nowrite(char *__unused)
{
	char *p = "uncached";
	pr_warn("nowb is deprecated; use cachepolicy=%s\n", p);
	early_cachepolicy(p);
	return 0;
}
early_param("nowb", early_nowrite);

#ifndef CONFIG_ARM_LPAE
static int __init early_ecc(char *p)
{
	if (memcmp(p, "on", 2) == 0)
		ecc_mask = PMD_PROTECTION;
	else if (memcmp(p, "off", 3) == 0)
		ecc_mask = 0;
	return 0;
}
early_param("ecc", early_ecc);
#endif

#else /* ifdef CONFIG_CPU_CP15 */

static int __init early_cachepolicy(char *p)
{
	pr_warn("cachepolicy kernel parameter not supported without cp15\n");
}
early_param("cachepolicy", early_cachepolicy);

static int __init noalign_setup(char *__unused)
{
	pr_warn("noalign kernel parameter not supported without cp15\n");
}
__setup("noalign", noalign_setup);

#endif /* ifdef CONFIG_CPU_CP15 / else */

#define PROT_PTE_DEVICE		L_PTE_PRESENT|L_PTE_YOUNG|L_PTE_DIRTY|L_PTE_XN
#define PROT_PTE_S2_DEVICE	PROT_PTE_DEVICE
#define PROT_SECT_DEVICE	PMD_TYPE_SECT|PMD_SECT_AP_WRITE

static struct mem_type mem_types[] = {
	[MT_DEVICE] = {		  /* Strongly ordered / ARMv6 shared device */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED |
				  L_PTE_SHARED,//2차 변환 수행시 사용하는 2차페이지테이블의 descriptor 엔트리 속성.
		.prot_pte_s2	= s2_policy(PROT_PTE_S2_DEVICE) |
				  s2_policy(L_PTE_S2_MT_DEV_SHARED) |
				  L_PTE_SHARED,
		//하이퍼바이저에서 prot_pte대신 사용
		.prot_l1	= PMD_TYPE_TABLE,
		//2차 변환 수행시 사용하는 1차 페이지 테이블  descriptor 엔트리 속성
		.prot_sect	= PROT_SECT_DEVICE | PMD_SECT_S,
		//1차 변환 수행시 사용하는 섹션 페이지 descriptor 엔트리 속성.
		.domain		= DOMAIN_IO,
		//domain : 해당 페이지를 통제하는 주체.

		//shared : 여러 프로세서들 사이에서 공유되는 메모리들을 다룰수 있음.
	},
	[MT_DEVICE_NONSHARED] = { /* ARMv6 non-shared device */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_NONSHARED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE,
		.domain		= DOMAIN_IO,
		//Non-shared : 하나의 프로세서에 의해 사용되는 메모리를 다룰 수 있음.
	},
	[MT_DEVICE_CACHED] = {	  /* ioremap_cached */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_CACHED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE | PMD_SECT_WB,
		.domain		= DOMAIN_IO,
	},
	[MT_DEVICE_WC] = {	/* ioremap_wc */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_WC,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE,
		.domain		= DOMAIN_IO,
	},
	[MT_UNCACHED] = {
		.prot_pte	= PROT_PTE_DEVICE,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PMD_TYPE_SECT | PMD_SECT_XN,
		.domain		= DOMAIN_IO,
	},
	[MT_CACHECLEAN] = {
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
#ifndef CONFIG_ARM_LPAE
	[MT_MINICLEAN] = {
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN | PMD_SECT_MINICACHE,
		.domain    = DOMAIN_KERNEL,
	},
#endif
	[MT_LOW_VECTORS] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_RDONLY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_VECTORS,
	},
	[MT_HIGH_VECTORS] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_USER | L_PTE_RDONLY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_VECTORS,
	},
	[MT_MEMORY_RWX] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_RW] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
			     L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_ROM] = {
		.prot_sect = PMD_TYPE_SECT,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_RWX_NONCACHED] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_MT_BUFFERABLE,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_RW_DTCM] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_RWX_ITCM] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_RW_SO] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_MT_UNCACHED | L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_S |
				PMD_SECT_UNCACHED | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_DMA_READY] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_KERNEL,
	},
};

const struct mem_type *get_mem_type(unsigned int type)
{
	return type < ARRAY_SIZE(mem_types) ? &mem_types[type] : NULL;
}
EXPORT_SYMBOL(get_mem_type);

static pte_t *(*pte_offset_fixmap)(pmd_t *dir, unsigned long addr);

static pte_t bm_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
	__aligned(PTE_HWTABLE_OFF + PTE_HWTABLE_SIZE) __initdata;
// bm_pte : page table 

static pte_t * __init pte_offset_early_fixmap(pmd_t *dir, unsigned long addr)
{
	return &bm_pte[pte_index(addr)];
}

static pte_t *pte_offset_late_fixmap(pmd_t *dir, unsigned long addr)
{
	return pte_offset_kernel(dir, addr);
}

static inline pmd_t * __init fixmap_pmd(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);
	pud_t *pud = pud_offset(pgd, addr); //32비트이므로 바로 pmd를 리턴하는 함수.
	pmd_t *pmd = pmd_offset(pud, addr);

	return pmd;
}

void __init early_fixmap_init(void)
{
	pmd_t *pmd;

	/*
	 * The early fixmap range spans multiple pmds, for which
	 * we are not prepared:
	 */
	/*
	 * ZONE_HIGHMEM 은 vmap, kmap, fixmap 영역으로 구분된다.
	 */
	BUILD_BUG_ON((__fix_to_virt(__end_of_early_ioremap_region) >> PMD_SHIFT)
		     != FIXADDR_TOP >> PMD_SHIFT);

	pmd = fixmap_pmd(FIXADDR_TOP);
	pmd_populate_kernel(&init_mm, pmd, bm_pte);

	pte_offset_fixmap = pte_offset_early_fixmap;
	// 주어지는 addr 을 통해 pte table의 해당 pte 주소를 리턴 
}

/*
 * To avoid TLB flush broadcasts, this uses local_flush_tlb_kernel_range().
 * As a result, this can only be called with preemption disabled, as under
 * stop_machine().
 */
void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
	unsigned long vaddr = __fix_to_virt(idx);
	pte_t *pte = pte_offset_fixmap(pmd_off_k(vaddr), vaddr);

	/* Make sure fixmap region does not exceed available allocation. */
	BUILD_BUG_ON(FIXADDR_START + (__end_of_fixed_addresses * PAGE_SIZE) >
		     FIXADDR_END);
	BUG_ON(idx >= __end_of_fixed_addresses);

	if (pgprot_val(prot))
		set_pte_at(NULL, vaddr, pte,
			pfn_pte(phys >> PAGE_SHIFT, prot));
	else
		pte_clear(NULL, vaddr, pte);
	local_flush_tlb_kernel_range(vaddr, vaddr + PAGE_SIZE);
}

/*
 * Adjust the PMD section entries according to the CPU in use.
 */
static void __init build_mem_type_table(void)
{
	struct cachepolicy *cp; //각 아키텍처가 지원하는 캐시정책이 담긴다.
	unsigned int cr = get_cr();
	pteval_t user_pgprot, kern_pgprot, vecs_pgprot;
	pteval_t hyp_device_pgprot, s2_pgprot, s2_device_pgprot;
	// prot : ?
	int cpu_arch = cpu_architecture();//현재 머신의 아키텍처를 알아내는 함수
	int i;
	/*
0 0 : noncached nonbuffered
	DCache disabled. Read from external memory. Write as a nonbuffered store(s) to external memory. DCache is updated.

0 1 : noncached buffered
	DCache disabled. Read from external memory. Write as a buffered store(s) to external memory. DCache is not updated.
	*/
	if (cpu_arch < CPU_ARCH_ARMv6) {
#if defined(CONFIG_CPU_DCACHE_DISABLE) // DCACHE에 대한 write를 안하고 버퍼에다가 하겠다.?
		//cpu <-> dcache(이건 off) <-> (buffer(mem chip에 포함) <-> memory) 
		if (cachepolicy > CPOLICY_BUFFERED)
			cachepolicy = CPOLICY_BUFFERED;
#elif defined(CONFIG_CPU_DCACHE_WRITETHROUGH)
		if (cachepolicy > CPOLICY_WRITETHROUGH)
			cachepolicy = CPOLICY_WRITETHROUGH;
#endif
	}
	if (cpu_arch < CPU_ARCH_ARMv5) {
		if (cachepolicy >= CPOLICY_WRITEALLOC)
			cachepolicy = CPOLICY_WRITEBACK;
		ecc_mask = 0;
	}
	/*
	 * write allocate : write 할 때, miss 나면 캐시 라인 할당
	 * no-write allocate(read allocate) : write 할 때, 캐시 안쓰고 바로 메모리로 쏘겠다.
	 * smp면 write allocate 랑 page table 공유 하겠다.
	 */
	if (is_smp()) {
		if (cachepolicy != CPOLICY_WRITEALLOC) {
			pr_warn("Forcing write-allocate cache policy for SMP\n");
			cachepolicy = CPOLICY_WRITEALLOC;
		}
		if (!(initial_pmd_value & PMD_SECT_S)) {
			pr_warn("Forcing shared mappings for SMP\n");
			initial_pmd_value |= PMD_SECT_S;
		}
	}
	// cachepolicy는 이 아키텍처에서 사용 가능한 정책들이고
	// 만약에 cachepolicy가 CPOLICY_WRITEALLOC 이면 그 이하의 정책들도 사용가능
	// 아래는 이제 메모리를 메모리 타입별로 구분하고 그 타입별로
	// 각각에 맞는 정책을 설정
	//////////////////////////////////////////////////// 	
	/*
	 * Strip out features not present on earlier architectures.
	 * Pre-ARMv5 CPUs don't have TEX bits.  Pre-ARMv6 CPUs or those
	 * without extended page tables don't have the 'Shared' bit.
	 */
	if (cpu_arch < CPU_ARCH_ARMv5)
		for (i = 0; i < ARRAY_SIZE(mem_types); i++)
			mem_types[i].prot_sect &= ~PMD_SECT_TEX(7); //TEX : Type EXtension
	if ((cpu_arch < CPU_ARCH_ARMv6 || !(cr & CR_XP)) && !cpu_is_xsc3())
		for (i = 0; i < ARRAY_SIZE(mem_types); i++)
			mem_types[i].prot_sect &= ~PMD_SECT_S;

	/*
	 * ARMv5 and lower, bit 4 must be set for page tables (was: cache
	 * "update-able on write" bit on ARM610).  However, Xscale and
	 * Xscale3 require this bit to be cleared.
	 */
	if (cpu_is_xscale_family()) {
		for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
			mem_types[i].prot_sect &= ~PMD_BIT4;
			mem_types[i].prot_l1 &= ~PMD_BIT4;
		}
	} else if (cpu_arch < CPU_ARCH_ARMv6) {
		for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
			if (mem_types[i].prot_l1)
				mem_types[i].prot_l1 |= PMD_BIT4;
			if (mem_types[i].prot_sect)
				mem_types[i].prot_sect |= PMD_BIT4;
		}
	}

	/*
	 * Mark the device areas according to the CPU/architecture.
	 */
	if (cpu_is_xsc3() || (cpu_arch >= CPU_ARCH_ARMv6 && (cr & CR_XP))) {
		if (!cpu_is_xsc3()) {
			/*
			 * Mark device regions on ARMv6+ as execute-never
			 * to prevent speculative instruction fetches.
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_CACHED].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_XN;

			/* Also setup NX memory mapping */
			mem_types[MT_MEMORY_RW].prot_sect |= PMD_SECT_XN;
		}
		if (cpu_arch >= CPU_ARCH_ARMv7 && (cr & CR_TRE)) {
			/*
			 * For ARMv7 with TEX remapping,
			 * - shared device is SXCB=1100
			 * - nonshared device is SXCB=0100
			 * - write combine device mem is SXCB=0001
			 * (Uncached Normal memory)
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_TEX(1);
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(1);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_BUFFERABLE;
		} else if (cpu_is_xsc3()) {
			/*
			 * For Xscale3,
			 * - shared device is TEXCB=00101
			 * - nonshared device is TEXCB=01000
			 * - write combine device mem is TEXCB=00100
			 * (Inner/Outer Uncacheable in xsc3 parlance)
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_TEX(1) | PMD_SECT_BUFFERED;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(2);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_TEX(1);
		} else {
			/*
			 * For ARMv6 and ARMv7 without TEX remapping,
			 * - shared device is TEXCB=00001
			 * - nonshared device is TEXCB=01000
			 * - write combine device mem is TEXCB=00100
			 * (Uncached Normal in ARMv6 parlance).
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_BUFFERED;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(2);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_TEX(1);
		}
	} else {
		/*
		 * On others, write combining is "Uncached/Buffered"
		 */
		mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_BUFFERABLE;
	}

	/*
	 * Now deal with the memory-type mappings
	 */
	cp = &cache_policies[cachepolicy];
	vecs_pgprot = kern_pgprot = user_pgprot = cp->pte;
	//vecs_pgprot : interrupt_vector에 해당하는 페이지 속성
	s2_pgprot = cp->pte_s2;
	hyp_device_pgprot = mem_types[MT_DEVICE].prot_pte;
	s2_device_pgprot = mem_types[MT_DEVICE].prot_pte_s2;

#ifndef CONFIG_ARM_LPAE
	/*
	 * We don't use domains on ARMv6 (since this causes problems with
	 * v6/v7 kernels), so we must use a separate memory type for user
	 * r/o, kernel r/w to map the vectors page.
	 */
	if (cpu_arch == CPU_ARCH_ARMv6)
		vecs_pgprot |= L_PTE_MT_VECTORS;

	/*
	 * Check is it with support for the PXN bit
	 * in the Short-descriptor translation table format descriptors.
	 */
	if (cpu_arch == CPU_ARCH_ARMv7 &&
		(read_cpuid_ext(CPUID_EXT_MMFR0) & 0xF) >= 4) {
		user_pmd_table |= PMD_PXNTABLE;
	}
#endif

	/*
	 * ARMv6 and above have extended page tables.
	 */
	if (cpu_arch >= CPU_ARCH_ARMv6 && (cr & CR_XP)) { // ARMv6 이상이고 smp 면 SHARE 하겠다. 
#ifndef CONFIG_ARM_LPAE
		/*
		 * Mark cache clean areas and XIP ROM read only
		 * from SVC mode and no access from userspace.
		 */
		mem_types[MT_ROM].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
		mem_types[MT_MINICLEAN].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
#endif

		/*
		 * If the initial page tables were created with the S bit
		 * set, then we need to do the same here for the same
		 * reasons given in early_cachepolicy().
		 */
		if (initial_pmd_value & PMD_SECT_S) { // initial_pmd_value 위에서 설정했음
			user_pgprot |= L_PTE_SHARED;
			kern_pgprot |= L_PTE_SHARED;
			vecs_pgprot |= L_PTE_SHARED;
			s2_pgprot |= L_PTE_SHARED;
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_S;
			mem_types[MT_DEVICE_WC].prot_pte |= L_PTE_SHARED;
			mem_types[MT_DEVICE_CACHED].prot_sect |= PMD_SECT_S;
			mem_types[MT_DEVICE_CACHED].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_RWX].prot_sect |= PMD_SECT_S;
			mem_types[MT_MEMORY_RWX].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_RW].prot_sect |= PMD_SECT_S;
			mem_types[MT_MEMORY_RW].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_DMA_READY].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_RWX_NONCACHED].prot_sect |= PMD_SECT_S;
			mem_types[MT_MEMORY_RWX_NONCACHED].prot_pte |= L_PTE_SHARED;
		}
	}

	/*
	 * Non-cacheable Normal - intended for memory areas that must
	 * not cause dirty cache line writebacks when used
	 */
	if (cpu_arch >= CPU_ARCH_ARMv6) {
		if (cpu_arch >= CPU_ARCH_ARMv7 && (cr & CR_TRE)) {
			/* Non-cacheable Normal is XCB = 001 */
			mem_types[MT_MEMORY_RWX_NONCACHED].prot_sect |=
				PMD_SECT_BUFFERED;
		} else {
			/* For both ARMv6 and non-TEX-remapping ARMv7 */
			mem_types[MT_MEMORY_RWX_NONCACHED].prot_sect |=
				PMD_SECT_TEX(1);
		}
	} else {
		mem_types[MT_MEMORY_RWX_NONCACHED].prot_sect |= PMD_SECT_BUFFERABLE;
	}

#ifdef CONFIG_ARM_LPAE
	/*
	 * Do not generate access flag faults for the kernel mappings.
	 */
	for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
		mem_types[i].prot_pte |= PTE_EXT_AF;
		if (mem_types[i].prot_sect)
			mem_types[i].prot_sect |= PMD_SECT_AF;
	}
	kern_pgprot |= PTE_EXT_AF;
	vecs_pgprot |= PTE_EXT_AF;

	/*
	 * Set PXN for user mappings
	 */
	user_pgprot |= PTE_EXT_PXN;
#endif

	for (i = 0; i < 16; i++) {
		pteval_t v = pgprot_val(protection_map[i]);
		protection_map[i] = __pgprot(v | user_pgprot);
	}

	mem_types[MT_LOW_VECTORS].prot_pte |= vecs_pgprot;
	mem_types[MT_HIGH_VECTORS].prot_pte |= vecs_pgprot;

	pgprot_user   = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG | user_pgprot);
	pgprot_kernel = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG |
				 L_PTE_DIRTY | kern_pgprot);
	pgprot_s2  = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG | s2_pgprot);
	pgprot_s2_device  = __pgprot(s2_device_pgprot);
	pgprot_hyp_device  = __pgprot(hyp_device_pgprot);

	mem_types[MT_LOW_VECTORS].prot_l1 |= ecc_mask;
	mem_types[MT_HIGH_VECTORS].prot_l1 |= ecc_mask;
	mem_types[MT_MEMORY_RWX].prot_sect |= ecc_mask | cp->pmd;
	mem_types[MT_MEMORY_RWX].prot_pte |= kern_pgprot;
	mem_types[MT_MEMORY_RW].prot_sect |= ecc_mask | cp->pmd;
	mem_types[MT_MEMORY_RW].prot_pte |= kern_pgprot;
	mem_types[MT_MEMORY_DMA_READY].prot_pte |= kern_pgprot;
	mem_types[MT_MEMORY_RWX_NONCACHED].prot_sect |= ecc_mask;
	mem_types[MT_ROM].prot_sect |= cp->pmd;

	switch (cp->pmd) {
	case PMD_SECT_WT:
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_WT;
		break;
	case PMD_SECT_WB:
	case PMD_SECT_WBWA:
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_WB;
		break;
	}
	pr_info("Memory policy: %sData cache %s\n",
		ecc_mask ? "ECC enabled, " : "", cp->policy);

	for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
		struct mem_type *t = &mem_types[i];
		if (t->prot_l1)
			t->prot_l1 |= PMD_DOMAIN(t->domain);
		if (t->prot_sect)
			t->prot_sect |= PMD_DOMAIN(t->domain);
	}
}

#ifdef CONFIG_ARM_DMA_MEM_BUFFERABLE
pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
			      unsigned long size, pgprot_t vma_prot)
{
	if (!pfn_valid(pfn))
		return pgprot_noncached(vma_prot);
	else if (file->f_flags & O_SYNC)
		return pgprot_writecombine(vma_prot);
	return vma_prot;
}
EXPORT_SYMBOL(phys_mem_access_prot);
#endif

#define vectors_base()	(vectors_high() ? 0xffff0000 : 0)

static void __init *early_alloc_aligned(unsigned long sz, unsigned long align)
{
	void *ptr = __va(memblock_alloc(sz, align));
	//할당받은 memblock의 가상주소를 이용.
	memset(ptr, 0, sz);
	return ptr;
}

static void __init *early_alloc(unsigned long sz)
{
	return early_alloc_aligned(sz, sz);
}

static void *__init late_alloc(unsigned long sz)
{
	void *ptr = (void *)__get_free_pages(PGALLOC_GFP, get_order(sz));

	BUG_ON(!ptr);
	return ptr;
}

static pte_t * __init arm_pte_alloc(pmd_t *pmd, unsigned long addr,
				unsigned long prot,
				void *(*alloc)(unsigned long sz))
{
	if (pmd_none(*pmd)) {
		pte_t *pte = alloc(PTE_HWTABLE_OFF + PTE_HWTABLE_SIZE);
		//pte 할당. 각 아키텍처마다 정의 되어있는 alloc 콜백 함수로 할당.
		__pmd_populate(pmd, __pa(pte), prot);
		//할당된 pte로 pmd를 정의.
	}
	BUG_ON(pmd_bad(*pmd));
	return pte_offset_kernel(pmd, addr);
	//할당한 pte의 오프셋 리턴.
}

static pte_t * __init early_pte_alloc(pmd_t *pmd, unsigned long addr,
				      unsigned long prot)
		//
{
	return arm_pte_alloc(pmd, addr, prot, early_alloc);
}

static void __init alloc_init_pte(pmd_t *pmd, unsigned long addr,
				  unsigned long end, unsigned long pfn,
				  const struct mem_type *type,
				  void *(*alloc)(unsigned long sz),
				  bool ng)
{
	pte_t *pte = arm_pte_alloc(pmd, addr, type->prot_l1, alloc);
	do {
		set_pte_ext(pte, pfn_pte(pfn, __pgprot(type->prot_pte)),
			    ng ? PTE_EXT_NG : 0);
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

static void __init __map_init_section(pmd_t *pmd, unsigned long addr,
			unsigned long end, phys_addr_t phys,
			const struct mem_type *type, bool ng)
{
	pmd_t *p = pmd;

#ifndef CONFIG_ARM_LPAE
	/*
	 * In classic MMU format, puds and pmds are folded in to
	 * the pgds. pmd_offset gives the PGD entry. PGDs refer to a
	 * group of L1 entries making up one logical pointer to
	 * an L2 table (2MB), where as PMDs refer to the individual
	 * L1 entries (1MB). Hence increment to get the correct
	 * offset for odd 1MB sections.
	 * (See arch/arm/include/asm/pgtable-2level.h)
	 */
	if (addr & SECTION_SIZE)
		pmd++;
#endif
	do {
		*pmd = __pmd(phys | type->prot_sect | (ng ? PMD_SECT_nG : 0));
		phys += SECTION_SIZE;
	} while (pmd++, addr += SECTION_SIZE, addr != end);

	flush_pmd_entry(p);
}

static void __init alloc_init_pmd(pud_t *pud, unsigned long addr,
				      unsigned long end, phys_addr_t phys,
				      const struct mem_type *type,
				      void *(*alloc)(unsigned long sz), bool ng)
{
	pmd_t *pmd = pmd_offset(pud, addr);
	unsigned long next;

	do {
		/*
		 * With LPAE, we must loop over to map
		 * all the pmds for the given range.
		 */
		next = pmd_addr_end(addr, end);

		/*
		 * Try a section mapping - addr, next and phys must all be
		 * aligned to a section boundary.
		 */
		if (type->prot_sect &&
				((addr | next | phys) & ~SECTION_MASK) == 0) {
			__map_init_section(pmd, addr, next, phys, type, ng);
		} else {
			alloc_init_pte(pmd, addr, next,
				       __phys_to_pfn(phys), type, alloc, ng);
		}

		phys += next - addr;

	} while (pmd++, addr = next, addr != end);
}

static void __init alloc_init_pud(pgd_t *pgd, unsigned long addr,
				  unsigned long end, phys_addr_t phys,
				  const struct mem_type *type,
				  void *(*alloc)(unsigned long sz), bool ng)
{
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		alloc_init_pmd(pud, addr, next, phys, type, alloc, ng);
		phys += next - addr;
	} while (pud++, addr = next, addr != end);
}

#ifndef CONFIG_ARM_LPAE
static void __init create_36bit_mapping(struct mm_struct *mm,
					struct map_desc *md,
					const struct mem_type *type,
					bool ng)
{
	unsigned long addr, length, end;
	phys_addr_t phys;
	pgd_t *pgd;

	addr = md->virtual;
	phys = __pfn_to_phys(md->pfn);
	length = PAGE_ALIGN(md->length);

	if (!(cpu_architecture() >= CPU_ARCH_ARMv6 || cpu_is_xsc3())) {
		pr_err("MM: CPU does not support supersection mapping for 0x%08llx at 0x%08lx\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	/* N.B.	ARMv6 supersections are only defined to work with domain 0.
	 *	Since domain assignments can in fact be arbitrary, the
	 *	'domain == 0' check below is required to insure that ARMv6
	 *	supersections are only allocated for domain 0 regardless
	 *	of the actual domain assignments in use.
	 */
	if (type->domain) {
		pr_err("MM: invalid domain in supersection mapping for 0x%08llx at 0x%08lx\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	if ((addr | length | __pfn_to_phys(md->pfn)) & ~SUPERSECTION_MASK) {
		pr_err("MM: cannot create mapping for 0x%08llx at 0x%08lx invalid alignment\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	/*
	 * Shift bits [35:32] of address into bits [23:20] of PMD
	 * (See ARMv6 spec).
	 */
	phys |= (((md->pfn >> (32 - PAGE_SHIFT)) & 0xF) << 20);

	pgd = pgd_offset(mm, addr);
	end = addr + length;
	do {
		pud_t *pud = pud_offset(pgd, addr);
		pmd_t *pmd = pmd_offset(pud, addr);
		int i;

		for (i = 0; i < 16; i++)
			*pmd++ = __pmd(phys | type->prot_sect | PMD_SECT_SUPER |
				       (ng ? PMD_SECT_nG : 0));

		addr += SUPERSECTION_SIZE;
		phys += SUPERSECTION_SIZE;
		pgd += SUPERSECTION_SIZE >> PGDIR_SHIFT;
	} while (addr != end);
}
#endif	/* !CONFIG_ARM_LPAE */

static void __init __create_mapping(struct mm_struct *mm, struct map_desc *md,
				    void *(*alloc)(unsigned long sz),
				    bool ng)
{
		
	unsigned long addr, length, end;
	phys_addr_t phys;
	const struct mem_type *type;
	pgd_t *pgd;//초기화 되어 있는 pgd

	type = &mem_types[md->type];

#ifndef CONFIG_ARM_LPAE
	/*
	 * Catch 36-bit addresses
	 */
	if (md->pfn >= 0x100000) {
		create_36bit_mapping(mm, md, type, ng);
		return;
	}
#endif

	addr = md->virtual & PAGE_MASK; // pgd 찾을 거니까 뒤쪽 비트 주소 필요없음
	/*
	 * #define PAGE_MASK       (~((1 << PAGE_SHIFT) - 1))
	 *
	 * 00000000 00000000 00001000 00000000  (1 << 12)
	 * 00000000 00000000 00000111 11111111  (-1)
	 * 11111111 11111111 11111000 00000000  (~)
	 */
	phys = __pfn_to_phys(md->pfn);
	length = PAGE_ALIGN(md->length + (md->virtual & ~PAGE_MASK));

	if (type->prot_l1 == 0 && ((addr | phys | length) & ~SECTION_MASK)) {
		pr_warn("BUG: map for 0x%08llx at 0x%08lx can not be mapped using pages, ignoring.\n",
			(long long)__pfn_to_phys(md->pfn), addr);
		return;
	}

	pgd = pgd_offset(mm, addr);//pgd의 기본주소 할당.
	end = addr + length;
	do {
		unsigned long next = pgd_addr_end(addr, end);

		alloc_init_pud(pgd, addr, next, phys, type, alloc, ng);

		phys += next - addr;
		addr = next;
	} while (pgd++, addr != end);
	//기본주소를 pgd에 할당후, memblock의 end까지 반복함 - 매핑의 과정

}

/*
 * Create the page directory entries and any necessary
 * page tables for the mapping specified by `md'.  We
 * are able to cope here with varying sizes and address
 * offsets, and we take full advantage of sections and
 * supersections.
 */
static void __init create_mapping(struct map_desc *md)
{
	if (md->virtual != vectors_base() && md->virtual < TASK_SIZE) {
		pr_warn("BUG: not creating mapping for 0x%08llx at 0x%08lx in user region\n",
			(long long)__pfn_to_phys((u64)md->pfn), md->virtual);
		return;
	}

	if ((md->type == MT_DEVICE || md->type == MT_ROM) &&
	    md->virtual >= PAGE_OFFSET && md->virtual < FIXADDR_START &&
	    (md->virtual < VMALLOC_START || md->virtual >= VMALLOC_END)) {
		pr_warn("BUG: mapping for 0x%08llx at 0x%08lx out of vmalloc space\n",
			(long long)__pfn_to_phys((u64)md->pfn), md->virtual);
	}

	__create_mapping(&init_mm, md, early_alloc, false);
}

void __init create_mapping_late(struct mm_struct *mm, struct map_desc *md,
				bool ng)
{
#ifdef CONFIG_ARM_LPAE
	pud_t *pud = pud_alloc(mm, pgd_offset(mm, md->virtual), md->virtual);
	if (WARN_ON(!pud))
		return;
	pmd_alloc(mm, pud, 0);
#endif
	__create_mapping(mm, md, late_alloc, ng);
}

/*
 * Create the architecture specific mappings
 */
void __init iotable_init(struct map_desc *io_desc, int nr)
{
	struct map_desc *md;
	struct vm_struct *vm;
	struct static_vm *svm;

	if (!nr)
		return;

	svm = early_alloc_aligned(sizeof(*svm) * nr, __alignof__(*svm));
	// nr 개 만큼 svm 할당
	// svm 안에 vm 하나 인듯	
	// svm 은 svm 들끼리 연결된 list를 구성
	// vm 은 vm 들끼리 연결된 list를 구성
	
	for (md = io_desc; nr; md++, nr--) {
		create_mapping(md);

		vm = &svm->vm;
		vm->addr = (void *)(md->virtual & PAGE_MASK);
		vm->size = PAGE_ALIGN(md->length + (md->virtual & ~PAGE_MASK));
		vm->phys_addr = __pfn_to_phys(md->pfn);
		vm->flags = VM_IOREMAP | VM_ARM_STATIC_MAPPING;
		vm->flags |= VM_ARM_MTYPE(md->type);
		vm->caller = iotable_init;
		add_static_vm_early(svm++); // svm list에 만든 svm을 넣음
	}
}

void __init vm_reserve_area_early(unsigned long addr, unsigned long size,
				  void *caller)
{
	struct vm_struct *vm;
	struct static_vm *svm;

	svm = early_alloc_aligned(sizeof(*svm), __alignof__(*svm));

	vm = &svm->vm;
	vm->addr = (void *)addr;
	vm->size = size;
	vm->flags = VM_IOREMAP | VM_ARM_EMPTY_MAPPING;
	vm->caller = caller;
	add_static_vm_early(svm);
}

#ifndef CONFIG_ARM_LPAE

/*
 * The Linux PMD is made of two consecutive section entries covering 2MB
 * (see definition in include/asm/pgtable-2level.h).  However a call to
 * create_mapping() may optimize static mappings by using individual
 * 1MB section mappings.  This leaves the actual PMD potentially half
 * initialized if the top or bottom section entry isn't used, leaving it
 * open to problems if a subsequent ioremap() or vmalloc() tries to use
 * the virtual space left free by that unused section entry.
 *
 * Let's avoid the issue by inserting dummy vm entries covering the unused
 * PMD halves once the static mappings are in place.
 */

static void __init pmd_empty_section_gap(unsigned long addr)
{
	vm_reserve_area_early(addr, SECTION_SIZE, pmd_empty_section_gap);
}

static void __init fill_pmd_gaps(void)
{
	struct static_vm *svm;
	struct vm_struct *vm;
	unsigned long addr, next = 0;
	pmd_t *pmd;

	list_for_each_entry(svm, &static_vmlist, list) {
		vm = &svm->vm;
		addr = (unsigned long)vm->addr;
		if (addr < next)
			continue;

		/*
		 * Check if this vm starts on an odd section boundary.
		 * If so and the first section entry for this PMD is free
		 * then we block the corresponding virtual address.
		 */
		if ((addr & ~PMD_MASK) == SECTION_SIZE) {
			pmd = pmd_off_k(addr);
			if (pmd_none(*pmd))
				pmd_empty_section_gap(addr & PMD_MASK);
		}

		/*
		 * Then check if this vm ends on an odd section boundary.
		 * If so and the second section entry for this PMD is empty
		 * then we block the corresponding virtual address.
		 */
		addr += vm->size;
		if ((addr & ~PMD_MASK) == SECTION_SIZE) {
			pmd = pmd_off_k(addr) + 1;
			if (pmd_none(*pmd))
				pmd_empty_section_gap(addr);
		}

		/* no need to look at any vm entry until we hit the next PMD */
		next = (addr + PMD_SIZE - 1) & PMD_MASK;
	}
}

#else
#define fill_pmd_gaps() do { } while (0)
#endif

#if defined(CONFIG_PCI) && !defined(CONFIG_NEED_MACH_IO_H)
static void __init pci_reserve_io(void)
{
	struct static_vm *svm;

	svm = find_static_vm_vaddr((void *)PCI_IO_VIRT_BASE);
	if (svm)
		return;

	vm_reserve_area_early(PCI_IO_VIRT_BASE, SZ_2M, pci_reserve_io);
}
#else
#define pci_reserve_io() do { } while (0)
#endif

#ifdef CONFIG_DEBUG_LL
void __init debug_ll_io_init(void)
{
	struct map_desc map;

	debug_ll_addr(&map.pfn, &map.virtual);
	if (!map.pfn || !map.virtual)
		return;
	map.pfn = __phys_to_pfn(map.pfn);
	map.virtual &= PAGE_MASK;
	map.length = PAGE_SIZE;
	map.type = MT_DEVICE;
	iotable_init(&map, 1);
}
#endif

static void * __initdata vmalloc_min =
	(void *)(VMALLOC_END - (240 << 20) - VMALLOC_OFFSET);

/*
 * vmalloc=size forces the vmalloc area to be exactly 'size'
 * bytes. This can be used to increase (or decrease) the vmalloc
 * area - the default is 240m.
 */
static int __init early_vmalloc(char *arg)
{
	unsigned long vmalloc_reserve = memparse(arg, NULL);

	if (vmalloc_reserve < SZ_16M) {
		vmalloc_reserve = SZ_16M;
		pr_warn("vmalloc area too small, limiting to %luMB\n",
			vmalloc_reserve >> 20);
	}

	if (vmalloc_reserve > VMALLOC_END - (PAGE_OFFSET + SZ_32M)) {
		vmalloc_reserve = VMALLOC_END - (PAGE_OFFSET + SZ_32M);
		pr_warn("vmalloc area is too big, limiting to %luMB\n",
			vmalloc_reserve >> 20);
	}

	vmalloc_min = (void *)(VMALLOC_END - vmalloc_reserve);
	return 0;
}
early_param("vmalloc", early_vmalloc);

phys_addr_t arm_lowmem_limit __initdata = 0;

void __init sanity_check_meminfo(void)
		/*1, lowmem 영역만 사용해야 하는 case에 대해 memblock 영역 삭제
		  2. arm_lowmem_limit 및 highmemory 설정.
		  3. memblock.current_limit 설정*/

		//memory memblock에 대해 미리 사전체크, early memory allocator로 동작할수있도록 함.
		//memblock : 기본적인 메모리관리자, buddy와 slab과 같은 memory allocator로 전환하기 전 부트 타임에만 동작.
{
	phys_addr_t memblock_limit = 0;
	int highmem = 0;
	phys_addr_t vmalloc_limit = __pa(vmalloc_min - 1) + 1;
	//vmalloc의 물리주소가 할당된다.
	struct memblock_region *reg;
	bool should_use_highmem = false;

	for_each_memblock(memory, reg) { //등록된 memblock은 커널 설정 초기에 2M 단위를 메모리르 할당받아 사용.
		phys_addr_t block_start = reg->base;
		phys_addr_t block_end = reg->base + reg->size;
		phys_addr_t size_limit = reg->size;
		//memblock의 크기 설정...(2MB?)

		if (reg->base >= vmalloc_limit)
		//영역의 시작무리주소가 vmalloc_init 초과시 highmem영역이라 판단.
			highmem = 1;
		else
			size_limit = vmalloc_limit - reg->base;


		if (!IS_ENABLED(CONFIG_HIGHMEM) || cache_is_vipt_aliasing()) {
		//highmeme 설정이 안되잇거나 d-cache가 vipt aliasing을 사용하는 경우.
			if (highmem) {//highmem 영역을 사용하는 블록 삭제.
				pr_notice("Ignoring RAM at %pa-%pa (!CONFIG_HIGHMEM)\n",
					  &block_start, &block_end);
				memblock_remove(reg->base, reg->size);
				should_use_highmem = true;
				continue;
			}

			if (reg->size > size_limit) {
				phys_addr_t overlap_size = reg->size - size_limit;

				pr_notice("Truncating RAM at %pa-%pa to -%pa",
					  &block_start, &block_end, &vmalloc_limit);
				memblock_remove(vmalloc_limit, overlap_size);
				block_end = vmalloc_limit;
				should_use_highmem = true;
			}
		}

		if (!highmem) {//highmem이 없으므로 그에 따른 limit 설정을 다시 하는 부분.
			if (block_end > arm_lowmem_limit) {
				if (reg->size > size_limit)
					arm_lowmem_limit = vmalloc_limit;
				else
					arm_lowmem_limit = block_end;
			}

			/*
			 * Find the first non-pmd-aligned page, and point
			 * memblock_limit at it. This relies on rounding the
			 * limit down to be pmd-aligned, which happens at the
			 * end of this function.
			 *
			 * With this algorithm, the start or end of almost any
			 * bank can be non-pmd-aligned. The only exception is
			 * that the start of the bank 0 must be section-
			 * aligned, since otherwise memory would need to be
			 * allocated when mapping the start of bank 0, which
			 * occurs before any free memory is mapped.
			 */
			if (!memblock_limit) {
				if (!IS_ALIGNED(block_start, PMD_SIZE))
					memblock_limit = block_start;
				else if (!IS_ALIGNED(block_end, PMD_SIZE))
					memblock_limit = arm_lowmem_limit;
			}

		}
	}

	if (should_use_highmem)
		pr_notice("Consider using a HIGHMEM enabled kernel.\n");

	high_memory = __va(arm_lowmem_limit - 1) + 1;

	/*
	 * Round the memblock limit down to a pmd size.  This
	 * helps to ensure that we will allocate memory from the
	 * last full pmd, which should be mapped.
	 */
	if (memblock_limit)//memblock은 설정 초기에 2MB단위로 할당 받으므로 align되지 않은 메모리가 배열에 등록되어 있다면 align된 영역까지만 사용, 나머지는 memblock_limit을 설정.
		memblock_limit = round_down(memblock_limit, PMD_SIZE);
	if (!memblock_limit)
		memblock_limit = arm_lowmem_limit;

	memblock_set_current_limit(memblock_limit);
	//전 과정을 거친 limit을 current limit으로 설정
}

static inline void prepare_page_table(void)
{
	//커널 이미지 아래쪽에 해당하는 페이지 디레토리의 각 엔트리에 대해 pmd 섹션을 0으로 클리어
	//커널 공간에 해당하는 페이지 디렉토리의 각 엔트리에 대해서 pmd 섹션을 0으로 클리어.
	/*
	1.0x0 ~ 모듈영역 전까지
	2.모듈영역 ~ PAGE_OFFSET 영역(커널이미지의 가상주소)
	3.lowmem 남은 공간 부터 VMALLOC_START 영역전
	->각 영역들을 1차 페이지 테이블에서 초기화
	   */
	unsigned long addr;
	phys_addr_t end;

	/*
	 * Clear out all the mappings below the kernel image.
	 */
	for (addr = 0; addr < MODULES_VADDR; addr += PMD_SIZE)//2mb 단위의 엔트리
		pmd_clear(pmd_off_k(addr));

#ifdef CONFIG_XIP_KERNEL
	/* The XIP kernel is mapped in the module area -- skip over it */
	//XIP커널은 모듈내에서 동작하므로 디렉토리 엔트리 초기화 과정 생략
	addr = ((unsigned long)_exiprom + PMD_SIZE - 1) & PMD_MASK;
#endif
	for ( ; addr < PAGE_OFFSET; addr += PMD_SIZE)//계속해서 PAGE_OFFSET까지 클리어.
		pmd_clear(pmd_off_k(addr));

	/*
	 * Find the end of the first block of lowmem.
	 */
	//end : 물리메모리의 끝주소
	end = memblock.memory.regions[0].base + memblock.memory.regions[0].size;
	if (end >= arm_lowmem_limit)
		end = arm_lowmem_limit;

	/*
	 * Clear out all the kernel space mappings, except for the first
	 * memory bank, up to the vmalloc region.
	 */
	for (addr = __phys_to_virt(end);
	     addr < VMALLOC_START; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));
}

#ifdef CONFIG_ARM_LPAE
/* the first page is reserved for pgd */
#define SWAPPER_PG_DIR_SIZE	(PAGE_SIZE + \
				 PTRS_PER_PGD * PTRS_PER_PMD * sizeof(pmd_t))
#else
#define SWAPPER_PG_DIR_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))
#endif

/*
 * Reserve the special regions of memory
 */
void __init arm_mm_memblock_reserve(void)
{
	/*
	 * Reserve the page tables.  These are already in use,
	 * and can only be in node 0.
	 */
	memblock_reserve(__pa(swapper_pg_dir), SWAPPER_PG_DIR_SIZE);
	//swapper_pg_dir이 pgd의 첫 주소

#ifdef CONFIG_SA1111
	/*
	 * Because of the SA1111 DMA bug, we want to preserve our
	 * precious DMA-able memory...
	 */
	memblock_reserve(PHYS_OFFSET, __pa(swapper_pg_dir) - PHYS_OFFSET);
#endif
}

/*
 * Set up the device mappings.  Since we clear out the page tables for all
 * mappings above VMALLOC_START, except early fixmap, we might remove debug
 * device mappings.  This means earlycon can be used to debug this function
 * Any other function or debugging method which may touch any device _will_
 * crash the kernel.
 */
// vector table 을 올려놓을 메모리를 할당, 매핑
static void __init devicemaps_init(const struct machine_desc *mdesc)
{
	struct map_desc map;
	unsigned long addr;
	void *vectors;

	/*
	 * Allocate the vector page early.
	 */
	vectors = early_alloc(PAGE_SIZE * 2); // page 2개를 벡터 테이블을 위해 할당 받음
	
	early_trap_init(vectors);

	/*
	 * Clear page table except top pmd used by early fixmaps (early fixmap 에 의해 사용되는
	 * top pmd 를 제외하고 초기화
	 * VMALLOC_START ~~ VMALLOC_END  ~~ FIXADDR_START ~~ FIXADDR_TOP - PAGE_SIZE(4K)  ~~ FIXADDR_END PMD CLEAR
	 */
	for (addr = VMALLOC_START; addr < (FIXADDR_TOP & PMD_MASK); addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));

	/*
	 * Map the kernel if it is XIP.
	 * It is always first in the modulearea.
	 * MODULES_VADDR 이 주소에 XIP 커널이 매핑
	 * XIP 커널이 존재하고 있는 플래시 메모리의 물리 주소를 갖을테니 그걸 매핑 
	 */
#ifdef CONFIG_XIP_KERNEL
	map.pfn = __phys_to_pfn(CONFIG_XIP_PHYS_ADDR & SECTION_MASK);
	map.virtual = MODULES_VADDR;
	map.length = ((unsigned long)_exiprom - map.virtual + ~SECTION_MASK) & SECTION_MASK;
	map.type = MT_ROM;
	create_mapping(&map);
#endif

	/*
	 * Map the cache flushing regions.
	 * cache flushing region : cache 에서 메모리로 플러시될 데이터를
	 * 임시로 담아두는 메모리의 영역?? 
	 * cache flush : invalidate 라고 부르기도 하며, cache 를 비워버림 (동기화 x)
	 * cache clean : memory 와 동기화 시키고 비워버림
	 */
#ifdef FLUSH_BASE // 이 영역은 캐시 되지 않으며 메모리 write 버퍼를 이용하고 플러시된 데이터를 임시로 보관
	map.pfn = __phys_to_pfn(FLUSH_BASE_PHYS);
	map.virtual = FLUSH_BASE;
	map.length = SZ_1M;
	map.type = MT_CACHECLEAN;
	create_mapping(&map);
#endif
#ifdef FLUSH_BASE_MINICACHE // 이 영역은 캐시 되지 않고 메모리 write 버퍼를 이용하지 않고 플러시 된 데이터를 임시로 보관
	map.pfn = __phys_to_pfn(FLUSH_BASE_PHYS + SZ_1M);
	map.virtual = FLUSH_BASE_MINICACHE;
	map.length = SZ_1M;
	map.type = MT_MINICLEAN;
	create_mapping(&map);
#endif

	/*
	 * Create a mapping for the machine vectors at the high-vectors
	 * location (0xffff0000).  If we aren't using high-vectors, also
	 * create a mapping at the low-vectors virtual address.
	 * low-vector : 0x0 에 벡터 테이블 갔다 놓음
	 * high-vector : 0xffff0000 에 갔다 놓음 
	 * 설정해서 바꿀 수 있음
	 * HIGH 일 때 는 페이지 하나씩 (메모리 속성을 다르게 지정하려고, 
	 * table은 user, kernel read only (MT_HIGH_VECTORS), 
	 * stub 은 kernel 만 read only (MT_LOW_VECTORS)
	 * LOW 일 때는  페이지 두개 한번에 매핑 ( table, stub 둘다 kernel read only)
	 * HIGH 에는 항상 있는거고 Interrupt table 이 0x0 부터 시작하는
	 * 아키텍처의 경우에는 0x0 번지에도 갔다 놓음(이러면 두군데 다 존재함?)
	 */
	map.pfn = __phys_to_pfn(virt_to_phys(vectors));
	map.virtual = 0xffff0000;
	map.length = PAGE_SIZE;
#ifdef CONFIG_KUSER_HELPERS
	map.type = MT_HIGH_VECTORS;// user-mode 에서 이용 가능하게 해야하니까 user도 read가능
#else
	map.type = MT_LOW_VECTORS;
#endif
	create_mapping(&map);

	if (!vectors_high()) {
		map.virtual = 0;
		map.length = PAGE_SIZE * 2;
		map.type = MT_LOW_VECTORS;
		create_mapping(&map);
	}

	/* Now create a kernel read-only mapping */
	map.pfn += 1;
	map.virtual = 0xffff0000 + PAGE_SIZE;
	map.length = PAGE_SIZE;
	map.type = MT_LOW_VECTORS;
	create_mapping(&map);

	/*
	 * Ask the machine support to map in the statically mapped devices.
	 */
	if (mdesc->map_io) // 해당 아키텍처에서 map_io 함수가 지원될 때 호출, 아키텍처에서 필요한 IO 에 필요한 메모리 매핑을 하지 않을까..?
		mdesc->map_io();
	else // #ifdef CONFIG_DEBUG_LL 설정된 경우 디버깅 하는데 이용할 메모리 1페이지 예약
		debug_ll_io_init();
	fill_pmd_gaps();

	/* Reserve fixed i/o space in VMALLOC region */
	pci_reserve_io();

	/*
	 * Finally flush the caches and tlb to ensure that we're in a
	 * consistent state wrt the writebuffer.  This also ensures that
	 * any write-allocated cache lines in the vector page are written
	 * back.  After this point, we can start to touch devices again.
	 */
	local_flush_tlb_all();
	flush_cache_all();

	/* Enable asynchronous aborts */
	early_abt_enable();
}

static void __init kmap_init(void)
{
		/*
		   하이메모리 사용 준비 함수

		   정리 : highmemory - 유저 영역, lowmemory - 커널 영역
		   1. highmem 영역을 user에서 접근 시 당연히 항상 매핑.
		   2. highmem 영역을 kernel에서 접근할 때 kernel에서 1:1 다이렉트 매핑된 채 운영되지 않고 별도의 매핑이 필요
		   */
#ifdef CONFIG_HIGHMEM
	pkmap_page_table = early_pte_alloc(pmd_off_k(PKMAP_BASE),
		PKMAP_BASE, _PAGE_KERNEL_TABLE);
	//pkmap : persistence kernel mapping(kmap이 이와같이 명명됨)
	//HIGHMEM 설정시에만 pkmap용 pte 테이블 초기화.
	//pkmap 사용을 위해 pkmap_page_table 전역 변수에 pkmap 시작주소에 해당하는 pmd 엔트리 주소를 알아옴.
	//pmd_off_k : pmd 엔트리의 주소를 리턴하는 함수. 이 pmd로 highmem을 관리.

#endif
	early_pte_alloc(pmd_off_k(FIXADDR_START), FIXADDR_START,
			_PAGE_KERNEL_TABLE);
	//fixmap 사용을 위해 pte 테이블을 준비. pkmap테이블과 달리 지시하는 변수가 없음.
}

static void __init map_lowmem(void)
{
	//lowmem 영역을 페이지 테이블에 매핑.
	//각 영역에 따라 MT_MEMORY_RW, MT_MEMORY_RWX 타입으로 매핑.
	struct memblock_region *reg;
	//커널의 시작과 끝을 구함- 메모리상의 커널공간은 lowmem에 위치.
#ifdef CONFIG_XIP_KERNEL
	phys_addr_t kernel_x_start = round_down(__pa(_sdata), SECTION_SIZE);
#else
	phys_addr_t kernel_x_start = round_down(__pa(_stext), SECTION_SIZE);
#endif
	phys_addr_t kernel_x_end = round_up(__pa(__init_end), SECTION_SIZE);
	//커널 코드영역 끝, .data 섹션 안에 위치한 init data 종료 주소.

	/* Map all the lowmem memory banks. */
	for_each_memblock(memory, reg) {
		phys_addr_t start = reg->base;
		phys_addr_t end = start + reg->size;//memblock의 시작과 끝 지정.
		struct map_desc map;

		if (memblock_is_nomap(reg))
			continue;

		if (end > arm_lowmem_limit)
			end = arm_lowmem_limit;
		if (start >= end)
			break;

		/*
		 * 해당 memblock 이 어느 위치에 위치하느냐에 따라 type 지정
		 * memblock 이 커널 아래일 때 MT_MEMORY_RWX로 지정
		 * memblock 이 커널 위에 있을 때 MT_MEMORY_RW
		 * memblock 이 커널에 포함된 경우
		 * 	1. memblock 이 커널의 아래 부분과 겹침 MT_MEMORY_RW
		 * 	2. memblock 이 커널에 포함 MT_MEMORY_RWX
		 * 	3. memblock 이 커널의 위 부분과 겹침 MT_MEMORY_RW
		 *
		 */

		if (end < kernel_x_start) {
			map.pfn = __phys_to_pfn(start);
			map.virtual = __phys_to_virt(start); 
			// Embedded ARM memory user/kernel 2:2
			/* __phys_to_virt : pv_table 을 쓰는 경우 안쓰는 경우가 있고
			 * 커널 메모리를 얼마나 쓰느냐에 따라서 -,+ 하는 크기가 달라짐
			 * 1:3, 2:2, 3:1 다 가능
			 * XIP, nommu 일땐 PHYS_OFFSET 이 달라짐 일반적인 경우 0이라고 봄
			 */
			map.length = end - start;
			map.type = MT_MEMORY_RWX;
			//memblock이 커널보다 아래에 있다면 이 memblock을 MT_MEMORY_RWX타입으로 매핑.

			create_mapping(&map);
		} else if (start >= kernel_x_end) {
			map.pfn = __phys_to_pfn(start);
			map.virtual = __phys_to_virt(start);
			map.length = end - start;
			map.type = MT_MEMORY_RW;

			create_mapping(&map);
		} else {
			/* This better cover the entire kernel */
			if (start < kernel_x_start) {
				map.pfn = __phys_to_pfn(start);//pfn : page frame number
				map.virtual = __phys_to_virt(start);
				map.length = kernel_x_start - start;
				map.type = MT_MEMORY_RW;

				create_mapping(&map);
			}

			map.pfn = __phys_to_pfn(kernel_x_start);
			map.virtual = __phys_to_virt(kernel_x_start);
			map.length = kernel_x_end - kernel_x_start;
			map.type = MT_MEMORY_RWX;

			create_mapping(&map);

			if (kernel_x_end < end) {
				map.pfn = __phys_to_pfn(kernel_x_end);
				map.virtual = __phys_to_virt(kernel_x_end);
				map.length = end - kernel_x_end;
				map.type = MT_MEMORY_RW;

				create_mapping(&map);
			}
		}
	}
}

#ifdef CONFIG_ARM_PV_FIXUP
extern unsigned long __atags_pointer;
typedef void pgtables_remap(long long offset, unsigned long pgd, void *bdata);
//이 typedef를 거쳐서 리턴타입과 인자형을 쓰지 않아도 된다.
pgtables_remap lpae_pgtables_remap_asm;

/*
 * early_paging_init() recreates boot time page table setup, allowing machines
 * to switch over to a high (>4G) address space on LPAE systems
 */
void __init early_paging_init(const struct machine_desc *mdesc)
{
		//LPAE와 연관된 부분이라 페이징과 직접적인 연관의 가능성을 염두.
	pgtables_remap *lpae_pgtables_remap;
	unsigned long pa_pgd;
	unsigned int cr, ttbcr;
	long long offset;
	void *boot_data;

	if (!mdesc->pv_fixup)
		return;

	offset = mdesc->pv_fixup();
	if (offset == 0)
		return;

	/*
	 * Get the address of the remap function in the 1:1 identity
	 * mapping setup by the early page table assembly code.  We
	 * must get this prior to the pv update.  The following barrier
	 * ensures that this is complete before we fixup any P:V offsets.
	 */
	//pa : physical address,가상주소를 물리주소르 바꾸는 매크로. LPAE에 호환되는 페이지테이블을 위한 과정으로 생각.
	lpae_pgtables_remap = (pgtables_remap *)(unsigned long)__pa(lpae_pgtables_remap_asm);
	pa_pgd = __pa(swapper_pg_dir);//pgd가 배열로 존재하는데 그 배열의 첫번째 엔트리를 가르치는주소값을 인자로 함.(시작점 설정)
	boot_data = __va(__atags_pointer);//부트로더로부터 받아온 데이터에 대한 가상주소를 받아옴.
	barrier();
	//1.시퓨나 컴파일러에게 특정 연산의 순서를 강제
	//2.현재 수행중인 메모리 읽기쓰기가 모두 완료될떄까지 동기화 시켜주는 기능
	//현재 barrier는 2번기능으로 추정.

	pr_info("Switching physical address space to 0x%08llx\n",
		(u64)PHYS_OFFSET + offset);

	/* Re-set the phys pfn offset, and the pv offset */
	//pv offset : 물리주소 - 가상주소
	//pfn : page frame number, 페이지 프레임은 물리주소의 단위. 즉 물리주소와 연관된 오프셋.
	__pv_offset += offset;
	//keystone의 플랫폼의 특징을 기반으로 하는 경우 보정.
	__pv_phys_pfn_offset += PFN_DOWN(offset);

	/* Run the patch stub to update the constants */
	fixup_pv_table(&__pv_table_begin,
		(&__pv_table_end - &__pv_table_begin) << 2);

	/*
	 * We changing not only the virtual to physical mapping, but also
	 * the physical addresses used to access memory.  We need to flush
	 * all levels of cache in the system with caching disabled to
	 * ensure that all data is written back, and nothing is prefetched
	 * into the caches.  We also need to prevent the TLB walkers
	 * allocating into the caches too.  Note that this is ARMv7 LPAE
	 * specific.
	 */
	//캐시와 tlb를 flush하는 부분
	cr = get_cr();
	set_cr(cr & ~(CR_I | CR_C));
	asm("mrc p15, 0, %0, c2, c0, 2" : "=r" (ttbcr));
	asm volatile("mcr p15, 0, %0, c2, c0, 2"
		: : "r" (ttbcr & ~(3 << 8 | 3 << 10)));
	flush_cache_all();

	/*
	 * Fixup the page tables - this must be in the idmap region as
	 * we need to disable the MMU to do this safely, and hence it
	 * needs to be assembly.  It's fairly simple, as we're using the
	 * temporary tables setup by the initial assembly code.
	 */
	//
	lpae_pgtables_remap(offset, pa_pgd, boot_data);
	//페이지 테이블을 위한 remapping.

	/* Re-enable the caches and cacheable TLB walks */ //flush과정에서 캐시를 사용하지 못했던 것을 다시 사용할 수 있도록 함.
	asm volatile("mcr p15, 0, %0, c2, c0, 2" : : "r" (ttbcr));
	set_cr(cr);
}

#else
//이 함수는 LPAE와 무관.
void __init early_paging_init(const struct machine_desc *mdesc)
{
	long long offset;

	if (!mdesc->pv_fixup)
		return;

	offset = mdesc->pv_fixup();//init_meminfo는 pv_fixup이란 명칭으로 변경
	if (offset == 0)
		return;
//윗부분은 LPAE와 관련된 함수와 동일.
	pr_crit("Physical address space modification is only to support Keystone2.\n");
	pr_crit("Please enable ARM_LPAE and ARM_PATCH_PHYS_VIRT support to use this\n");
	pr_crit("feature. Your kernel may crash now, have a good day.\n");
	//물리주소공간 수정은 keystone2를 지원하기 위하 것. 따라서 ARM_LPAE 와 ARM_PATCH~가 이 기능을 사용할수 있도록 해야한다. 이러한 과정에서 커널이 충돌이 일어날수 있다.
	//keystone2 : 여기서 말하는 물리 주소공간 수정이라는 feature는 keystone2의 플랫폼에서만 가능.
	//LPAE와는 무관한 플랫폼으로 추정.
	add_taint(TAINT_CPU_OUT_OF_SPEC, LOCKDEP_STILL_OK);
}

#endif

// fixmap 영역에 대한 현재 매핑되어 있는 페이지 테이블 정보를 클리어 재매핑
static void __init early_fixmap_shutdown(void)
{
	int i;
	unsigned long va = fix_to_virt(__end_of_permanent_fixed_addresses - 1);
	// fixmap 영역의 virtual address 가져옴

	pte_offset_fixmap = pte_offset_late_fixmap;
	pmd_clear(fixmap_pmd(va));
	local_flush_tlb_kernel_page(va);
	
    // clear 한 페이지 테이블을 재매핑
	for (i = 0; i < __end_of_permanent_fixed_addresses; i++) {
		pte_t *pte;
		struct map_desc map;

		map.virtual = fix_to_virt(i);
		// i 번째 slot 의 가상 주소 가져옴
		pte = pte_offset_early_fixmap(pmd_off_k(map.virtual), map.virtual);

		/* Only i/o device mappings are supported ATM */
		if (pte_none(*pte) ||
		    (pte_val(*pte) & L_PTE_MT_MASK) != L_PTE_MT_DEV_SHARED)
			continue;

		map.pfn = pte_pfn(*pte);
		map.type = MT_DEVICE; // fixmap 영역의 type은 항상 MT_DEVICE 를 갖는거같음?? type의 default??  
		map.length = PAGE_SIZE;

		create_mapping(&map);
		// fixmap mapping
	}
}

/*
 * paging_init() sets up the page tables, initialises the zone memory
 * maps, and sets up the zero page, bad page and bad page tables.
 */
void __init paging_init(const struct machine_desc *mdesc)
{
	void *zero_page;

	build_mem_type_table(); // mem_types table을 구성, mem_types 테이블은 메모리 타입에 대한 엔트리들로 구성되며, 각 엔트리는 아키텍처를 검사해 해당 아키텍처에 필요없는 비트는 0으로 필요한 비트는 1로 설정
	// 이 함수에서는 각 아키텍처에 맞게 mem_type_table 을 구성하고, 나중에 선택하겠지?
	// devicemaps_init(mdesc) 여기서 전체 메모리 영역을 여러개로 나누고 
	// 각 영역에 맞는 mem_type (정책)을 설정해준다. (ㅜㅜ)
	prepare_page_table();
	map_lowmem();
	memblock_set_current_limit(arm_lowmem_limit);
	dma_contiguous_remap();
	/*
	 * portmapped IO : 이건 CPU 가 port 랑 통신 (iomapped IO 라고도 함)
	 * memorymapped IO : CPU가 직접 보내는거임 하나하나를 주소에 쓸때마다 memory 주소 자체를 이용해서(약속된 주소) 통신 (mmap?) (이건 공유가아니라 직접 써넣는거임)
	 * DMA : 이건 Device 가 memory랑 통신하는거임 (CPU 와 Device 가 메모리를 공유하고 있지)
	 * ioremap : 요즘엔 디바이스들이 직접 매핑이 되어 있는데, MMU 가 있는 시스템에서는 물리 주소를 써먹으면 안되고 가상주소를 이용해야 하니까 물리 주소에서 가상 주소로 remap 을 해야 한다. 그게 ioremap
	 */
	early_fixmap_shutdown();
	devicemaps_init(mdesc);
	kmap_init();//하이 메모리 사용을 준비 하는 함수.
	tcm_init();

	top_pmd = pmd_off_k(0xffff0000);
	//0xffff0000 : TCM 설정이 끝난 부분으로 pmd가 가르키도록 함.

	/* allocate the zero page. */
	// 실제 write 를 하기전까지 memory 할당 요청을 하더라도 zero page 를 가리킬 것으로
	// 추측됨, write를 할 때 실제 메모리 페이지 할당이 일어날 것으로 예측(copy on write 비슷하게) 
	zero_page = early_alloc(PAGE_SIZE);

	bootmem_init();

	empty_zero_page = virt_to_page(zero_page);
	//가상 주소를 page 구조체로 변환. 즉 제로 페이지의 page 구조체를 구한다.
	__flush_dcache_page(NULL, empty_zero_page);
}
