/*
 *  linux/arch/arm/kernel/setup.c
 *
 *  Copyright (C) 1995-2001 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/screen_info.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/of_fdt.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/sort.h>
#include <linux/psci.h>

#include <asm/unified.h>
#include <asm/cp15.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/efi.h>
#include <asm/elf.h>
#include <asm/early_ioremap.h>
#include <asm/fixmap.h>
#include <asm/procinfo.h>
#include <asm/psci.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/mach-types.h>
#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/tlbflush.h>
#include <asm/xen/hypervisor.h>

#include <asm/prom.h>
#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/system_info.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/unwind.h>
#include <asm/memblock.h>
#include <asm/virt.h>

#include "atags.h"


#if defined(CONFIG_FPE_NWFPE) || defined(CONFIG_FPE_FASTFPE)
char fpe_type[8];

static int __init fpe_setup(char *line)
{
	memcpy(fpe_type, line, 8);
	return 1;
}

__setup("fpe=", fpe_setup);
#endif

extern void init_default_cache_policy(unsigned long);
extern void paging_init(const struct machine_desc *desc);
extern void early_paging_init(const struct machine_desc *);
extern void sanity_check_meminfo(void);
extern enum reboot_mode reboot_mode;
extern void setup_dma_zone(const struct machine_desc *desc);

unsigned int processor_id;
EXPORT_SYMBOL(processor_id);
unsigned int __machine_arch_type __read_mostly;
EXPORT_SYMBOL(__machine_arch_type);
unsigned int cacheid __read_mostly;
EXPORT_SYMBOL(cacheid);

unsigned int __atags_pointer __initdata;

unsigned int system_rev;
EXPORT_SYMBOL(system_rev);

const char *system_serial;
EXPORT_SYMBOL(system_serial);

unsigned int system_serial_low;
EXPORT_SYMBOL(system_serial_low);

unsigned int system_serial_high;
EXPORT_SYMBOL(system_serial_high);

unsigned int elf_hwcap __read_mostly;
EXPORT_SYMBOL(elf_hwcap);

unsigned int elf_hwcap2 __read_mostly;
EXPORT_SYMBOL(elf_hwcap2);


#ifdef MULTI_CPU
struct processor processor __read_mostly;
#endif
#ifdef MULTI_TLB
struct cpu_tlb_fns cpu_tlb __read_mostly;
#endif
#ifdef MULTI_USER
struct cpu_user_fns cpu_user __read_mostly;
#endif
#ifdef MULTI_CACHE
struct cpu_cache_fns cpu_cache __read_mostly;
#endif
#ifdef CONFIG_OUTER_CACHE
struct outer_cache_fns outer_cache __read_mostly;
EXPORT_SYMBOL(outer_cache);
#endif

/*
 * Cached cpu_architecture() result for use by assembler code.
 * C code should use the cpu_architecture() function instead of accessing this
 * variable directly.
 */
int __cpu_architecture __read_mostly = CPU_ARCH_UNKNOWN;

struct stack { //각 모드일때(irq,abt,und,fiq) 스택의 포인터를 가지는 구조체)
	u32 irq[3];
	u32 abt[3];
	u32 und[3];
	u32 fiq[3];
} ____cacheline_aligned;

#ifndef CONFIG_CPU_V7M
static struct stack stacks[NR_CPUS];
#endif

char elf_platform[ELF_PLATFORM_SIZE];
EXPORT_SYMBOL(elf_platform);

static const char *cpu_name;
static const char *machine_name;
static char __initdata cmd_line[COMMAND_LINE_SIZE];
const struct machine_desc *machine_desc __initdata;

static union { char c[4]; unsigned long l; } endian_test __initdata = { { 'l', '?', '?', 'b' } };
#define ENDIANNESS ((char)endian_test.l)

DEFINE_PER_CPU(struct cpuinfo_arm, cpu_data);

/*
 * Standard memory resources
 */
static struct resource mem_res[] = {
	{
		.name = "Video RAM",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel code",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	},
	{
		.name = "Kernel data",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	}
};

#define video_ram   mem_res[0]
#define kernel_code mem_res[1]
#define kernel_data mem_res[2]

static struct resource io_res[] = {
	{
		.name = "reserved",
		.start = 0x3bc,
		.end = 0x3be,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x378,
		.end = 0x37f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x278,
		.end = 0x27f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	}
};

#define lp0 io_res[0]
#define lp1 io_res[1]
#define lp2 io_res[2]

static const char *proc_arch[] = {
	"undefined/unknown",
	"3",
	"4",
	"4T",
	"5",
	"5T",
	"5TE",
	"5TEJ",
	"6TEJ",
	"7",
	"7M",
	"?(12)",
	"?(13)",
	"?(14)",
	"?(15)",
	"?(16)",
	"?(17)",
};

#ifdef CONFIG_CPU_V7M
static int __get_cpu_architecture(void)
{
	return CPU_ARCH_ARMv7M;
}
#else
static int __get_cpu_architecture(void) //arm의 어떠한 architecture인지에 대한 정보를 얻는 함수.
{
	int cpu_arch;

	if ((read_cpuid_id() & 0x0008f000) == 0) {
		cpu_arch = CPU_ARCH_UNKNOWN;
	} else if ((read_cpuid_id() & 0x0008f000) == 0x00007000) {
		cpu_arch = (read_cpuid_id() & (1 << 23)) ? CPU_ARCH_ARMv4T : CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x00080000) == 0x00000000) {
		cpu_arch = (read_cpuid_id() >> 16) & 7;
		if (cpu_arch)
			cpu_arch += CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x000f0000) == 0x000f0000) {
		/* Revised CPUID format. Read the Memory Model Feature
		 * Register 0 and check for VMSAv7 or PMSAv7 */
		unsigned int mmfr0 = read_cpuid_ext(CPUID_EXT_MMFR0);
		if ((mmfr0 & 0x0000000f) >= 0x00000003 ||
		    (mmfr0 & 0x000000f0) >= 0x00000030)
			cpu_arch = CPU_ARCH_ARMv7;
		else if ((mmfr0 & 0x0000000f) == 0x00000002 ||
			 (mmfr0 & 0x000000f0) == 0x00000020)
			cpu_arch = CPU_ARCH_ARMv6;
		else
			cpu_arch = CPU_ARCH_UNKNOWN;
	} else
		cpu_arch = CPU_ARCH_UNKNOWN;

	return cpu_arch;
}
#endif

int __pure cpu_architecture(void) 
	// 같은 인수로 호출하면 항상 같은 값을 반환하는데 전역 변수에 대해서는 읽기만 수행하겠다.
	// __pure : 한번 호출 되면 나중에 호출 되면 함수 수행이 안되고 그전에 호출될때 리턴됬던값을 그대로 리턴, 전역 변수 사용할 때는 조심해야함
{
	BUG_ON(__cpu_architecture == CPU_ARCH_UNKNOWN);

	return __cpu_architecture;
}

static int cpu_has_aliasing_icache(unsigned int arch)
{
	int aliasing_icache;
	unsigned int id_reg, num_sets, line_size;

	/* PIPT caches never alias. */
	if (icache_is_pipt())
		return 0;

	/* arch specifies the register format */
	switch (arch) {
	case CPU_ARCH_ARMv7:
		asm("mcr	p15, 2, %0, c0, c0, 0 @ set CSSELR"
		    : /* No output operands */
		    : "r" (1));
		isb();
		asm("mrc	p15, 1, %0, c0, c0, 0 @ read CCSIDR"
		    : "=r" (id_reg));
		line_size = 4 << ((id_reg & 0x7) + 2);
		num_sets = ((id_reg >> 13) & 0x7fff) + 1;
		aliasing_icache = (line_size * num_sets) > PAGE_SIZE;
		break;
	case CPU_ARCH_ARMv6:
		aliasing_icache = read_cpuid_cachetype() & (1 << 11);
		break;
	default:
		/* I-cache aliases will be handled by D-cache aliasing code */
		aliasing_icache = 0;
	}

	return aliasing_icache;
}

static void __init cacheid_init(void)
{
	unsigned int arch = cpu_architecture();

	if (arch == CPU_ARCH_ARMv7M) {
		cacheid = 0;
	} else if (arch >= CPU_ARCH_ARMv6) {
		unsigned int cachetype = read_cpuid_cachetype();
		if ((cachetype & (7 << 29)) == 4 << 29) {
			/* ARMv7 register format */
			arch = CPU_ARCH_ARMv7;
			cacheid = CACHEID_VIPT_NONALIASING;
			switch (cachetype & (3 << 14)) {
			case (1 << 14):
				cacheid |= CACHEID_ASID_TAGGED;
				break;
			case (3 << 14):
				cacheid |= CACHEID_PIPT;
				break;
			}
		} else {
			arch = CPU_ARCH_ARMv6;
			if (cachetype & (1 << 23))
				cacheid = CACHEID_VIPT_ALIASING;
			else
				cacheid = CACHEID_VIPT_NONALIASING;
		}
		if (cpu_has_aliasing_icache(arch))
			cacheid |= CACHEID_VIPT_I_ALIASING;
	} else {
		cacheid = CACHEID_VIVT;
	}

	pr_info("CPU: %s data cache, %s instruction cache\n",
		cache_is_vivt() ? "VIVT" :
		cache_is_vipt_aliasing() ? "VIPT aliasing" :
		cache_is_vipt_nonaliasing() ? "PIPT / VIPT nonaliasing" : "unknown",
		cache_is_vivt() ? "VIVT" :
		icache_is_vivt_asid_tagged() ? "VIVT ASID tagged" :
		icache_is_vipt_aliasing() ? "VIPT aliasing" :
		icache_is_pipt() ? "PIPT" :
		cache_is_vipt_nonaliasing() ? "VIPT nonaliasing" : "unknown");
}

/*
 * These functions re-use the assembly code in head.S, which
 * already provide the required functionality.
 */
extern struct proc_info_list *lookup_processor_type(unsigned int);

void __init early_print(const char *str, ...)
{
	extern void printascii(const char *);
	char buf[256];
	va_list ap;

	va_start(ap, str);
	vsnprintf(buf, sizeof(buf), str, ap);
	va_end(ap);

#ifdef CONFIG_DEBUG_LL
	printascii(buf);
#endif
	printk("%s", buf);
}

#ifdef CONFIG_ARM_PATCH_IDIV

static inline u32 __attribute_const__ sdiv_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "sdiv r0, r0, r1" */
		u32 insn = __opcode_thumb32_compose(0xfb90, 0xf0f1);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "sdiv r0, r0, r1" */
	return __opcode_to_mem_arm(0xe710f110);
}

static inline u32 __attribute_const__ udiv_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "udiv r0, r0, r1" */
		u32 insn = __opcode_thumb32_compose(0xfbb0, 0xf0f1);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "udiv r0, r0, r1" */
	return __opcode_to_mem_arm(0xe730f110);
}

static inline u32 __attribute_const__ bx_lr_instruction(void)
{
	if (IS_ENABLED(CONFIG_THUMB2_KERNEL)) {
		/* "bx lr; nop" */
		u32 insn = __opcode_thumb32_compose(0x4770, 0x46c0);
		return __opcode_to_mem_thumb32(insn);
	}

	/* "bx lr" */
	return __opcode_to_mem_arm(0xe12fff1e);
}

static void __init patch_aeabi_idiv(void)
{
	extern void __aeabi_uidiv(void);
	extern void __aeabi_idiv(void);
	uintptr_t fn_addr;
	unsigned int mask;

	mask = IS_ENABLED(CONFIG_THUMB2_KERNEL) ? HWCAP_IDIVT : HWCAP_IDIVA;
	if (!(elf_hwcap & mask))
		return;

	pr_info("CPU: div instructions available: patching division code\n");
	
	//나눗셈이 가능한 arch의 경우 어떠한 방식으로 division을 할지에 대한 
	//handling을 정의.
	fn_addr = ((uintptr_t)&__aeabi_uidiv) & ~1; // ~(0000 0001) -> 1111 1110 
	asm ("" : "+g" (fn_addr));
	((u32 *)fn_addr)[0] = udiv_instruction();
	((u32 *)fn_addr)[1] = bx_lr_instruction();
	flush_icache_range(fn_addr, fn_addr + 8);

	fn_addr = ((uintptr_t)&__aeabi_idiv) & ~1;
	asm ("" : "+g" (fn_addr));
	((u32 *)fn_addr)[0] = sdiv_instruction();
	((u32 *)fn_addr)[1] = bx_lr_instruction();
	flush_icache_range(fn_addr, fn_addr + 8);
}

#else
static inline void patch_aeabi_idiv(void) { }
#endif

static void __init cpuid_init_hwcaps(void)
{
	int block;
	u32 isar5;

	if (cpu_architecture() < CPU_ARCH_ARMv7)
		return;

	block = cpuid_feature_extract(CPUID_EXT_ISAR0, 24);
	if (block >= 2)
		elf_hwcap |= HWCAP_IDIVA; //bitmask 'or 연산'
	if (block >= 1)
		elf_hwcap |= HWCAP_IDIVT;

	/* LPAE implies atomic ldrd/strd instructions */
	block = cpuid_feature_extract(CPUID_EXT_MMFR0, 0);
	if (block >= 5)
		elf_hwcap |= HWCAP_LPAE;

	/* check for supported v8 Crypto instructions */
	isar5 = read_cpuid_ext(CPUID_EXT_ISAR5);
	

	block = cpuid_feature_extract_field(isar5, 4);
	if (block >= 2)
		elf_hwcap2 |= HWCAP2_PMULL;
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_AES;

	block = cpuid_feature_extract_field(isar5, 8);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SHA1;

	block = cpuid_feature_extract_field(isar5, 12);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_SHA2;

	block = cpuid_feature_extract_field(isar5, 16);
	if (block >= 1)
		elf_hwcap2 |= HWCAP2_CRC32;
}

static void __init elf_hwcap_fixup(void)
{
	unsigned id = read_cpuid_id();

	/*
	 * HWCAP_TLS is available only on 1136 r1p0 and later,
	 * see also kuser_get_tls_init.
	 */
	if (read_cpuid_part() == ARM_CPU_PART_ARM1136 &&
	    ((id >> 20) & 3) == 0) {
		elf_hwcap &= ~HWCAP_TLS;
		return;
	}

	/* Verify if CPUID scheme is implemented */
	if ((id & 0x000f0000) != 0x000f0000)
		return;

	/*
	 * If the CPU supports LDREX/STREX and LDREXB/STREXB,
	 * avoid advertising SWP; it may not be atomic with
	 * multiprocessing cores.
	 */
	if (cpuid_feature_extract(CPUID_EXT_ISAR3, 12) > 1 ||
	    (cpuid_feature_extract(CPUID_EXT_ISAR3, 12) == 1 &&
	     cpuid_feature_extract(CPUID_EXT_ISAR4, 20) >= 3))
		elf_hwcap &= ~HWCAP_SWP;
}

/*
 * cpu_init - initialise one CPU.
 *
 * cpu_init sets up the per-CPU stacks.
 */
void notrace cpu_init(void)
{
// notrace : 컴파일러가 컴파일을 할때 그 함수를 profiling을 하는 기능이 있는데 notrace키워드가 있을 경우 그러한 기능을 하지 않도록 하는 키워드.(no_instrument_function)
#ifndef CONFIG_CPU_V7M
	unsigned int cpu = smp_processor_id();
	//프로세서의 번호를 알아냄.
	struct stack *stk = &stacks[cpu];//stacks : 전역배열

	if (cpu >= NR_CPUS) { //NR_CPUS : 시스템이 지원할 수 있는 최대 CPU 개수.
		pr_crit("CPU%u: bad primary CPU number\n", cpu);
		BUG();
	}

	/*
	 * This only works on resume and secondary cores. For booting on the
	 * boot cpu, smp_prepare_boot_cpu is called after percpu area setup.
	 */
	set_my_cpu_offset(per_cpu_offset(cpu));
	// per_cpu 주소를 setting 한다.
	// per_cpu : memory 영역을 cpu 별로 분리한다.  

	cpu_proc_init();
	// "CPU_NAME" + "_proc_init" 의 이름의 함수를 호출 
	// arch/arm/mm/proc-* 이름의 파일로 함수들이 구현되어 있음
	//

	/*
	 * Define the placement constraint for the inline asm directive below.
	 * In Thumb-2, msr with an immediate value is not allowed.
	 */
#ifdef CONFIG_THUMB2_KERNEL
#define PLC	"r"
#else
#define PLC	"I"
#endif

	/*
	 * setup stacks for re-entrant exception handlers
	 */
	 // stack 주소 초기화 
	__asm__ (
	"msr	cpsr_c, %1\n\t"  // msr dest src (intel syntax..?) cpsr_c 
	"add	r14, %0, %2\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %3\n\t"
	"add	r14, %0, %4\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %5\n\t"
	"add	r14, %0, %6\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %7\n\t"
	"add	r14, %0, %8\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %9"
	    :
	    : "r" (stk), // %0
		// Fast interupt mask, interupt, 
	      PLC (PSR_F_BIT | PSR_I_BIT | IRQ_MODE), // %1, PLC :  r 또는 I 
	      "I" (offsetof(struct stack, irq[0])), // %2
	      PLC (PSR_F_BIT | PSR_I_BIT | ABT_MODE),
	      "I" (offsetof(struct stack, abt[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | UND_MODE),
	      "I" (offsetof(struct stack, und[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | FIQ_MODE),
	      "I" (offsetof(struct stack, fiq[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | SVC_MODE) // %9
	    : "r14");
#endif
}

u32 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

void __init smp_setup_processor_id(void)
/*smp : 동등한 입장에서의 processor*/
{
	int i;
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;
	u32 cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	//읽어온 mpidr로 해당 affinity_level(cpu의 고유 물리 번호)의 값을 추출. 
	//현재 코어의 개수를 가져오는 함수....
	//u32 : 32비트 unsigned int

	cpu_logical_map(0) = cpu;
	for (i = 1; i < nr_cpu_ids; ++i)//nr_cpu_ids : 프로세서 코어의 개수
		cpu_logical_map(i) = i == cpu ? 0 : i;//1번부터 cpu의 번호를 삽입.

	/*
	 * clear __my_cpu_offset on boot CPU to avoid hang caused by
	 * using percpu variable early, for example, lockdep will
	 * access percpu variable inside lock_release
	 *
	 * percpu : 커널 메모리 관리 기법. 각 cpu별로 따로 사용하는 데이터를 완전히 분리하여
	 *	    lock과 같은 동기화 없이 빠르게 데이터에 접근 하는 방법. 
	 */
	set_my_cpu_offset(0);//cpu offset 초기화 세팅.

	pr_info("Booting Linux on physical CPU 0x%x\n", mpidr);
	//프로세서의 어떤 코어로 부팅중인지 알려주는 출력문.
}

struct mpidr_hash mpidr_hash;
#ifdef CONFIG_SMP
/**
 * smp_build_mpidr_hash - Pre-compute shifts required at each affinity
 *			  level in order to build a linear index from an
 *			  MPIDR value. Resulting algorithm is a collision
 *			  free hash carried out through shifting and ORing
 */
static void __init smp_build_mpidr_hash(void)
{
	u32 i, affinity;
	u32 fs[3], bits[3], ls, mask = 0;
	/*
	 * Pre-scan the list of MPIDRS and filter out bits that do
	 * not contribute to affinity levels, ie they never toggle.
	 */
	for_each_possible_cpu(i)
		mask |= (cpu_logical_map(i) ^ cpu_logical_map(0));
	pr_debug("mask of set bits 0x%x\n", mask);
	/*
	 * Find and stash the last and first bit set at all affinity levels to
	 * check how many bits are required to represent them.
	 */
	for (i = 0; i < 3; i++) {
		affinity = MPIDR_AFFINITY_LEVEL(mask, i);
		/*
		 * Find the MSB bit and LSB bits position
		 * to determine how many bits are required
		 * to express the affinity level.
		 */
		ls = fls(affinity);
		fs[i] = affinity ? ffs(affinity) - 1 : 0;
		bits[i] = ls - fs[i];
	}
	/*
	 * An index can be created from the MPIDR by isolating the
	 * significant bits at each affinity level and by shifting
	 * them in order to compress the 24 bits values space to a
	 * compressed set of values. This is equivalent to hashing
	 * the MPIDR through shifting and ORing. It is a collision free
	 * hash though not minimal since some levels might contain a number
	 * of CPUs that is not an exact power of 2 and their bit
	 * representation might contain holes, eg MPIDR[7:0] = {0x2, 0x80}.
	 */
	mpidr_hash.shift_aff[0] = fs[0];
	mpidr_hash.shift_aff[1] = MPIDR_LEVEL_BITS + fs[1] - bits[0];
	mpidr_hash.shift_aff[2] = 2*MPIDR_LEVEL_BITS + fs[2] -
						(bits[1] + bits[0]);
	mpidr_hash.mask = mask;
	mpidr_hash.bits = bits[2] + bits[1] + bits[0];
	pr_debug("MPIDR hash: aff0[%u] aff1[%u] aff2[%u] mask[0x%x] bits[%u]\n",
				mpidr_hash.shift_aff[0],
				mpidr_hash.shift_aff[1],
				mpidr_hash.shift_aff[2],
				mpidr_hash.mask,
				mpidr_hash.bits);
	/*
	 * 4x is an arbitrary value used to warn on a hash table much bigger
	 * than expected on most systems.
	 */
	if (mpidr_hash_size() > 4 * num_possible_cpus())
		pr_warn("Large number of MPIDR hash buckets detected\n");
	sync_cache_w(&mpidr_hash);
}
#endif

static void __init setup_processor(void)
{
	struct proc_info_list *list; //프로세스에 대한 정보를 담고 있는 구조체.

	/*
	 * locate processor in the list of supported processor
	 * types.  The linker builds this table for us from the
	 * entries in arch/arm/mm/proc-*.S
	 */
	list = lookup_processor_type(read_cpuid_id());
	//read_cpuid_id : architecture에 따라 cpuid를 읽어옴
	//lookup_processor_type : read_cpuid_id의 결과를 이용하여 cpu의 정보를 가져 오는 함수. __lookup_processor_type 레이블에 있는 어셈블리 코드를 동일하게 수행하여 현재 프로세서에 해당하는 정보를 저장하는 proc_info_list에 대한 포인터를 가져옴.
	//링커가 만들어 내는 별도의 섹션 공간에서 지원되는 프로세서 리스트를 검색.

	
	if (!list) {
		pr_err("CPU configuration botched (ID %08x), unable to continue.\n",
		       read_cpuid_id());
		while (1);
	}

	cpu_name = list->cpu_name; 
	__cpu_architecture = __get_cpu_architecture();
	// cpu_architecture를 읽어옴

#ifdef MULTI_CPU
	processor = *(list->proc);
#endif
#ifdef MULTI_TLB
	cpu_tlb = *list->tlb;
#endif
#ifdef MULTI_USER
	cpu_user = *list->user;
#endif
#ifdef MULTI_CACHE
	cpu_cache = *list->cache;
#endif

	pr_info("CPU: %s [%08x] revision %d (ARMv%s), cr=%08lx\n",
		cpu_name, read_cpuid_id(), read_cpuid_id() & 15,
		proc_arch[cpu_architecture()], get_cr());

	snprintf(init_utsname()->machine, __NEW_UTS_LEN + 1, "%s%c",
		 list->arch_name, ENDIANNESS);
	snprintf(elf_platform, ELF_PLATFORM_SIZE, "%s%c",
		 list->elf_name, ENDIANNESS);
	elf_hwcap = list->elf_hwcap; 
	// elf_hwcap : cpu 아키텍처에 따라서 지원하는 하드웨어들... 
	//cpu가 어떤 명령어를 지원하는 알아내기위해 유저프로그램이 사용할수 있는 bitflag.

	cpuid_init_hwcaps(); // elf_hwcap 변수를 이용해서 어떤 instruction set이 사용 가능한지   비트연산을 통해 초기화. 
	patch_aeabi_idiv(); 
	// cpu 아키텍처에 따른 div 연산을 patch(각 arch에 대한 division에 대한 지원 여부)
	// aeabi : arm 아키텍처를 위한 application binary 인터페이스.
	

#ifndef CONFIG_ARM_THUMB
	elf_hwcap &= ~(HWCAP_THUMB | HWCAP_IDIVT); // thumb 연산이 가능한지? idivt 연산이 가능한지 
	// bit set
#endif
#ifdef CONFIG_MMU
	init_default_cache_policy(list->__cpu_mm_mmu_flags);
	// list->__cpu_mm_mmu_flags 에 저장되어있는 policy 캐시 정책 설정
	// TLB에 대한 정책 설정(TLB : 가상메모리 주소를 물리메모리 주소로 변환하는 속도를 높이기 위한 캐시)
	// pmd, pte, 2단계 페이지 테이블 이용하는듯... pmd가 1차 테이블
#endif
//751라인부터는 프로세서 자체의 캐시에 대한 초기화 함수 부분

	erratum_a15_798181_init();
	// 아키텍처에 따른 에러처리
	// erratum = error
	// 에러처리에 대해 핸들러를 할당, 초기화 하는 함수.
	elf_hwcap_fixup();
	// 아키텍처에 따라 생길 수 있는 오류를 보정
	// 지원에 대한 오류를 cachedid_init 이전에 수정.
	cacheid_init();
	// 프로세서의 캐시 타입(TLB X)을 찾아 초기화를 하는 함수.
	// CPU 아키텍처에 따라 캐시 타입을 설정 캐시 타입에는 네가지가 있음
	// PIPT, VIVT, VIPT, (PIVT - 이론 상으로만 존재) 
	cpu_init();
	// ARM 예외 모드마다 스택을 지정.
}

void __init dump_machine_table(void)
{
	const struct machine_desc *p;

	early_print("Available machine support:\n\nID (hex)\tNAME\n");
	for_each_machine_desc(p)
		early_print("%08x\t%s\n", p->nr, p->name);

	early_print("\nPlease check your kernel config and/or bootloader.\n");

	while (true)
		/* can't use cpu_relax() here as it may require MMU setup */;
}

int __init arm_add_memory(u64 start, u64 size)
{
	u64 aligned_start;

	/*
	 * Ensure that start/size are aligned to a page boundary.
	 * Size is rounded down, start is rounded up.
	 */
	aligned_start = PAGE_ALIGN(start);
	if (aligned_start > start + size)
		size = 0;
	else
		size -= aligned_start - start;

#ifndef CONFIG_ARCH_PHYS_ADDR_T_64BIT
	if (aligned_start > ULONG_MAX) {
		pr_crit("Ignoring memory at 0x%08llx outside 32-bit physical address space\n",
			(long long)start);
		return -EINVAL;
	}

	if (aligned_start + size > ULONG_MAX) {
		pr_crit("Truncating memory at 0x%08llx to fit in 32-bit physical address space\n",
			(long long)start);
		/*
		 * To ensure bank->start + bank->size is representable in
		 * 32 bits, we use ULONG_MAX as the upper limit rather than 4GB.
		 * This means we lose a page after masking.
		 */
		size = ULONG_MAX - aligned_start;
	}
#endif

	if (aligned_start < PHYS_OFFSET) {
		if (aligned_start + size <= PHYS_OFFSET) {
			pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
				aligned_start, aligned_start + size);
			return -EINVAL;
		}

		pr_info("Ignoring memory below PHYS_OFFSET: 0x%08llx-0x%08llx\n",
			aligned_start, (u64)PHYS_OFFSET);

		size -= PHYS_OFFSET - aligned_start;
		aligned_start = PHYS_OFFSET;
	}

	start = aligned_start;
	size = size & ~(phys_addr_t)(PAGE_SIZE - 1);

	/*
	 * Check whether this memory region has non-zero size or
	 * invalid node number.
	 */
	if (size == 0)
		return -EINVAL;

	memblock_add(start, size);
	return 0;
}

/*
 * Pick out the memory size.  We look for mem=size@start,
 * where start and size are "size[KkMm]"
 */

static int __init early_mem(char *p)
{
	static int usermem __initdata = 0;
	u64 size;
	u64 start;
	char *endp;

	/*
	 * If the user specifies memory size, we
	 * blow away any automatically generated
	 * size.
	 */
	if (usermem == 0) {
		usermem = 1;
		memblock_remove(memblock_start_of_DRAM(),
			memblock_end_of_DRAM() - memblock_start_of_DRAM());
	}

	start = PHYS_OFFSET;
	size  = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	arm_add_memory(start, size);

	return 0;
}
early_param("mem", early_mem);

static void __init request_standard_resources(const struct machine_desc *mdesc)
{
	struct memblock_region *region;//memblock 
	struct resource *res;

	kernel_code.start   = virt_to_phys(_text);
	kernel_code.end     = virt_to_phys(_etext - 1);
	kernel_data.start   = virt_to_phys(_sdata);
	kernel_data.end     = virt_to_phys(_end - 1);
	//커널 구간 지정.

	for_each_memblock(memory, region) {//memblock 루프 시작
		res = memblock_virt_alloc(sizeof(*res), 0);
		res->name  = "System RAM";
		res->start = __pfn_to_phys(memblock_region_memory_base_pfn(region));
		res->end = __pfn_to_phys(memblock_region_memory_end_pfn(region)) - 1;
		res->flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;

		request_resource(&iomem_resource, res);

		if (kernel_code.start >= res->start &&
		    kernel_code.end <= res->end)//커널의 코드가 리소스 안에 있을 경우
			request_resource(res, &kernel_code);
		if (kernel_data.start >= res->start &&
		    kernel_data.end <= res->end)//커널의 데이터가 리소스 안에 있을 겨우
			request_resource(res, &kernel_data);
	}

	if (mdesc->video_start) {
	//video : console display, 부팅 할때 텍스트를 출력하기 위한 메모리.
		video_ram.start = mdesc->video_start;
		video_ram.end   = mdesc->video_end;
		request_resource(&iomem_resource, &video_ram);
	}

	/*
	 * Some machines don't have the possibility of ever
	 * possessing lp0, lp1 or lp2
	 */
	if (mdesc->reserve_lp0)//lp : line printer?
		//io port(pci로 예상)와 관련된 장치가 존재하는 경우...
		request_resource(&ioport_resource, &lp0);
	if (mdesc->reserve_lp1)
		request_resource(&ioport_resource, &lp1);
	if (mdesc->reserve_lp2)
		request_resource(&ioport_resource, &lp2);
}

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE)
struct screen_info screen_info = {
 .orig_video_lines	= 30,
 .orig_video_cols	= 80,
 .orig_video_mode	= 0,
 .orig_video_ega_bx	= 0,
 .orig_video_isVGA	= 1,
 .orig_video_points	= 8
};
#endif

static int __init customize_machine(void)
{
	/*
	 * customizes platform devices, or adds new ones
	 * On DT based machines, we fall back to populating the
	 * machine from the device tree, if no callback is provided,
	 * otherwise we would always need an init_machine callback.
	 */
	of_iommu_init();
	if (machine_desc->init_machine)
		machine_desc->init_machine();
#ifdef CONFIG_OF
	else
		of_platform_populate(NULL, of_default_bus_match_table,
					NULL, NULL);
#endif
	return 0;
}
arch_initcall(customize_machine);

static int __init init_machine_late(void)
{
	struct device_node *root;
	int ret;

	if (machine_desc->init_late)
		machine_desc->init_late();

	root = of_find_node_by_path("/");
	if (root) {
		ret = of_property_read_string(root, "serial-number",
					      &system_serial);
		if (ret)
			system_serial = NULL;
	}

	if (!system_serial)
		system_serial = kasprintf(GFP_KERNEL, "%08x%08x",
					  system_serial_high,
					  system_serial_low);

	return 0;
}
late_initcall(init_machine_late);

#ifdef CONFIG_KEXEC
static inline unsigned long long get_total_mem(void)
{
	unsigned long total;

	total = max_low_pfn - min_low_pfn;
	return total << PAGE_SHIFT;
}

/**
 * reserve_crashkernel() - reserves memory are for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by a dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base;
	unsigned long long total_mem;
	int ret;

	total_mem = get_total_mem();
	ret = parse_crashkernel(boot_command_line, total_mem,
				&crash_size, &crash_base);
	if (ret)
		return;

	ret = memblock_reserve(crash_base, crash_size);
	if (ret < 0) {
		pr_warn("crashkernel reservation failed - memory is in use (0x%lx)\n",
			(unsigned long)crash_base);
		return;
	}

	pr_info("Reserving %ldMB of memory at %ldMB for crashkernel (System RAM: %ldMB)\n",
		(unsigned long)(crash_size >> 20),
		(unsigned long)(crash_base >> 20),
		(unsigned long)(total_mem >> 20));

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}
#else
static inline void reserve_crashkernel(void) {}
#endif /* CONFIG_KEXEC */

void __init hyp_mode_check(void)
{
#ifdef CONFIG_ARM_VIRT_EXT
	sync_boot_mode();

	if (is_hyp_mode_available()) {
		pr_info("CPU: All CPU(s) started in HYP mode.\n");
		pr_info("CPU: Virtualization extensions available.\n");
	} else if (is_hyp_mode_mismatched()) {
		pr_warn("CPU: WARNING: CPU(s) started in wrong/inconsistent modes (primary CPU mode 0x%x)\n",
			__boot_cpu_mode & MODE_MASK);
		pr_warn("CPU: This may indicate a broken bootloader or firmware.\n");
	} else
		pr_info("CPU: All CPU(s) started in SVC mode.\n");
#endif
}

void __init setup_arch(char **cmdline_p)
{
	const struct machine_desc *mdesc;
	//커널을 구동하는 machine(또는 architecture)의 정보를 담은 지시자. 각 정보와 콜백 필드들이 있음.
	
	//unwind_init(); -- 4.6.3버전에서는 사용하지 않는 함수.
	
	setup_processor();//현재 커널이 수행되고 있는 프로세스의 정보 설정

	/*
	ATAG( ARM tag, bootloader로 부터 넘어 오는 정보)
	AAPCS(Procedure Call Standard for the ARM Architecture) 표준을 다를 때 부트로더로부터
	4개의 인자를 전달 받으며, r0 = 0, r1 = architecture ID, r2 = tagged list 포인터가 넘어온다.
	tagged list 는 struct tags의 배열로 구성되며, memory, video, initrd, revision, cmdline 등의 정보를 포함한다.
	덮여 쓰여지면 안되기 때문에, 주로 RAM의 16KB에 위치하게 된다.(권장사항)
	bootloader 에서도 아키텍처에 대한 어느정도의 설정을 하는듯????
	ATAG  방식이 예전부터 사용해오던 방식이며, 다양한 하드웨어 지원하기 위해서 
	device tree 자료구조를 정의하였음. powerpc 계열과 sparc 플랫폼에서 주로 사용되었기 때문에 
	powerpc 계열에서 사용되던 이름인 fdt(flattend device tree)라고 이름 지었음.
	그래서 ATAG 방식과 device tree 방식 둘다를 지원해야함.   		
	 */
	mdesc = setup_machine_fdt(__atags_pointer); // __atgas_pointer : 부트로더로부터 전달된 파라미터
	if (!mdesc) // setup_machine_fdt 로 부터 machine_desc 구조체를 채울수 없으면 setup_machine_tags 호출
		mdesc = setup_machine_tags(__atags_pointer, __machine_arch_type);
	machine_desc = mdesc;
	machine_name = mdesc->name;
	dump_stack_set_arch_desc("%s", mdesc->name);//mdesc의 이름을 출력.

	if (mdesc->reboot_mode != REBOOT_HARD)
		reboot_mode = mdesc->reboot_mode;
	/*재부팅시 여러가지 모드가 존재.
cold,hard : 컴퓨터 전원이 완전히 나간 후 다시 reboot.(디폴트)
warm,soft : 컴퓨터 전원이 완전히 나가지 않은 상태에서 다시 reboot.
gpio : general purpose.
	*/

	//init_mm : mm struct 구조체 변수. 0-idle프로세스 메모리 정보를 담고 있음. 
	//			즉, 지금 동작하고 있는 이 부분이 결론적으로 idle task가 되며
	//			여기에 대한 메모리 영역을 정의하는 구간.
	//			init process 의 mm struct
	//_text,_etext,_edata,_end는 arch/arm/kernel/vmlinux.lds.S에 정의 되어 있음.
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code   = (unsigned long) _etext;
	init_mm.end_data   = (unsigned long) _edata;
	init_mm.brk	   = (unsigned long) _end;
	//초기 상태 : start_brk = brk = end_data
	//https://sploitfun.wordpress.com/tag/heap/

	/*코드의 시작이 data의 시작이므로 start_data를 명시해줄 필요는 없지만
	  brk의 시작(heap의 시작)은 할당에 따라 변동.*/

	/* populate cmd_line too for later use, preserving boot_command_line */
	strlcpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);
	//차후 사용을 대비해 boot_command_line을 cmd_line에 복사.
	*cmdline_p = cmd_line;
	//setup_arch 함수의 매개변수에 cmd_line을 변경

	early_fixmap_init(); // fixmap 영역 초기화
	early_ioremap_init(); // bm_pte (bitmap_pte ?????, device 매핑되 사용될 메모리를 위해 pte table????) 

	parse_early_param(); //tmp 커맨드라인으로 들어가는 command를 나뉘어지는 토큰에 따라 setup_func함수를 호출.

#ifdef CONFIG_MMU //
	early_paging_init(mdesc);
	//LPAE와 관련이 있는 경우와 아닌경우로 나누어 메모리 정보에 대한 초기화를 하는 함수. 페이징에 대한 정보를 초기화하는 것이 아닌 페이징과 연관이 있을 메모리의 정보를 초기화.
#endif
	setup_dma_zone(mdesc);
	efi_init(); //efi 또는 uefi에 대한 메모리, descriptor 등 설정.
	sanity_check_meminfo();//highmem과 lowmem의 memblock 유효성 검사.
	arm_memblock_init(mdesc);

	early_ioremap_reset();

	paging_init(mdesc);//메모리 페이징 준비.
	request_standard_resources(mdesc);//리소스 트리 구성

	if (mdesc->restart)
		arm_pm_restart = mdesc->restart;

	unflatten_device_tree(); // fdt를 tree 구조로 만듬

	arm_dt_init_cpu_maps(); //구성된 cpu id 배열을 다시 이전에 구조를 만든 DTB와 비교하여 재구성
	psci_dt_init();
	xen_early_init();
#ifdef CONFIG_SMP
	if (is_smp()) {
		//smp 설정여부
		if (!mdesc->smp_init || !mdesc->smp_init()) {
			//smp 초기화 여부
			if (psci_smp_available())
				//psci 동작 여부
				smp_set_ops(&psci_smp_ops);
			//동작시 smp_ops가 psci_smp_ops를 가르키게 한다
			else if (mdesc->smp)
				smp_set_ops(mdesc->smp);
	
		}
		smp_init_cpus();//
		smp_build_mpidr_hash();
	}
#endif

	if (!is_smp())
		hyp_mode_check();

	reserve_crashkernel();

#ifdef CONFIG_MULTI_IRQ_HANDLER
	handle_arch_irq = mdesc->handle_irq;
#endif

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)
	conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)
	conswitchp = &dummy_con;
#endif
#endif

	if (mdesc->init_early)
		mdesc->init_early();
}


static int __init topology_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_arm *cpuinfo = &per_cpu(cpu_data, cpu);
		cpuinfo->cpu.hotpluggable = platform_can_hotplug_cpu(cpu);
		register_cpu(&cpuinfo->cpu, cpu);
	}

	return 0;
}
subsys_initcall(topology_init);

#ifdef CONFIG_HAVE_PROC_CPU
static int __init proc_cpu_init(void)
{
	struct proc_dir_entry *res;

	res = proc_mkdir("cpu", NULL);
	if (!res)
		return -ENOMEM;
	return 0;
}
fs_initcall(proc_cpu_init);
#endif

static const char *hwcap_str[] = {
	"swp",
	"half",
	"thumb",
	"26bit",
	"fastmult",
	"fpa",
	"vfp",
	"edsp",
	"java",
	"iwmmxt",
	"crunch",
	"thumbee",
	"neon",
	"vfpv3",
	"vfpv3d16",
	"tls",
	"vfpv4",
	"idiva",
	"idivt",
	"vfpd32",
	"lpae",
	"evtstrm",
	NULL
};

static const char *hwcap2_str[] = {
	"aes",
	"pmull",
	"sha1",
	"sha2",
	"crc32",
	NULL
};

static int c_show(struct seq_file *m, void *v)
{
	int i, j;
	u32 cpuid;

	for_each_online_cpu(i) {
		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
		seq_printf(m, "processor\t: %d\n", i);
		cpuid = is_smp() ? per_cpu(cpu_data, i).cpuid : read_cpuid_id();
		seq_printf(m, "model name\t: %s rev %d (%s)\n",
			   cpu_name, cpuid & 15, elf_platform);

#if defined(CONFIG_SMP)
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   per_cpu(cpu_data, i).loops_per_jiffy / (500000UL/HZ),
			   (per_cpu(cpu_data, i).loops_per_jiffy / (5000UL/HZ)) % 100);
#else
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   loops_per_jiffy / (500000/HZ),
			   (loops_per_jiffy / (5000/HZ)) % 100);
#endif
		/* dump out the processor features */
		seq_puts(m, "Features\t: ");

		for (j = 0; hwcap_str[j]; j++)
			if (elf_hwcap & (1 << j))
				seq_printf(m, "%s ", hwcap_str[j]);

		for (j = 0; hwcap2_str[j]; j++)
			if (elf_hwcap2 & (1 << j))
				seq_printf(m, "%s ", hwcap2_str[j]);

		seq_printf(m, "\nCPU implementer\t: 0x%02x\n", cpuid >> 24);
		seq_printf(m, "CPU architecture: %s\n",
			   proc_arch[cpu_architecture()]);

		if ((cpuid & 0x0008f000) == 0x00000000) {
			/* pre-ARM7 */
			seq_printf(m, "CPU part\t: %07x\n", cpuid >> 4);
		} else {
			if ((cpuid & 0x0008f000) == 0x00007000) {
				/* ARM7 */
				seq_printf(m, "CPU variant\t: 0x%02x\n",
					   (cpuid >> 16) & 127);
			} else {
				/* post-ARM7 */
				seq_printf(m, "CPU variant\t: 0x%x\n",
					   (cpuid >> 20) & 15);
			}
			seq_printf(m, "CPU part\t: 0x%03x\n",
				   (cpuid >> 4) & 0xfff);
		}
		seq_printf(m, "CPU revision\t: %d\n\n", cpuid & 15);
	}

	seq_printf(m, "Hardware\t: %s\n", machine_name);
	seq_printf(m, "Revision\t: %04x\n", system_rev);
	seq_printf(m, "Serial\t\t: %s\n", system_serial);

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};
