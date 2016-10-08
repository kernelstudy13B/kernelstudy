/*
 *  linux/arch/arm/kernel/devtree.c
 *
 *  Copyright (C) 2009 Canonical Ltd. <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/smp.h>

#include <asm/cputype.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/smp_plat.h>
#include <asm/mach/arch.h>
#include <asm/mach-types.h>


#ifdef CONFIG_SMP
extern struct of_cpu_method __cpu_method_of_table[];

static const struct of_cpu_method __cpu_method_of_table_sentinel
	__used __section(__cpu_method_of_table_end);


static int __init set_smp_ops_by_method(struct device_node *node)
{
	const char *method;
	struct of_cpu_method *m = __cpu_method_of_table;

	if (of_property_read_string(node, "enable-method", &method))
		return 0;

	for (; m->method; m++)
		if (!strcmp(m->method, method)) {
			smp_set_ops(m->ops);
			return 1;
		}

	return 0;
}
#else
static inline int set_smp_ops_by_method(struct device_node *node)
{
	return 1;
}
#endif


/*
 * arm_dt_init_cpu_maps - Function retrieves cpu nodes from the device tree
 * and builds the cpu logical map array containing MPIDR values related to
 * logical cpus
 *
 * Updates the cpu possible mask with the number of parsed cpu nodes
 */
// smp_setup_processor_id 에서 구성했던 logical cpu array와 dtb를 비교하여 재구성하고
// 특정 SMP 아키텍처의 smp handler가 있는경우에 smp_ops를 설정한다.
// MPIDR : MultiProcessor Affinity Register
void __init arm_dt_init_cpu_maps(void)
{
	/*
	 * Temp logical map is initialized with UINT_MAX values that are
	 * considered invalid logical map entries since the logical map must
	 * contain a list of MPIDR[23:0] values where MPIDR[31:24] must
	 * read as 0.
	 */
	// MPIDR 구조(ARM 제품군에 따라 다르다. 아래는 cortex-A53 기준)
	// 31 bit : reserved always 1(new format)
	// 30 bit U : 0-> multiprocessor 1->uniprocessor
	// 29:25 UNK : reserved
	// 24 bit : Multi Thread, affinity의 가장 낮은 레벨이 멀티스레딩 타입을 이용되서 
	// 구현된 논리 코어로 구성되는지 안되는지를 나타낸다.
	// 0 : 최소 affinity 레벨에서 코어의 성능이 독립적
	// 1 : 최소 affinity 레벨에서 코어의 성능이 결합적
	// affinity 
	struct device_node *cpu, *cpus;
	int found_method = 0;
	u32 i, j, cpuidx = 1;
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;

	u32 tmp_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };
	//tmp_map의 0번째 인덱스부터 NR_CPUS-1번쨰 인덱스까지 MPIDR_INVALID(0xff00_0000)로 대입.
	bool bootcpu_valid = false;
	cpus = of_find_node_by_path("/cpus");
	// /cpus 노드를 찾음.

	if (!cpus)
		return;

	for_each_child_of_node(cpus, cpu) {
		u32 hwid;

		if (of_node_cmp(cpu->type, "cpu"))
			continue;//노드 타입이 cpu가 아니면 무시.

		pr_debug(" * %s...\n", cpu->full_name);
		/*
		 * A device tree containing CPU nodes with missing "reg"
		 * properties is considered invalid to build the
		 * cpu_logical_map.
		 */
		if (of_property_read_u32(cpu, "reg", &hwid))
	       //reg 속성이 없는 경우	{
			pr_debug(" * %s missing reg property\n",
				     cpu->full_name);
			of_node_put(cpu);
			return;
		}

		/*
		 * 8 MSBs must be set to 0 in the DT since the reg property
		 * defines the MPIDR[23:0].
		 8 MSBs(최상위 비트 8개)는 DT 에서 0으로 세팅되어야한다.
		 값이 정해져 있으면 함수를 빠져나간다.
		 cpu 노드안에 reg property가 16진수로 적혀있다.

		 reg property : 레지스터에서 읽어 온 값 또는 주소값

		 */
		if (hwid & ~MPIDR_HWID_BITMASK) {//0xFFFFFF-24비트
			of_node_put(cpu);//참조 카운트 감소
			return;
		}

		/*
		 * Duplicate MPIDRs are a recipe for disaster.
		 * Scan all initialized entries and check for
		 * duplicates. If any is found just bail out.
		 * temp values were initialized to UINT_MAX
		 * to avoid matching valid MPIDR[23:0] values.

		 reg가 중복이 되는지를 체크.
		 */
		for (j = 0; j < cpuidx; j++)
			if (WARN(tmp_map[j] == hwid,
				 "Duplicate /cpu reg properties in the DT\n")) {
				of_node_put(cpu);
				return;
			}

		/*
		 * Build a stashed array of MPIDR values. Numbering scheme
		 * requires that if detected the boot CPU must be assigned
		 * logical id 0. Other CPUs get sequential indexes starting
		 * from 1. If a CPU node with a reg property matching the
		 * boot CPU MPIDR is detected, this is recorded so that the
		 * logical map built from DT is validated and can be used
		 * to override the map created in smp_setup_processor_id().
		 */
		if (hwid == mpidr) {//DTB에서 읽은 값과 레지스터에서 읽은 값을을 비교해서 현재 부팅되어 진행중인 물리 cpu인 경우 i=0, bootcpu_valid=true로 대입
			i = 0;
			bootcpu_valid = true;
		} else {
			i = cpuidx++;
		}

		if (WARN(cpuidx > nr_cpu_ids, "DT /cpu %u nodes greater than "
					       "max cores %u, capping them\n",
					       cpuidx, nr_cpu_ids)) {
			//DTB 이상
			cpuidx = nr_cpu_ids;
			of_node_put(cpu);
			break;
		}

		tmp_map[i] = hwid;//예외처리를 다 끝낸 hwid를 대입.

		if (!found_method)//최초 루프시에만 유효한 if문.
			found_method = set_smp_ops_by_method(cpu);
	}

	/*
	 * Fallback to an enable-method in the cpus node if nothing found in
	 * a cpu node.
	cpu노드에서 아무것도 발견되지 않았을때 cpu 노드에서 사용가능한 대비책.
	 */
	if (!found_method)
		set_smp_ops_by_method(cpus);

	if (!bootcpu_valid) {//DTB에서 bootcpu가 정해지지 않은경우
		pr_warn("DT missing boot CPU MPIDR[23:0], fall back to default cpu_logical_map\n");
		return;
	}

	/*
	 * Since the boot CPU node contains proper data, and all nodes have
	 * a reg property, the DT CPU list can be considered valid and the
	 * logical map created in smp_setup_processor_id() can be overridden

	 boot cpu 노드는 proper data를 포함하고 모든 노드들은 reg property를 가지므로
	 DT cpu 리스트는 유효하고 smp~()함수 에서 만들어진 logical map은 덮어씌어진다.
	 */
	for (i = 0; i < cpuidx; i++) {
		set_cpu_possible(i, true);
		//논리 cpu(코어??)의 possible(인식 가능) 비트를 true로 만듬.
		cpu_logical_map(i) = tmp_map[i];
		pr_debug("cpu logical map 0x%x\n", cpu_logical_map(i));
	}
}

bool arch_match_cpu_phys_id(int cpu, u64 phys_id)
{
	return phys_id == cpu_logical_map(cpu);
}

static const void * __init arch_get_next_mach(const char *const **match)
{
	static const struct machine_desc *mdesc = __arch_info_begin;
	const struct machine_desc *m = mdesc;

	if (m >= __arch_info_end)
		return NULL;

	mdesc++;
	*match = m->dt_compat;
	return m;
}

/**
 * setup_machine_fdt - Machine setup when an dtb was passed to the kernel
 * @dt_phys: physical address of dt blob
 *
 * If a dtb was passed to the kernel in r2, then use it to choose the
 * correct machine_desc and to setup the system.
 */
// device tree : 하드웨어를 서술하기 위한 데이터 구조와 언어....?
const struct machine_desc * __init setup_machine_fdt(unsigned int dt_phys)
{
	const struct machine_desc *mdesc, *mdesc_best = NULL;

#if defined(CONFIG_ARCH_MULTIPLATFORM) || defined(CONFIG_ARM_SINGLE_ARMV7M)
	DT_MACHINE_START(GENERIC_DT, "Generic DT based system") // 구조체 관련 설정
	MACHINE_END

	mdesc_best = &__mach_desc_GENERIC_DT;
#endif
	// head.S 에서 pv_table 설정이 되있음
	// early_init_dt_verify : 디바이스 트리 물리 주소가 이상있는지 확인
	if (!dt_phys || !early_init_dt_verify(phys_to_virt(dt_phys))) 
		return NULL;

	mdesc = of_flat_dt_match_machine(mdesc_best, arch_get_next_mach);
	// device tree에 맞는 machine을 찾아 machine_desc 구조체를 리턴

	if (!mdesc) {
		const char *prop;
		int size;
		unsigned long dt_root;

		early_print("\nError: unrecognized/unsupported "
			    "device tree compatible list:\n[ ");

		dt_root = of_get_flat_dt_root();
		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);
		while (size > 0) {
			early_print("'%s' ", prop);
			size -= strlen(prop) + 1;
			prop += strlen(prop) + 1;
		}
		early_print("]\n\n");

		dump_machine_table(); /* does not return */
	}

	/* We really don't want to do this, but sometimes firmware provides buggy data */
	if (mdesc->dt_fixup)
		mdesc->dt_fixup();

	early_init_dt_scan_nodes();
	//  

	/* Change machine number to match the mdesc we're using */
	__machine_arch_type = mdesc->nr;

	return mdesc;
}
