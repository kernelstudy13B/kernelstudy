#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/cpumask.h>

#include <linux/atomic.h>
#include <asm/pgtable.h>
#include <asm/mmu.h>

#ifndef INIT_MM_CONTEXT
#define INIT_MM_CONTEXT(name)
#endif

struct mm_struct init_mm = {
	.mm_rb		= RB_ROOT,
	.pgd		= swapper_pg_dir, //pgd : 페이지 디렉토리의 위치.
	/*swapper_pg_dir : 초기 페이지 테이블의 가상주소. 즉 커널이 시작되는 가상 주소
	  값에서 페이지 디렉토리 사이즈를 뺸 값.
	  head.S에 정의되어 있으며 커널이 위치할 RAM의 가상주소 아래에 위치하게 됨.
	  PAGE_OFFSET : 커널 영역의 시작 주소, TEXT_OFFSET : 커널영역의 시작주소로부터
	  실제 커널 진입점의 OFFSET
	 */
	.mm_users	= ATOMIC_INIT(2), //여기서 users는 프로세서들을 의미.
	.mm_count	= ATOMIC_INIT(1), //mm_users = mm_count + 1
	.mmap_sem	= __RWSEM_INITIALIZER(init_mm.mmap_sem),
	.page_table_lock =  __SPIN_LOCK_UNLOCKED(init_mm.page_table_lock),
	//데드락 방지를 위한 설정해주는 스핀락과 세마포어
	.mmlist		= LIST_HEAD_INIT(init_mm.mmlist),
	//시스템 내의 모든 mm_struct는 이중연결 리스트로 연결 되어 있음.
	INIT_MM_CONTEXT(init_mm)
};
