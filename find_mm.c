#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/mm.h>
#include <linux/elf.h>
#include <linux/mmap_lock.h>
#include <linux/highmem.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ztex");
MODULE_DESCRIPTION("Linux kernel module to find mm containing ELF .eh_frame information");

static int pid = 0;

module_param(pid, int, 0);

/*
Reference:
 * https://stackoverflow.com/questions/60802010/linux-kernel-module-read-from-process-vma
 * https://elixir.bootlin.com/linux/v5.15/source/mm/memory.c#L5118
 * https://elixir.bootlin.com/linux/v5.15/source/mm/memory.c#L5118
*/

/*
Here we do the following things:
1. mmap_read_lock(mm); to get the rw_sem from mmap
2. get_user_pages_remote(mm, vma->vm_start, 1, FOLL_FORCE, &page, NULL, NULL);
-> to get the pages from the other userspace process
3. offset = vma->vm_start & (PAGE_SIZE-1);
-> to calculate the offset within the page
4. size = vma->vm_end - vma->vm_start;
5. if (size > PAGE_SIZE-offset) size = PAGE_SIZE-offset;
-> take care the case that the size exceeds the page size
6. maddr = kmap(page);
-> map the page to the current kernel process's memory space
7. copy_from_user_page(vma, page, vma->vm_start, buf, maddr + offset, size);
-> copy the date from the userspace page to the buffer
-> if ret <=0 it could be VM_IO | VM_PFNMAP VMA
8. log the buffer
*/
int read_vma(struct mm_struct *mm, unsigned long addr, void *buf,
		       int len, unsigned int gup_flags)
{
    struct vm_area_struct *vma;
	void *old_buf = buf;
	int write = gup_flags & FOLL_WRITE;

	if (mmap_read_lock_killable(mm))
		return 0;

	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages_remote(mm, addr, 1,
				gup_flags, &page, &vma, NULL);
		if (ret <= 0) {
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
			vma = vma_lookup(mm, addr);
			if (!vma)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
				break;
			bytes = ret;
		} else {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;

			maddr = kmap(page);
			if (write) {
                pr_err("[ztex] we dont support write here\n");
			} else {
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			put_page(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	mmap_read_unlock(mm);

	return buf - old_buf;
}

static int __init find_mm_init(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    Elf_Ehdr *ehdr;
    int found = 0;
    unsigned long size;
    unsigned long addr;
    int ret = 0;
    char *buf = NULL;

    printk(KERN_INFO "find_mm: finding mm for process with pid %d\n", pid);

    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_INFO "find_mm: process with pid %d not found\n", pid);
        return -ESRCH;
    }

    mm = get_task_mm(task);
    if (!mm) {
        pr_err("find_mm: mm not found for process with pid %d\n", pid);
        return -ENOMEM;
    }

    pr_info("find_mm: searching for ELF .eh_frame information in mm for process with pid %d\n", pid);

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        size = vma->vm_end - vma->vm_start;
        addr = vma->vm_start;
        buf = (char *)kmalloc(size + 1, GFP_KERNEL);
        if (!buf) {
            pr_err("[ztex] fail to alloc kernel buffer for [addr: %lx]:[size: %lu]\n", addr, size);
            goto loop_out;
        }
        ret = read_vma(mm, addr, buf, size, FOLL_FORCE);
        buf[size] = '\0';
        pr_info("[ztex][vma:%lx-%lx]: %s\n", vma->vm_start, vma->vm_end, buf);
loop_out:
        if (buf) {
            kfree(buf);
            buf = NULL;
        }
        /*
        if (vma->vm_file && vma->vm_file->f_op && vma->vm_file->f_op->mmap) {
            ehdr = (Elf_Ehdr *) vma->vm_file->f_op->mmap(vma->vm_file, vma, 0);
            if (ehdr && ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
                ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
                ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
                ehdr->e_ident[EI_MAG3] == ELFMAG3 &&
                ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
                ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
                ehdr->e_ident[EI_VERSION] == EV_CURRENT &&
                ehdr->e_ident[EI_OSABI] == ELFOSABI_LINUX &&
                ehdr->e_type == ET_DYN) {
                found = 1;
                break;
            }
        }
        */
    }

    mmput(mm);
    if (found) {
        pr_info("find_mm: found mm containing ELF .eh_frame information in process with pid %d\n", pid);
        pr_info("find_mm: mm start = 0x%lx, mm end = 0x%lx\n", mm->start_code, mm->end_code);
        return 0;
    } else {
        pr_info("find_mm: ELF .eh_frame information not found in mm for process with pid %d\n", pid);
        return -ENOENT;
    }
}

static void __exit find_mm_exit(void) {
    printk(KERN_INFO "find_mm: module unloaded\n");
}

module_init(find_mm_init);
module_exit(find_mm_exit);

