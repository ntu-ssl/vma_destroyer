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

// reference: https://stackoverflow.com/questions/60802010/linux-kernel-module-read-from-process-vma
static int read_vma(struct mm_struct *mm, struct vm_area_struct *vma)
{
    void *maddr;
    struct page *page;
    unsigned long size;
    char *buf = NULL;
    int offset;
    long ret = -1;

    if (!vma) {
        pr_warn("vma is a NULL\n");
        return ret;
    }
    if (!(vma->vm_flags & VM_READ)) {
        pr_warn("vma is not a readable one\n");
        return ret;
    }
    mmap_read_lock(mm);

    // get the page from the remote user process, which is not neccessary the current task
    ret = get_user_pages_remote(mm, vma->vm_start, 1, FOLL_FORCE, &page, NULL, NULL);
    if (ret <= 0) {
        pr_err("err: %ld, Perhaps VM_IO | VM_PFNMAP VMA, we don't take care here\n", ret);
        // reference: https://elixir.bootlin.com/linux/v5.15/source/mm/memory.c#L5118
        ret = -1;
        goto out;
    }
    offset = vma->vm_start & (PAGE_SIZE-1);
    size = vma->vm_end - vma->vm_start;
    // Reference: https://elixir.bootlin.com/linux/v5.15/source/mm/memory.c#L5118
    /*
    The size might exceed the page size, we don't take care of it here
    */
    if (size > PAGE_SIZE-offset)
	    size = PAGE_SIZE-offset;
    buf = (char *) kmalloc(size + 1, GFP_KERNEL);
    maddr = kmap(page);
    copy_from_user_page(vma, page, vma->vm_start, buf, maddr + offset, size);

    buf[size] = '\0';
    pr_info("[ztex][vma:%lx-%lx][buff] %s\n", vma->vm_start, vma->vm_end, buf);
    ret = 0;

    kunmap(page);
    put_page(page);
out:
    mmap_read_unlock(mm);
    if (buf)
        kfree(buf);
    return ret;
}

static int __init find_mm_init(void) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    Elf_Ehdr *ehdr;
    int found = 0;

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
        read_vma(mm, vma);
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

