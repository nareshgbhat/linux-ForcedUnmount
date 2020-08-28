/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/cdev.h>
#include <linux/errno.h>

#ifdef CONFIG_FUMOUNT
static LIST_HEAD(defunct_list);

extern int remove_file_mappings(struct file *);
extern void remove_file_locks(struct file *);
extern void fumount_close( struct file *);

static struct file * clone_filp(struct file *);

/* ditto for the close semaphore */
DECLARE_MUTEX(close_sem);
#endif 

/* sysctl tunables... */
struct files_stat_struct files_stat = {
	.max_files = NR_FILE
};

EXPORT_SYMBOL(files_stat); /* Needed by unix.o */

/* public. Not pretty! */
spinlock_t __cacheline_aligned_in_smp files_lock = SPIN_LOCK_UNLOCKED;

static spinlock_t filp_count_lock = SPIN_LOCK_UNLOCKED;

/* slab constructors and destructors are called from arbitrary
 * context and must be fully threaded - use a local spinlock
 * to protect files_stat.nr_files
 */
void filp_ctor(void * objp, struct kmem_cache_s *cachep, unsigned long cflags)
{
	if ((cflags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
	    SLAB_CTOR_CONSTRUCTOR) {
		unsigned long flags;
		spin_lock_irqsave(&filp_count_lock, flags);
		files_stat.nr_files++;
		spin_unlock_irqrestore(&filp_count_lock, flags);
	}
}

void filp_dtor(void * objp, struct kmem_cache_s *cachep, unsigned long dflags)
{
	unsigned long flags;
	spin_lock_irqsave(&filp_count_lock, flags);
	files_stat.nr_files--;
	spin_unlock_irqrestore(&filp_count_lock, flags);
}

static inline void file_free(struct file *f)
{
	kmem_cache_free(filp_cachep, f);
}

/* Find an unused file structure and return a pointer to it.
 * Returns NULL, if there are no more free file structures or
 * we run out of memory.
 */
struct file *get_empty_filp(void)
{
static int old_max;
	struct file * f;

	/*
	 * Privileged users can go above max_files
	 */
	if (files_stat.nr_files < files_stat.max_files ||
				capable(CAP_SYS_ADMIN)) {
		f = kmem_cache_alloc(filp_cachep, GFP_KERNEL);
		if (f) {
			memset(f, 0, sizeof(*f));
			if (security_file_alloc(f)) {
				file_free(f);
				goto fail;
			}
			eventpoll_init_file(f);
			atomic_set(&f->f_count, 1);
			f->f_uid = current->fsuid;
			f->f_gid = current->fsgid;
			f->f_owner.lock = RW_LOCK_UNLOCKED;
			/* f->f_version: 0 */
			INIT_LIST_HEAD(&f->f_list);
			return f;
		}
	}

	/* Ran out of filps - report that */
	if (files_stat.max_files >= old_max) {
		printk(KERN_INFO "VFS: file-max limit %d reached\n",
					files_stat.max_files);
		old_max = files_stat.max_files;
	} else {
		/* Big problems... */
		printk(KERN_WARNING "VFS: filp allocation failed\n");
	}
fail:
	return NULL;
}

EXPORT_SYMBOL(get_empty_filp);

void fastcall fput(struct file *file)
{
	if (atomic_dec_and_test(&file->f_count))
		__fput(file);
}

EXPORT_SYMBOL(fput);

/* __fput is called from task context when aio completion releases the last
 * last use of a struct file *.  Do not use otherwise.
 */
void fastcall __fput(struct file *file)
{
	struct dentry *dentry = file->f_dentry;
	struct vfsmount *mnt = file->f_vfsmnt;
	struct inode *inode = dentry->d_inode;

	might_sleep();
	/*
	 * The function eventpoll_release() should be the first called
	 * in the file cleanup chain.
	 */
	eventpoll_release(file);
	locks_remove_flock(file);

	if (file->f_op && file->f_op->release)
		file->f_op->release(inode, file);
	security_file_free(file);
	if (unlikely(inode->i_cdev != NULL))
		cdev_put(inode->i_cdev);
	fops_put(file->f_op);
	if (file->f_mode & FMODE_WRITE)
		put_write_access(inode);
	file_kill(file);
	file->f_dentry = NULL;
	file->f_vfsmnt = NULL;
	file_free(file);
	dput(dentry);
	mntput(mnt);
}

#ifdef CONFIG_FUMOUNT 
void fumount_fput(struct file * file) 
{
	DEBUG_FUMOUNT;

	/* fput has already been called on this file. */
	if (atomic_dec_and_test(&file->f_count)) {
		file_free(file);
	}
}

void fastcall file_io_out(struct file * file)
{
	atomic_dec(&file->f_io_count);
}
#endif

struct file fastcall *fget(unsigned int fd)
{
	struct file *file;
	struct files_struct *files = current->files;

	spin_lock(&files->file_lock);
	file = fcheck_files(files, fd);

#ifdef CONFIG_FUMOUNT
	if (file) {
		if (file->f_mode & FMODE_FUMOUNT) {
			DEBUG_FUMOUNT;
			file = NULL;
		} else
#else
	if (file)
#endif
		get_file(file);
#ifdef CONFIG_FUMOUNT 		
	}
#endif
	spin_unlock(&files->file_lock);
	return file;
}

EXPORT_SYMBOL(fget);

#ifdef CONFIG_FUMOUNT 
/* Find an unused file structure and clone the existing file.  Returns NULL, if
 * there are no more free file structures or we run out of memory.  */
static struct file * clone_filp(struct file * orig)
{
	struct file * clone;

	DEBUG_FUMOUNT;
	clone = get_empty_filp();
	if (!clone) {
#ifdef CONFIG_FUMOUNT_DEBUG
		printk(KERN_WARNING "VFS FUMOUNT: filp allocation failed\n");
#endif
		return NULL;
	}
	/* Copy all file stats, flags etc. */
	clone->f_dentry       = orig->f_dentry;
	clone->f_version      = orig->f_version;
	clone->f_vfsmnt       = orig->f_vfsmnt;
	clone->f_op           = orig->f_op;
	clone->f_flags        = orig->f_flags;
	clone->f_mode         = orig->f_mode;
	clone->f_error        = orig->f_error;
	clone->f_pos          = orig->f_pos;
	clone->f_uid          = orig->f_uid;
	clone->f_gid          = orig->f_gid;
	clone->private_data   = orig->private_data;
	memcpy(&clone->f_ra, &orig->f_ra, sizeof(struct file_ra_state));

	return clone;
}
#endif

/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared. 
 * You can use this only if it is guranteed that the current task already 
 * holds a refcnt to that file. That check has to be done at fget() only
 * and a flag is returned to be passed to the corresponding fput_light().
 * There must not be a cloning between an fget_light/fput_light pair.
 */
struct file fastcall *fget_light(unsigned int fd, int *fput_needed)
{
	struct file *file;
	struct files_struct *files = current->files;

	*fput_needed = 0;
	if (likely((atomic_read(&files->count) == 1))) {
		file = fcheck_files(files, fd);
#ifdef CONFIG_FUMOUNT
		if (file) {
			if (file->f_mode & FMODE_FUMOUNT) {
				DEBUG_FUMOUNT;
				file = NULL;
			}
			else {
				file_io_in(file);
			}
		}
#endif
	} else {
		spin_lock(&files->file_lock);
		file = fcheck_files(files, fd);
		if (file) {
#ifdef CONFIG_FUMOUNT 	
			if (file->f_mode & FMODE_FUMOUNT) {
				DEBUG_FUMOUNT;
				file = NULL;
			} else {
#endif
				get_file(file); 
				*fput_needed = 1;
#ifdef CONFIG_FUMOUNT
				file_io_in(file);
			}
#endif
		}
		spin_unlock(&files->file_lock);
	}
	return file;
}


void put_filp(struct file *file)
{
	if (atomic_dec_and_test(&file->f_count)) {
		security_file_free(file);
		file_kill(file);
		file_free(file);
	}
}

void file_move(struct file *file, struct list_head *list)
{
	if (!list)
		return;
	file_list_lock();
	list_move(&file->f_list, list);
	file_list_unlock();
}

#ifdef CONFIG_FUMOUNT
/* file_move_test is same as file_move, but is used to complete open
   operations under the lock only if MS_FUMOUNT is not set.
   This makes sure that additional file objects are not placed on the
   sb open file list when a FORCED umount is pending.  */
int file_move_test(struct file *file, struct super_block *sb) 
{
	int ret = 0;
	struct list_head *p = &(sb->s_files);

	if (p) {
		if (!(sb->s_flags & MS_FUMOUNT))
			file_move(file, p);
		else {
			DEBUG_FUMOUNT;
			ret = -ENXIO;
		}
	}
	return ret;
}
#endif

void file_kill(struct file *file)
{
	if (!list_empty(&file->f_list)) {
		file_list_lock();
		list_del_init(&file->f_list);
		file_list_unlock();
	}
}

int fs_may_remount_ro(struct super_block *sb)
{
	struct list_head *p;

	/* Check that no files are currently opened for writing. */
	file_list_lock();
	list_for_each(p, &sb->s_files) {
		struct file *file = list_entry(p, struct file, f_list);
		struct inode *inode = file->f_dentry->d_inode;

		/* File with pending delete? */
		if (inode->i_nlink == 0)
			goto too_bad;

		/* Writeable file? */
		if (S_ISREG(inode->i_mode) && (file->f_mode & FMODE_WRITE))
			goto too_bad;
	}
	file_list_unlock();
	return 1; /* Tis' cool bro. */
too_bad:
	file_list_unlock();
	return 0;
}

#ifdef CONFIG_FUMOUNT
void fs_fumount_mark_files(struct super_block *sb)
{
 	struct list_head *p;
	struct file *file;

	DEBUG_FUMOUNT;
	/* get this lock - prevents problems with sys_flock */
	lock_kernel();

	/* Mark all files on the sb->s_files list for unmount */
	list_for_each(p, &sb->s_files) {
		file = list_entry(p, struct file, f_list);
		file->f_mode |= FMODE_FUMOUNT;
	}

	unlock_kernel();
	return; 
}

/* For each file object, unmmap all vm areas that is mmaped to file object,
 * remove file locks, and clone the file object.
 *
 * Because each mmap against a file increments the file object reference count,
 * it is necessary to unmap any areas that have been mmapped using this file 
 * descriptor.
 *
 * I'm about to clone the file object for open files and try to force a close 
 * - that can be tricky, as the close code wants to run in the context of the 
 * process that originally opened the file, and there may also be more than one 
 * owner of the file object at any given time, due to the fork and dup calls.
 * 
 * We clone the file object, move the file resources into a cloned file object, and
 * leave the previous owner with the husk only. This make the later close call of 
 * the original file owner have no effect.
 * 
 * The only syscall that is allowed to succeed following the setting of
 * FMODE_FUMOUNT is the close call, and that is protected by the new close_sem
 * semaphore. This will prevent the fumount code from colliding with the
 * normal syscall sys_close. In any event, I don't want to have a file object that 
 * I'm forcing close on to suddenly disappear when the real owner gets around to 
 * closing it.
 */
int fs_fumount_clone_list(struct super_block *sb)
{
	struct list_head *p, *n;
	int ret = 0;

	DEBUG_FUMOUNT;
	down(&close_sem);

	/* go through all the open files for this superblock */
	list_for_each_safe(p, n, &sb->s_files) {
		struct file *cloned_file;
		struct file *file = list_entry(p, struct file, f_list);
		int wait_count, file_io_count, file_io_count_old;

		if (!(file->f_mode & FMODE_FUMOUNT))
			continue;
	
		/* check for mmappings and undo, if any */
		get_file(file);  /* get reference count so file doesn't vanish */
		up(&close_sem);  /* drop lock to let sys_close progress - I have
				    the file reference to hold the object until I'm
				    done removing the mmaps */
		ret = remove_file_mappings(file);

		/* Wake up all processes waiting on the file lock and remove the file locks
		 * associated with this file object
		 */
		if(!file)
			continue;
		locks_remove_flock(file);

		down(&close_sem);
#ifdef CONFIG_FUMOUNT_DEBUG
		printk(KERN_DEBUG "file_count = %d\n", file_count(file));
#endif
		if ( file_count(file) == 1) {
		       /* okay, fumount holds last reference, so file will go away when
		 	* we fput the file, removing it from the sb list. We hold the close
			* semaphore, so the next list item will still be valid if we get
			* it before this file object is released. And, if we are terminating
			* the use of this file object, then there is nothing else to do for
			* this file, so no need to clone it. */
			fput(file);
			continue;
		}
		fput(file);

		/* clone the file */
		cloned_file = clone_filp(file);
		if (!cloned_file) {
			ret = -ENOMEM;
		break;
		}

		/* if there is any file operation in progress, wait for completion.
		* so, we can prevent the resources from being modified suddenly during file operation
		*/
		do {
			wait_count = 60;
			file_io_count_old = file_io_count(file);
			while ((file_io_count = file_io_count(file)) > 0 &&  wait_count > 0) {
#ifdef CONFIG_FUMOUNT_DEBUG
				printk("%s: waiting for io_count to be 0 (file = %x, io_count = %d)\n", __FUNCTION__, (int)file, file_io_count);
#endif
				current->state = TASK_UNINTERRUPTIBLE;
				schedule_timeout(1*HZ);
				wait_count--;
			}
		} while(file_io_count > 0 && file_io_count_old > file_io_count);

	        /* we now have a duplicated file object - change some of the
		 * fields to reflect that we stole the resources from the old
		 * file object
		 */
		file->f_op = NULL;
		file->f_dentry = (struct dentry *)NULL;
		file->f_vfsmnt = (struct vfsmount *)NULL;

		/* Set defunct flag for cleanup with sys_close */
		file->f_mode |= FMODE_DEFUNCT;

		cloned_file->f_mode &= ~FMODE_FUMOUNT;
		cloned_file->f_mode |= FMODE_DEFUNCT;

		/* Put the clone onto the sb list for further processing
		 * after the head of the sb list.
		 */
		list_move(&cloned_file->f_list, &defunct_list);
	}
	up(&close_sem);
	return ret;
}

/* Close the cloned file objects */
void fs_fumount_close( struct super_block *sb)
{
	struct list_head *p,*n;
	struct file *file;

	DEBUG_FUMOUNT;
	file_list_lock();
	/* We are deleting entries underneath ourself, so list_for_each_safe */
	list_for_each_safe(p, n, &defunct_list) {
		file = list_entry(p, struct file, f_list);
		/* fumount close grabs the list lock when required */
		file_list_unlock();
		if (!(file->f_mode & FMODE_DEFUNCT)) {
			BUG();
		}
		/* remove the cloned file object from list and close it */
		fumount_close(file);
		file_list_lock();
	}
	file_list_unlock();
	return;
}
#endif

void __init files_init(unsigned long mempages)
{ 
	int n; 
	/* One file with associated inode and dcache is very roughly 1K. 
	 * Per default don't use more than 10% of our memory for files. 
	 */ 

	n = (mempages * (PAGE_SIZE / 1024)) / 10;
	files_stat.max_files = n; 
	if (files_stat.max_files < NR_FILE)
		files_stat.max_files = NR_FILE;
} 
