
#include <linux/fs.h>
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/file.h>
#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"
#include "truncate.h"
#include "ext4.h"
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/fs_struct.h>
#include <linux/ima.h>
#include <linux/dnotify.h>
#include <linux/compat.h>
#include <linux/types.h>
#include<linux/audit.h>

#ifdef EXT4KFS_AVATAR

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};


struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);


static inline int build_open_flags(int flags, umode_t mode, struct open_flags *op)
{
	int lookup_flags = 0;
	int acc_mode;

	if (flags & (O_CREAT | __O_TMPFILE))
		op->mode = (mode & S_IALLUGO) | S_IFREG;
	else
		op->mode = 0;

	/* Must never be set by userspace */
	flags &= ~FMODE_NONOTIFY & ~O_CLOEXEC;

	/*
	 * O_SYNC is implemented as __O_SYNC|O_DSYNC.  As many places only
	 * check for O_DSYNC if the need any syncing at all we enforce it's
	 * always set instead of having to deal with possibly weird behaviour
	 * for malicious applications setting only __O_SYNC.
	 */
	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	if (flags & __O_TMPFILE) {
		if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
			return -EINVAL;
		acc_mode = MAY_OPEN | ACC_MODE(flags);
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	} else if (flags & O_PATH) {
		/*
		 * If we have O_PATH in the open flag. Then we
		 * cannot have anything other than the below set of flags
		 */
		flags &= O_DIRECTORY | O_NOFOLLOW | O_PATH;
		acc_mode = 0;
	} else {
		acc_mode = MAY_OPEN | ACC_MODE(flags);
	}

	op->open_flag = flags;

	/* O_TRUNC implies we need access checks for write permissions */
	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	/* Allow the LSM permission hook to distinguish append
	   access from general write access. */
	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL)
			op->intent |= LOOKUP_EXCL;
	}

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	op->lookup_flags = lookup_flags;
	return 0;
}


static struct file* do_sys_open_test(int dfd, const char* filename, int flags, umode_t mode)
{
	ext4k_debug("do_sys_open_test called");
	struct open_flags op;

	int fd = build_open_flags(flags, mode, &op);
	if (fd)	return fd;

	//struct filename tmp;
	struct filename *result;
	char *kname;
	
	//tmp.name = filename ; 
	//strcpy(tmp.iname,filename);
	//hcpark
	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);
	
	kname = (char *)result->iname;
	result->name = kname;

	strcpy(kname,filename);

	result->refcnt = 1;
	result->uptr = NULL;
	result->aname = NULL;
	//audit_getname(result);
	//hcpark

	
	fd = get_unused_fd_flags(flags);


	struct file *f ;
	
	if (fd >= 0) {
		//struct file *f = do_filp_open(dfd, &tmp, &op);
		f = do_filp_open(dfd, result, &op);

		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
		}
	}
	
	putname(result);
	//putname(&tmp);	
	
	//return fd;

	sys_close(fd) ;

	return f ;
}

//////////////////////////////////////////////////////////////////////////////////////////////


int dax_zero_page_range(struct inode *inode, loff_t from, unsigned length,
							get_block_t get_block);

static int __ext4_block_zero_page_range(handle_t *handle,
		struct address_space *mapping, loff_t from, loff_t length)
{
	ext4_fsblk_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize, pos;
	ext4_lblk_t iblock;
	struct inode *inode = mapping->host;
	struct buffer_head *bh;
	struct page *page;
	int err = 0;

	page = find_or_create_page(mapping, from >> PAGE_CACHE_SHIFT,
				   mapping_gfp_constraint(mapping, ~__GFP_FS));
	if (!page)
		return -ENOMEM;

	blocksize = inode->i_sb->s_blocksize;

	iblock = index << (PAGE_CACHE_SHIFT - inode->i_sb->s_blocksize_bits);

	if (!page_has_buffers(page))
		create_empty_buffers(page, blocksize, 0);

	/* Find the buffer that contains "offset" */
	bh = page_buffers(page);
	pos = blocksize;
	while (offset >= pos) {
		bh = bh->b_this_page;
		iblock++;
		pos += blocksize;
	}
	if (buffer_freed(bh)) {
		BUFFER_TRACE(bh, "freed: skip");
		goto unlock;
	}
	if (!buffer_mapped(bh)) {
		BUFFER_TRACE(bh, "unmapped");
		ext4_get_block(inode, iblock, bh, 0);
		/* unmapped? It's a hole - nothing to do */
		if (!buffer_mapped(bh)) {
			BUFFER_TRACE(bh, "still unmapped");
			goto unlock;
		}
	}

	/* Ok, it's mapped. Make sure it's up-to-date */
	if (PageUptodate(page))
		set_buffer_uptodate(bh);

	if (!buffer_uptodate(bh)) {
		err = -EIO;
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		/* Uhhuh. Read error. Complain and punt. */
		if (!buffer_uptodate(bh))
			goto unlock;
		if (S_ISREG(inode->i_mode) &&
		    ext4_encrypted_inode(inode)) {
			/* We expect the key to be set. */
			BUG_ON(!ext4_has_encryption_key(inode));
			BUG_ON(blocksize != PAGE_CACHE_SIZE);
			WARN_ON_ONCE(ext4_decrypt(page));
		}
	}
	if (ext4_should_journal_data(inode)) {
		BUFFER_TRACE(bh, "get write access");
		err = ext4_journal_get_write_access(handle, bh);
		if (err)
			goto unlock;
	}
	zero_user(page, offset, length);
	BUFFER_TRACE(bh, "zeroed end of block");

	if (ext4_should_journal_data(inode)) {
		err = ext4_handle_dirty_metadata(handle, inode, bh);
	} else {
		err = 0;
		mark_buffer_dirty(bh);
		if (ext4_test_inode_state(inode, EXT4_STATE_ORDERED_MODE))
			err = ext4_jbd2_file_inode(handle, inode);
	}

unlock:
	unlock_page(page);
	page_cache_release(page);
	return err;
}
		
static int ext4_block_zero_page_range(handle_t *handle,
		struct address_space *mapping, loff_t from, loff_t length)
{
	struct inode *inode = mapping->host;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned blocksize = inode->i_sb->s_blocksize;
	unsigned max = blocksize - (offset & (blocksize - 1));

	/*
	 * correct length if it does not fall between
	 * 'from' and the end of the block
	 */
	if (length > max || length < 0)
		length = max;

	if (IS_DAX(inode))
		return dax_zero_page_range(inode, from, length, ext4_get_block);
	return __ext4_block_zero_page_range(handle, mapping, from, length);
}
		
static int ext4_block_truncate_page(handle_t *handle,
		struct address_space *mapping, loff_t from)
{
	ext4k_debug("ext4_block_truncate_page called");

	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	unsigned length;
	unsigned blocksize;
	struct inode *inode = mapping->host;

	blocksize = inode->i_sb->s_blocksize;//4096바이트로 설정되어 있음
	length = blocksize - (offset & (blocksize - 1));

	return ext4_block_zero_page_range(handle, mapping, from, length);

}
		
void ext4_truncate_test(struct inode *inode)
{
	ext4k_debug("ext4_truncate_test called");

	struct ext4_inode_info *ei = EXT4_I(inode);
	unsigned int credits;
	handle_t *handle;
	struct address_space *mapping = inode->i_mapping;

	/*
	 * There is a possibility that we're either freeing the inode
	 * or it's a completely new inode. In those cases we might not
	 * have i_mutex locked because it's not necessary.
	 */
	if (!(inode->i_state & (I_NEW|I_FREEING)))
		WARN_ON((!mutex_is_locked(&inode->i_mutex)));
	
	//trace_ext4_truncate_enter(inode);

	if (!ext4_can_truncate(inode))
		return;

	ext4_clear_inode_flag(inode, EXT4_INODE_EOFBLOCKS);

	if (inode->i_size == 0 && !test_opt(inode->i_sb, NO_AUTO_DA_ALLOC))
		ext4_set_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE);

	if (ext4_has_inline_data(inode)) {//실행 안되고 있는중
		ext4k_debug("ext4_has_inline_data called");
		int has_inline = 1;

		ext4_inline_data_truncate(inode, &has_inline);
		if (has_inline)
			return;
	}

	/* If we zero-out tail of the page, we have to create jinode for jbd2 */
	if (inode->i_size & (inode->i_sb->s_blocksize - 1)) { // 파일의 사이즈가 블록사이즈로 딱 나누어 떨어지지 않을 때
		if (ext4_inode_attach_jinode(inode) < 0)
			return;
	}

	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))//이게 실행 되는중 
		{
			ext4k_debug("if ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS) called");
			credits = ext4_writepage_trans_blocks(inode);
	}
	else//실행 안되고 있는중
		{
			ext4k_debug("else ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS) called");
			credits = ext4_blocks_for_truncate(inode);
		}

	handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
	if (IS_ERR(handle)) {
		ext4_std_error(inode->i_sb, PTR_ERR(handle));
		return;
	}


	ext4k_debug("inode->i_size : %d", inode->i_size);

	ext4k_debug("inode->i_sb->s_blocksize : %d", inode->i_sb->s_blocksize);

	ext4k_debug("value : %d", inode->i_size & (inode->i_sb->s_blocksize - 1));
    
	if (inode->i_size & (inode->i_sb->s_blocksize - 1)) // 파일의 사이즈가 블록사이즈로 딱 나누어 떨어지지 않을 때
		ext4_block_truncate_page(handle, mapping, inode->i_size);

	/*
	 * We add the inode to the orphan list, so that if this
	 * truncate spans multiple transactions, and we crash, we will
	 * resume the truncate when the filesystem recovers.  It also
	 * marks the inode dirty, to catch the new size.
	 *
	 * Implication: the file must always be in a sane, consistent
	 * truncatable state while each transaction commits.
	 */
	if (ext4_orphan_add(handle, inode))
		goto out_stop;

	down_write(&EXT4_I(inode)->i_data_sem);

	ext4_discard_preallocations(inode);

	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
		ext4_ext_truncate(handle, inode);
	else
		ext4_ind_truncate(handle, inode);

	up_write(&ei->i_data_sem);

	if (IS_SYNC(inode))
		ext4_handle_sync(handle);
	
out_stop:
	/*
	 * If this was a simple ftruncate() and the file will remain alive,
	 * then we need to clear up the orphan record which we created above.
	 * However, if this was a real unlink then we were called by
	 * ext4_evict_inode(), and we allow that function to clean up the
	 * orphan info for us.
	 */
	if (inode->i_nlink)
		ext4_orphan_del(handle, inode);

	inode->i_mtime = inode->i_ctime = ext4_current_time(inode);
	ext4_mark_inode_dirty(handle, inode);
	ext4_journal_stop(handle);

	//trace_ext4_truncate_exit(inode);
}

static int travel_extents(struct rb_node* temp, int depth)// 중위 순회
{
	int left=0, right=0;

	if(temp->rb_left != NULL) left = 1 ;
	if(temp->rb_right != NULL) right = 1 ;

	int left_value = 0;
	if(left) left_value = travel_extents(temp->rb_left, depth+1);
	

	ext4k_debug("depth : %d, address(hex) : %llx left = %d, right =%d", depth, temp, left, right);

	struct extent_status *es;
		es = rb_entry(temp, struct extent_status, rb_node);
		ext4k_debug(" [%u/%u) %llu %x",
		       es->es_lblk, es->es_len,
		       ext4_es_pblock(es), ext4_es_status(es));
		
			   
	int right_value = 0;
	if(right) right_value =travel_extents(temp->rb_right, depth+1);

	return 1 + left_value + right_value ; 
}

static void ext4_es_print_tree_test(struct inode *inode)
{
	struct ext4_es_tree *tree;
	struct rb_node *node;

	printk(KERN_DEBUG "status extents for inode %lu:", inode->i_ino);
	tree = &EXT4_I(inode)->i_es_tree;
	node = rb_first(&tree->root);
	ext4k_debug("address(hex) : %llx", node); 
	int i = 0 ;
	while (node) {
		struct extent_status *es;
		es = rb_entry(node, struct extent_status, rb_node);
		printk(KERN_DEBUG "%d번 extent : [%u/%u) %llu %x",i++,
		       es->es_lblk, es->es_len,
		       ext4_es_pblock(es), ext4_es_status(es));
		node = rb_next(node);
	}
	printk(KERN_DEBUG "\n");
}

static struct rb_node* rb_nodes[50] ;//추가

static struct rb_node * get_rb_nodes(struct inode *inode)
{
	ext4k_debug("get_rb_nodes called");
	
	struct ext4_es_tree *tree;
	struct rb_node *node;

	tree = &EXT4_I(inode)->i_es_tree;
	node = rb_first(&tree->root);
	int i = 0 ;
	while (node) {
		ext4k_debug("node->__rb_parent_color : %u", node->__rb_parent_color);
		rb_nodes[i] = node ;
		struct extent_status *es;
		es = rb_entry(node, struct extent_status, rb_node);
		printk(KERN_DEBUG "%d번 extent : [%u/%u) %llu %x",i++,
		       es->es_lblk, es->es_len,
		       ext4_es_pblock(es), ext4_es_status(es));
		node = rb_next(node);
	}
	printk(KERN_DEBUG "\n");

	return rb_nodes ;
}


const long long LASTBLOCKNUM = 4294967295 ;

void splitFileHalf(struct inode *inode, int cnt)  
{
	int cnt1 = cnt/2 ;
	int cnt2 = cnt - cnt1 ;

	ext4k_debug("cnt1 = %d, cnt2 = %d", cnt1, cnt2);

	//우선 cnt1만큼을 중위순회 한다음 끝났으면 마지막블록 번호를 가지고 있는 익스텐트를 가지고 있는 노드를 만들어 그것을 가르키도록 하는 함수를 만들자.
	//
}

void cpyExtents(struct file* targetFile, struct file* sourceFile)
{
	ext4k_debug("cpyExtents called");
	struct inode *targetFileInode = file_inode(targetFile);
	struct inode *sourceFileInode = file_inode(sourceFile);

	targetFileInode->i_size = sourceFileInode->i_size;

	struct ext4_inode_info *targetFileEi = EXT4_I(targetFileInode);
	struct ext4_inode_info *sourceFileEi = EXT4_I(sourceFileInode);

	targetFileEi->i_es_tree.root.rb_node = sourceFileEi->i_es_tree.root.rb_node;


	ext4k_debug("sourcefile print");
	ext4_es_print_tree_test(sourceFile->f_inode);

	ext4k_debug("targetfile print");
	ext4_es_print_tree_test(targetFile->f_inode);
}

static int ext4_punch_hole_test(struct inode *inode, loff_t offset, loff_t length)
{
	ext4k_debug("ext4_punch_hole_test called");

	struct super_block *sb = inode->i_sb;
		ext4_lblk_t first_block, stop_block;
		struct address_space *mapping = inode->i_mapping;
		loff_t first_block_offset, last_block_offset;
		handle_t *handle;
		unsigned int credits;
		int ret = 0;
	
		if (!S_ISREG(inode->i_mode))
			return -EOPNOTSUPP;
	
		//trace_ext4_punch_hole(inode, offset, length, 0);
	
		/*
		 * Write out all dirty pages to avoid race conditions
		 * Then release them.
		 */
		if (mapping->nrpages && mapping_tagged(mapping, PAGECACHE_TAG_DIRTY)) {
			ret = filemap_write_and_wait_range(mapping, offset,
							   offset + length - 1);
			if (ret)
				return ret;
		}
	
		mutex_lock(&inode->i_mutex);
	
		/* No need to punch hole beyond i_size */
		if (offset >= inode->i_size)
			goto out_mutex;
	
		/*
		 * If the hole extends beyond i_size, set the hole
		 * to end after the page that contains i_size
		 */
		if (offset + length > inode->i_size) {
			length = inode->i_size +
			   PAGE_CACHE_SIZE - (inode->i_size & (PAGE_CACHE_SIZE - 1)) -
			   offset;
		}
	
		if (offset & (sb->s_blocksize - 1) ||
			(offset + length) & (sb->s_blocksize - 1)) {
			/*
			 * Attach jinode to inode for jbd2 if we do any zeroing of
			 * partial block
			 */
			ret = ext4_inode_attach_jinode(inode);
			if (ret < 0)
				goto out_mutex;
	
		}
	
		first_block_offset = round_up(offset, sb->s_blocksize);
		last_block_offset = round_down((offset + length), sb->s_blocksize) - 1;
	
		/* Now release the pages and zero block aligned part of pages*/
		if (last_block_offset > first_block_offset)
			truncate_pagecache_range(inode, first_block_offset,
						 last_block_offset);
	
		/* Wait all existing dio workers, newcomers will block on i_mutex */
		ext4_inode_block_unlocked_dio(inode);
		inode_dio_wait(inode);
	
		if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
			credits = ext4_writepage_trans_blocks(inode);
		else
			credits = ext4_blocks_for_truncate(inode);
		handle = ext4_journal_start(inode, EXT4_HT_TRUNCATE, credits);
		if (IS_ERR(handle)) {
			ret = PTR_ERR(handle);
			ext4_std_error(sb, ret);
			goto out_dio;
		}
	
		ret = ext4_zero_partial_blocks(handle, inode, offset,
						   length);
		if (ret)
			goto out_stop;
	
		first_block = (offset + sb->s_blocksize - 1) >>
			EXT4_BLOCK_SIZE_BITS(sb);
		stop_block = (offset + length) >> EXT4_BLOCK_SIZE_BITS(sb);
	
		/* If there are no blocks to remove, return now */
		if (first_block >= stop_block)
			//goto out_stop;
	
		down_write(&EXT4_I(inode)->i_data_sem);
		ext4_discard_preallocations(inode);

		ext4k_debug("first_block : %u, stop_block : %u, stop_block - first_block : %u", first_block, stop_block, stop_block - first_block);
		
		ret = ext4_es_remove_extent(inode, first_block,
						stop_block - first_block);
		if (ret) {
			up_write(&EXT4_I(inode)->i_data_sem);
			goto out_stop;
		}
	
		if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))
			ret = ext4_ext_remove_space(inode, first_block,
							stop_block - 1);
		else
			ret = ext4_ind_remove_space(handle, inode, first_block,
							stop_block);
	
		up_write(&EXT4_I(inode)->i_data_sem);
		if (IS_SYNC(inode))
			ext4_handle_sync(handle);
	
		/* Now release the pages again to reduce race window */
		if (last_block_offset > first_block_offset)
			truncate_pagecache_range(inode, first_block_offset,
						 last_block_offset);
	
		inode->i_mtime = inode->i_ctime = ext4_current_time(inode);
		ext4_mark_inode_dirty(handle, inode);
	out_stop:
		ext4_journal_stop(handle);
	out_dio:
		ext4_inode_resume_unlocked_dio(inode);
	out_mutex:
		mutex_unlock(&inode->i_mutex);
		return ret;

}

static void ext4_es_list_add(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

	if (!list_empty(&ei->i_es_list))
		return;

	spin_lock(&sbi->s_es_lock);
	if (list_empty(&ei->i_es_list)) {
		list_add_tail(&ei->i_es_list, &sbi->s_es_list);
		sbi->s_es_nr_inode++;
	}
	spin_unlock(&sbi->s_es_lock);
}

int ext4k_split(struct file *filp, unsigned long arg) {

	

	ext4k_debug("EXT4_IOC_SPLIT called");

	
	//////////////////////////////////////ext4_punch_hole_test//////////////////////////////////////////////////////
	struct inode *inode = file_inode(filp);
	struct ext4_inode_info *ei;
	struct rb_node* temp;
	int extent_cnt ;
	unsigned int block_cnt ; 

	//파일의 첫번 째 extent의 길이 구하기 and 분할 되야 할 파일들의 블록 길이와 바이트사이즈 구하기
	struct ext4_es_tree *tree = &EXT4_I(inode)->i_es_tree;
	struct rb_node *node = rb_first(&tree->root);
	struct extent_status *es = rb_entry(node, struct extent_status, rb_node);
	block_cnt = es->es_len ;
	ext4k_debug("block_cnt : %u", block_cnt);

	unsigned int split_size = block_cnt / arg ;//나누는 크기 단위 구하기
	ext4k_debug("split_size : %u", split_size);

	long long source_byte_size = inode->i_size;
	ext4k_debug("원래 파일의 사이즈 : %lld", source_byte_size);
	long long split_byte_size = (inode->i_size)/arg ;
	ext4k_debug("나누어 져야 할 파일의 사이즈 : %lld", split_byte_size);
	
	//원래의 파일 정보 출력
	ext4_es_print_tree_test(inode);
	ei = EXT4_I(inode);
	temp = ei->i_es_tree.root.rb_node;
	extent_cnt = travel_extents(temp, 0);
	ext4k_debug("cnt of extents(including root) : %d", extent_cnt);


	//split 시작
	int i ;
	for(i=1 ; i<=arg-1 ; i++)
	{
		long long start = split_size*i;
		start*=4 ;
 		start*=1024 ;
		long long length = 0;
		length*=4 ;
		length*=1024 ;
		ext4_punch_hole_test(inode, start, length);
		ext4_es_print_tree_test(inode);
		ei = EXT4_I(inode);
		temp = ei->i_es_tree.root.rb_node;
		extent_cnt = travel_extents(temp, 0);
		ext4k_debug("cnt of extents(including root) : %d", extent_cnt);
	}

	//분할이 완료된 파일의 extent들의 rb_node들을 가져오기 
	struct rb_node* *rb_nodes = get_rb_nodes(inode) ;
	for(i=0 ; i<arg ; i++)
	{
		struct extent_status *es;
		es = rb_entry(rb_nodes[i], struct extent_status, rb_node);
		printk(KERN_DEBUG "%d번 extent : [%u/%u) %llu %x",i,
		       es->es_lblk, es->es_len,
		       ext4_es_pblock(es), ext4_es_status(es));
	}
	
	
	//원본 파일 이름 테스트
	struct file *sourceFile = filp ;
	const unsigned char *source_name = filp->f_path.dentry->d_name.name;
	ext4k_debug("source_name : %s", source_name);

	struct inode * splited_file_inodes[20] ;
	struct file * splited_file_struct_files[20] ;

	//분할되는 파일들 생성
	for(i=0 ;i<arg ; i++)
	{
		char split_name[50];
		strcpy(split_name, "/home/junheejang/avatar/fs/");
		strcat(split_name, source_name) ;

		int num = i+1 ;
		char str_num[2] ;
		str_num[0] = '0'+num ;
		str_num[1] = '\0';
		strcat(split_name, str_num);
		ext4k_debug("split_name : %s", split_name);
		struct file * splited_file = do_sys_open_test(AT_FDCWD, split_name, O_WRONLY | O_CREAT, 0644);
		splited_file_struct_files[i] = splited_file ;



		//원본 파일의 현재 가르키고 있는 노드의 extent의 정보를 가져온다.
		struct extent_status *source_es;
			source_es = rb_entry(rb_nodes[i], struct extent_status, rb_node);


		ext4_es_insert_extent(file_inode(splited_file), 0, source_es->es_len, source_es->es_pblk, 2);
		//ext4_es_insert_extent(file_inode(splited_file), source_es->es_lblk, source_es->es_len, source_es->es_pblk, 2);

		/*struct kmem_cache *ext4_es_cachep = kmem_cache_create("ext4_extent_status",
							   sizeof(struct extent_status),
							   0, (SLAB_RECLAIM_ACCOUNT), NULL);

		//새로운 extent 정보를 할당하고 그 안에 원본 파일의 현재 가르키고 있는 extent정보를 복사한다.
		struct extent_status *newes;
		newes = kmem_cache_alloc(ext4_es_cachep, GFP_ATOMIC);
		newes->rb_node.__rb_parent_color = 1;
		newes->rb_node.rb_left=NULL;
		newes->rb_node.rb_right=NULL;
		newes->es_lblk = source_es->es_lblk ;
		newes->es_len = source_es->es_len ;
		newes->es_pblk = source_es->es_pblk ;

		

		if (!ext4_es_is_delayed(es)) {
		if (!EXT4_I(inode)->i_es_shk_nr++)
			ext4_es_list_add(inode);
		percpu_counter_inc(&EXT4_SB(inode->i_sb)->
					s_es_stats.es_stats_shk_cnt);
		}

		EXT4_I(inode)->i_es_all_nr++;
		percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_es_stats.es_stats_all_cnt);

		//분할 된 파일의 루트 노드가 방금 생성한 extent정보 안에 rb노드를 가르키게 한다.
		struct inode *splited_file_inode = file_inode(splited_file);
		struct ext4_es_tree *splited_file_tree;
		splited_file_tree = &EXT4_I(splited_file_inode)->i_es_tree;
	    splited_file_tree->root.rb_node = &(newes->rb_node) ;*/

		struct inode *splited_file_inode = file_inode(splited_file);
		if(i==arg-1)//마지막 분할되는 파일 이라면 
		{
			splited_file_inode->i_size = source_byte_size - (split_byte_size*i) ;
		}
		else
		{
			splited_file_inode->i_size = split_byte_size ;
		}
		
		splited_file_inodes[i] = splited_file_inode ;
	}

	ext4k_debug("%s의 extent 정보", source_name);
	ext4_es_print_tree_test(inode);
	
	
	for(i=0 ; i<arg ; i++)
	{
		ext4k_debug("%d번째 분할된 %s의 extent 정보", i+1, splited_file_struct_files[i]->f_path.dentry->d_name.name);
		ext4_es_print_tree_test(splited_file_inodes[i]);
	}
	
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	
	//struct inode *inode = file_inode(filp);
	
	//struct ext4_inode_info *ei = EXT4_I(inode);

	//struct rb_node* temp = ei->i_es_tree.root.rb_node;
	
	//int cnt = travel_extents(temp, 0);
	//ext4k_debug("cnt of extents(including root) : %d", cnt);


	//ext4k_debug("address(hex) : %llx, es_lblk : %u, es_len : %llu, es_pblk(hex) : %llx",&(ei->i_es_tree.cache_es->rb_node) , ei->i_es_tree.cache_es->es_lblk, ei->i_es_tree.cache_es->es_len, ei->i_es_tree.cache_es->es_pblk);

	//ext4_es_print_tree_test(inode);

	//splitFileHalf(inode, cnt-1);






	/*  truncate 테스트
		inode->i_size /= arg;
		ext4_truncate_test(inode);
   	*/


	


	
	/*int retval = 0;

	unsigned int nlink = filp->f_inode->i_nlink;
	ext4k_debug("nlink of inode: %u", nlink);

	// TODO: create empty file
	handle_t *handle;

	struct inode *inode = filp->f_inode;
	struct inode *tmp_inode = NULL;

	handle = ext4_journal_start(inode, EXT4_HT_MIGRATE,
		4 + EXT4_MAXQUOTAS_TRANS_BLOCKS(inode->i_sb));

	if (IS_ERR(handle)) {
		retval = PTR_ERR(handle);
		return retval;
	}
	
	__u32 goal;
	uid_t owner[2];

	goal = (((inode->i_ino - 1) / EXT4_INODES_PER_GROUP(inode->i_sb)) *
		EXT4_INODES_PER_GROUP(inode->i_sb)) + 1;
	ext4k_debug("goal = (%lu / %lu) * %lu + 1 = %u", inode->i_ino - 1,
		EXT4_INODES_PER_GROUP(inode->i_sb), EXT4_INODES_PER_GROUP(inode->i_sb), goal);

	owner[0] = i_uid_read(inode);
	owner[1] = i_gid_read(inode);
	ext4k_debug("owner[] = {%u, %u}", owner[0], owner[1]);

	struct inode* dinode = d_inode(inode->i_sb->s_root);

	ext4k_debug("d_inode->i_ino = %lu", dinode->i_ino);

	tmp_inode = ext4_new_inode(handle, dinode,
					S_IFREG, NULL, goal, owner);

	if (IS_ERR(tmp_inode)) {
		retval = PTR_ERR(tmp_inode);
		return retval;
	}
	
	ext4k_debug("tmp_inode : %lu", tmp_inode->i_ino);

	ext4_ext_tree_init(handle, tmp_inode);
	ext4_orphan_add(handle, tmp_inode);
	ext4_journal_stop(handle);

	// TODO: copy file of its from inode*/






	/*ext4k_debug("EXT4_IOC_SPLIT called");
	struct inode *inode = filp->f_inode;
	struct dentry* rootDentry = inode->i_sb->s_root;
	struct inode* dinode = d_inode(rootDentry);
	ext4k_debug("rootDentry name : %s",rootDentry->);*/

	//ext4k_debug("path : %s", filp->f_path.dentry->d_name.name);

	
    /*struct file * sourceFile = filp ;
	struct file * targetFile = do_sys_open_test(AT_FDCWD, "/home/junheejang/avatar/fs/test", O_WRONLY | O_CREAT, 0644);*/
	

	/*ext4k_debug("sourcefile print");
	ext4_es_print_tree_test(sourceFile->f_inode);

	ext4k_debug("targetfile print");
	ext4_es_print_tree_test(targetFile->f_inode);*/
	

	//cpyExtents(targetFile, sourceFile);
	

	
	return 0;

}

int ext4k_merge(struct file *filp, unsigned long arg) {	
	//ext4k_debug( "EXT4_IOC_MERGE called");

	
	

	return 0;
}


#endif

