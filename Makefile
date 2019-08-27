#
# Makefile for the linux ext4-filesystem routines.
#

obj-m = ext4k.o

ext4k-y	:= balloc.o bitmap.o dir.o file.o fsync.o ialloc.o inode.o page-io.o \
		ioctl.o namei.o super.o symlink.o hash.o resize.o extents.o \
		ext4_jbd2.o migrate.o mballoc.o block_validity.o move_extent.o \
		mmp.o indirect.o extents_status.o xattr.o xattr_user.o \
		xattr_trusted.o inline.o readpage.o sysfs.o avatar.o
#xattr_security.o 
#acl.o xattr_security.o crypto_policy.o crypto.o \
		crypto_key.o crypto_fname.o

all:
	+make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	+make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
