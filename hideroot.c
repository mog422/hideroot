/*
 * Copyright (C) 2013  mog422 (admin@mog422.net)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include <asm/mmu_writeable.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mog422 <admin@mog422.net>");
MODULE_DESCRIPTION("Android kernel module for to bypassing rooting check");

static unsigned long *k_syscall_table;

static int apps[32] = { -1, };
static int apps_cnt = 0;

module_param_array(apps, int, &apps_cnt, 0000);
MODULE_PARM_DESC(apps, "List of app numbers to bypass rooting check (max 32)");

asmlinkage long(*ori_sys_getuid)(void);

asmlinkage long(*ori_sys_open)(const char *, int, umode_t);
asmlinkage long(*ori_sys_openat)(int, const char *, int, umode_t);
asmlinkage long(*ori_sys_fstatat64)(int,const char *, struct stat64 *,int);
asmlinkage long(*ori_sys_stat64)(const char *, struct stat64 *);
asmlinkage long(*ori_sys_lstat64)(const char *, struct stat64 *);
asmlinkage long(*ori_sys_access)(const char *, int);
asmlinkage long(*ori_sys_faccessat)(int, const char *, int);

static int check_deny(int uid, char const *name) {
	int s, i;
	for (i = 0; i < apps_cnt; i++) if (apps[i] == uid) break;
	if(i==apps_cnt) return 0;
	if(!name) return 0;
	s=strlen(name);
	if(s>3 && !strcmp(&name[s-3],"/su")) return 1;
	if(s>10 && !strcmp(&name[s-10],"/rootshell")) return 1;
	if(!strncmp(name,"/proc/",6)) {
		if (s>8 && !strcmp(&name[s-8],"/cmdline")) return 1;
		if (s>5 && !strcmp(&name[s-5],"/stat")) return 1;
		if (s>7 && !strcmp(&name[s-7],"/status")) return 1;
	}
	if(!strcasecmp(name,"/system/app/Superuser.apk")) return 1;
	if(!strcasecmp(name,"/system/app/SuperSU.apk")) return 1;
	if(!strncmp(name,"/data/app/com.noshufou.android.su",33)) return 1;
	if(!strncmp(name,"/data/data/com.noshufou.android.su",34)) return 1;
	if(!strncmp(name, "/data/app/eu.chainfire.supersu",30)) return 1;
	if(!strncmp(name, "/data/data/eu.chainfire.supersu",31)) return 1;
	return 0;
}
asmlinkage long sys_hideroot_open(const char *_fname, int flags, umode_t mode)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);

	if(IS_ERR(fname)) goto out;

	if(check_deny(uid,fname) && strcmp(fname,"/proc/self/cmdline")) {
		if(strncmp(fname,"/proc/",6)) printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		putname(fname);
		return -ENOENT;
	}
	putname(fname);
	out:
	return(ori_sys_open(_fname, flags, mode));
}
asmlinkage long sys_hideroot_openat(int dfd, const char *_fname, int flags, umode_t mode)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);
	if(IS_ERR(fname)) goto out;
	if(check_deny(uid,fname) && strcmp(fname,"/proc/self/cmdline")) {
		if(strncmp(fname,"/proc/",6)) printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		putname(fname);
		return -ENOENT;
	}
	putname(fname);
	out:
	return(ori_sys_openat(dfd, _fname, flags, mode));
}
asmlinkage long sys_hideroot_fstatat64(int dfd, const char *_fname, struct stat64 *parm,int flag)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);
	if(IS_ERR(fname)) goto out;
	if(check_deny(uid,fname)) {
		printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		putname(fname);
		return -ENOENT;
	}
	putname(fname);
	out:
	return(ori_sys_fstatat64(dfd,_fname, parm,flag));
}

asmlinkage long sys_hideroot_stat64(const char *_fname, struct stat64 *parm)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);
	if(IS_ERR(fname)) goto out;

	if(check_deny(uid,fname)) {
		printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		putname(fname);
		return -ENOENT;
	}
	putname(fname);
	out:
	return(ori_sys_stat64(_fname, parm));
}
asmlinkage long sys_hideroot_lstat64(const char *_fname, struct stat64 *parm)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);
	if(IS_ERR(fname)) goto out;

	if(check_deny(uid,fname)) {
		printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		putname(fname);
		return -ENOENT;
	}
	putname(fname);
	out:
	return(ori_sys_lstat64(_fname, parm));
}

asmlinkage long sys_hideroot_access(char *_fname, int parm)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);
	if(IS_ERR(fname)) goto out;

	if(check_deny(uid,fname)) {
		printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		putname(fname);
		return -ENOENT;
	}
	putname(fname);
	out:
	return(ori_sys_access(_fname, parm));
}

asmlinkage long sys_hideroot_faccessat(int dfd, char *_fname, int parm)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);
	if(IS_ERR(fname)) goto out;

	if(check_deny(uid,fname)) {
		printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		putname(fname);
		return -ENOENT;
	}
	putname(fname);
	out:
	return(ori_sys_faccessat(dfd, _fname, parm));
}

int __init hideroot_init(void)
{
	int i;
	printk("hideroot: module init\n");
	k_syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	if(!k_syscall_table) {
		printk("hideroot: Failed to find sys_call_table\n");
		return -ENOMEM;
	} else {
		printk("hideroot: Okay let's hooking %x\n",(unsigned int)k_syscall_table);
		ori_sys_getuid = (void*)k_syscall_table[__NR_getuid];

		ori_sys_open = (void*)k_syscall_table[__NR_open];
		mem_text_write_kernel_word(&k_syscall_table[__NR_open], (unsigned long)sys_hideroot_open);
		ori_sys_openat = (void*)k_syscall_table[__NR_openat];
		mem_text_write_kernel_word(&k_syscall_table[__NR_openat], (unsigned long)sys_hideroot_openat);
		ori_sys_fstatat64 = (void*)k_syscall_table[__NR_fstatat64];
		mem_text_write_kernel_word(&k_syscall_table[__NR_fstatat64],(unsigned long)sys_hideroot_fstatat64);

		ori_sys_stat64 = (void*)k_syscall_table[__NR_stat64];
		mem_text_write_kernel_word(&k_syscall_table[__NR_stat64],(unsigned long)sys_hideroot_stat64);
		ori_sys_lstat64 = (void*)k_syscall_table[__NR_lstat64];
		mem_text_write_kernel_word(&k_syscall_table[__NR_lstat64],(unsigned long)sys_hideroot_lstat64);
		ori_sys_access = (void*)k_syscall_table[__NR_access];
		mem_text_write_kernel_word(&k_syscall_table[__NR_access],(unsigned long)sys_hideroot_access);
		ori_sys_faccessat = (void*)k_syscall_table[__NR_faccessat];
		mem_text_write_kernel_word(&k_syscall_table[__NR_faccessat],(unsigned long)sys_hideroot_faccessat);
	}

	printk("hideroot: Module loaded with next apps (total %d)\n", apps_cnt);
	for (i = 0; i < apps_cnt; i++) {
		apps[i] += 10000;
		printk("\t%d\n", apps[i]);
	}
	printk("-------------------------------------\n");
	return 0;
}

void __exit hideroot_exit(void)
{
	mem_text_write_kernel_word(&k_syscall_table[__NR_open],(unsigned long)ori_sys_open);
	mem_text_write_kernel_word(&k_syscall_table[__NR_openat],(unsigned long)ori_sys_openat);
	mem_text_write_kernel_word(&k_syscall_table[__NR_fstatat64],(unsigned long)ori_sys_fstatat64);
	mem_text_write_kernel_word(&k_syscall_table[__NR_stat64],(unsigned long)ori_sys_stat64);
	mem_text_write_kernel_word(&k_syscall_table[__NR_lstat64],(unsigned long)ori_sys_lstat64);
	mem_text_write_kernel_word(&k_syscall_table[__NR_access],(unsigned long)ori_sys_access);
	mem_text_write_kernel_word(&k_syscall_table[__NR_faccessat],(unsigned long)ori_sys_faccessat);

}

module_init(hideroot_init);
module_exit(hideroot_exit);
