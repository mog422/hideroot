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
#include <linux/cred.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/semaphore.h>
#include <linux/syscalls.h>
#include <asm/mmu_writeable.h>


static unsigned long *k_syscall_table;

asmlinkage int(*ori_sys_getuid)(void);

asmlinkage int(*ori_sys_open)(const char *, int, int);
asmlinkage int(*ori_sys_stat64)(const char *, void *);
asmlinkage int(*ori_sys_access)(const char *, int);

static int check_deny(int uid,char const *name) {
	int s;
	if(uid != 10249 && uid != 10218 && uid != 10239) return 0;
	if(!name) return 0;
	s=strlen(name);
	if(s>3 && !strcmp(&name[s-3],"/su")) return 1;
	if(s>10 && !strcmp(&name[s-10],"/rootshell")) return 1;
	if(!strcasecmp(name,"/system/app/Superuser.apk")) return 1;
	if(!strncmp(name,"/data/data/com.noshufou.android.su",34)) return 1;
	if(s>8&&!strncmp(name,"/proc/",6) && !strcmp(&name[s-8],"/cmdline")) return 1;
	return 0;
}
asmlinkage int sys_hideroot_open(char *_fname, int flags, int mode)
{
	int uid=ori_sys_getuid();
	char *fname=getname(_fname);
	if(fname && check_deny(uid,fname) && strcmp(fname,"/proc/self/cmdline")) {
		if(strncmp(fname,"/proc/",6)) printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		return -ENOENT;
	}
	return(ori_sys_open(_fname, flags, mode));
}
asmlinkage int sys_hideroot_stat64(char *_fname, void *parm)
{
	int uid=ori_sys_getuid();
	char const *fname=getname(_fname);
	if(check_deny(uid,fname)) {
		printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		return -ENOENT;
	}
	return(ori_sys_stat64(_fname, parm));
}
asmlinkage int sys_hideroot_access(char *_fname, int parm)
{
	int uid=ori_sys_getuid();
	char const *fname=getname(_fname);
	if(check_deny(uid,fname)) {
		printk("[%s] deny %s by %d\n", __FUNCTION__, fname, uid);
		return -ENOENT;
	}
	return(ori_sys_access(_fname, parm));
}

int __init hideroot_init(void)
{
	printk("hideroot module init\n");
	k_syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	if(!k_syscall_table) {
		printk("Failed to find sys_call_table\n");
		return -ENOMEM;
	} else {
		printk("Okay let's hooking %x\n",(unsigned int)k_syscall_table);
		ori_sys_getuid = (void*)k_syscall_table[__NR_getuid];
		ori_sys_open = (void*)k_syscall_table[__NR_open];
		mem_text_write_kernel_word(&k_syscall_table[__NR_open],(unsigned long)sys_hideroot_open);
		ori_sys_stat64 = (void*)k_syscall_table[__NR_stat64];
		mem_text_write_kernel_word(&k_syscall_table[__NR_stat64],(unsigned long)sys_hideroot_stat64);
		ori_sys_access = (void*)k_syscall_table[__NR_access];
		mem_text_write_kernel_word(&k_syscall_table[__NR_access],(unsigned long)sys_hideroot_access);
	}
	printk("loaded\n");
	return 0;
}

void __exit hideroot_exit(void)
{
	mem_text_write_kernel_word(&k_syscall_table[__NR_open],(unsigned long)ori_sys_open);
	mem_text_write_kernel_word(&k_syscall_table[__NR_stat64],(unsigned long)ori_sys_stat64);
	mem_text_write_kernel_word(&k_syscall_table[__NR_access],(unsigned long)ori_sys_access);
}

module_init(hideroot_init);
module_exit(hideroot_exit);
MODULE_LICENSE("GPL");

