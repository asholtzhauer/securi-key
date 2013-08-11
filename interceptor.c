//Securi-key by Andrew Holtzhauer

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/namei.h>

int flag=0;

#define MAX_TRY 1024;
//#define ULONG_MAX 4294967295;

MODULE_LICENSE ("GPL");

unsigned long *sys_call_table;
//unsigned long **sys_call_table;

asmlinkage long (*original_sys_setuid) (uid_t uid);
asmlinkage long (*original_sys_setresuid) (uid_t ruid, uid_t euid, uid_t suid);
asmlinkage long (*original_sys_delete_module)(const char __user *name_user, unsigned int flags);
asmlinkage long (*original_sys_kill)(int pid, int sig);

static void disable_page_protection(void){
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r" (value));
	if(!(value & 0x00010000))
		return;
	
	asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

static void enable_page_protection(void){
	unsigned long value;
	asm volatile("mov %%cr0, %0" : "=r" (value));
	if((value & 0x00010000))
		return;
	
	asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

asmlinkage long my_kill(int pid, int sig){
	return original_sys_kill(pid,sig);
}

int keychecker(void){
	struct file *f;
	char buf[128];
	mm_segment_t fs;
	int i;
	int pid = current->pid;

	// Init the buffer with 0
	for(i=0;i<128;i++)
		buf[i] = 0;
	
	f = filp_open("/home/key.keyfile", O_RDONLY, 0); //change directory here to find your keyfile
	if(f == NULL){
		printk("Key file not found!!\n");
		my_kill(pid,SIGINT);
		return 0;
	}
	else{
		//get current segment descriptor
		fs = get_fs();
		//set segment descriptor associated to kernel space
		set_fs(get_ds());
		f->f_op->read(f, buf, 128, &f->f_pos);
		//restore segment descriptor
		set_fs(fs);
	}
	filp_close(f,NULL);
	
	long key = simple_strtol(buf,0,10);
	
	if(key!=12345){ //the key we want is assigned here
		//printk("Key not found! Unable to escalate privilege!\n");
		my_kill(pid,SIGINT);
		return 0;
	}
	
	return 1;
}

asmlinkage long del_mod(const char __user *name_user, unsigned int flags){
	int keycheck = keychecker();
	
	if(keycheck==0){
		printk("Key not found! Unable to remove module!\n");
		return 0;
	}
	return original_sys_delete_module(name_user, flags);
}

asmlinkage long set_uid_protect(uid_t uid){
	// unsigned long long int startkey;
	// unsigned long long int startkey2;
	// unsigned long long int endkey;
	// unsigned long long int endcall;
	// __asm__ volatile (".byte 0x0f, 0x31" : "=A" (startkey)); //cycle # for i386 arch
	// __asm__ volatile (".byte 0x0f, 0x31" : "=A" (startkey2)); //cycle # for i386 arch
	int keycheck = keychecker();
	//__asm__ volatile (".byte 0x0f, 0x31" : "=A" (endkey)); //cycle # for i386 arch
	
	// printk("time between keys: %llu\n", startkey2-startkey);
	// printk("startkey: %llu\n",startkey);
	// printk("endkey: %llu\n",endkey);
	// printk("cycles elapsed: %llu\n",endkey-startkey);
	
	if(keycheck==0){
		printk("Key not found! Unable to escalate privilege!\n");
		return 0;
	}
	
	// __asm__ volatile (".byte 0x0f, 0x31" : "=A" (endcall)); //cycle # for i386 arch
	// printk("total cycles elapsed: %llu\n",endcall-startkey);
	return original_sys_setuid(uid);;
}

asmlinkage int set_resuid_protect(uid_t ruid, uid_t euid, uid_t suid){
	int keycheck = keychecker();
	
	if(keycheck!=1){
		printk("Key not found! Unable to escalate privilege!\n");
		return 0;
	}
		
	return original_sys_setresuid(ruid, euid, suid);;
}

static int __init my_init (void){
	unsigned long int i=PAGE_OFFSET;
	unsigned long *sys_table;
	sys_table = (unsigned long *)&system_utsname;


	while(i<ULONG_MAX){
		if(sys_table[__NR_read] == (unsigned long)sys_read){
				sys_call_table=sys_table;
				flag=1;
				break;   
		}
		i+= sizeof(void *);
		sys_table++;
	}

	if(flag){
		disable_page_protection();
		original_sys_setresuid =(void * )xchg(&sys_call_table[__NR_setresuid32],set_resuid_protect);
		original_sys_setuid =(void * )xchg(&sys_call_table[__NR_setuid32],set_uid_protect);
		original_sys_kill =(void * )xchg(&sys_call_table[__NR_kill],my_kill);
		enable_page_protection();
	}

	return 0;
}
        
static void my_exit (void){
	disable_page_protection();
	xchg(&sys_call_table[__NR_setresuid32], original_sys_setresuid);
	xchg(&sys_call_table[__NR_setuid32], original_sys_setuid);
	xchg(&sys_call_table[__NR_kill], original_sys_kill);
	enable_page_protection();
}
        
module_init(my_init);
module_exit(my_exit);
