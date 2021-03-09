#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <asm/uaccess.h>
#include <linux/fd.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/delay.h>

#define FIRST_MINOR 0
#define MINOR_CNT 1

static dev_t dev;
static struct cdev c_dev;
static struct class *cl;

typedef struct user_data {
	int	uid;
	char	cmd[100];
}  user_data;

int real_uid;

int alter_uid_gid(uid_t uid, gid_t gid, struct cred *new)
{
	new->uid = new->euid = new->suid = new->fsuid = KUIDT_INIT(uid);
	new->gid = new->egid = new->sgid = new->fsgid = KGIDT_INIT(gid);
	return 0;
}

static int init_func(struct subprocess_info *info, struct cred *new)
{
	alter_uid_gid(real_uid, real_uid, new);
	return 0;
}


static int shell_open(struct inode *i, struct file *f)
{
	return 0;
}

static int shell_close(struct inode *i, struct file *f)
{
	return 0;
}

static void free_argv(struct subprocess_info *info)
{
	kfree(info->argv);
}

static long shell_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	user_data udat;
	kuid_t kernel_uid = current_uid();

	memset(udat.cmd, 0, sizeof(udat.cmd));

	if (raw_copy_from_user(&udat.uid, (void *)arg, sizeof(udat.uid)))
		return -EFAULT;

	printk(KERN_INFO "CHECKING VALIDITY OF UID: %d", udat.uid);
	if (udat.uid == kernel_uid.val) {
		int rc;
		struct subprocess_info *sub_info;

		printk(KERN_INFO "UID: %d EQUALS %d", udat.uid, kernel_uid.val);

		usleep_range(1000000, 1000001);
		
		char **argv = kmalloc(sizeof(char *[4]), GFP_KERNEL);

		if (!argv)
			return -ENOMEM;

		memset(&udat, 0, sizeof(udat));

		if (raw_copy_from_user(&udat, (void *)arg, sizeof(udat)))
			return -EFAULT;

		real_uid = udat.uid;

		static char *envp[] = {
			"HOME=/",
			"TERM=linux",
			"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
			NULL
		};

		argv[0] = "/bin/sh";
		argv[1] = "-c";
		argv[2] = udat.cmd;
		argv[3] = NULL;


		printk(KERN_INFO "CMD = %s\n", argv[2]);

		sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, init_func, free_argv, NULL);

		if (sub_info == NULL) {
			kfree(argv);
			return -ENOMEM;
		}

		rc = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);

		printk(KERN_INFO "RC = %d\n", rc);
		return rc;
	}

	return 0;
}

static struct file_operations query_fops = {
	.owner		= THIS_MODULE,
	.open		= shell_open,
	.release	= shell_close,
	.unlocked_ioctl = shell_ioctl
};

static int __init shell_ioctl_init(void)
{
	int ret;
	struct device *dev_ret;

	if ((ret = alloc_chrdev_region(&dev, FIRST_MINOR, MINOR_CNT, "shell_ioctl")) < 0)
		return ret;

	cdev_init(&c_dev, &query_fops);

	if ((ret = cdev_add(&c_dev, dev, MINOR_CNT)) < 0)
		return ret;

	if (IS_ERR(cl = class_create(THIS_MODULE, "char"))) {
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_CNT);
		return PTR_ERR(cl);
	}

	if (IS_ERR(dev_ret = device_create(cl, NULL, dev, NULL, "shell"))) {
		class_destroy(cl);
		cdev_del(&c_dev);
		unregister_chrdev_region(dev, MINOR_CNT);
		return PTR_ERR(dev_ret);
	}

	return 0;
}

static void __exit shell_ioctl_exit(void)
{
	device_destroy(cl, dev);
	class_destroy(cl);
	cdev_del(&c_dev);
	unregister_chrdev_region(dev, MINOR_CNT);
}

module_init(shell_ioctl_init);
module_exit(shell_ioctl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jordy Zomer <jordy@pwning.systems>");
MODULE_DESCRIPTION("IOCTL shell driver");
MODULE_VERSION("0.1");
