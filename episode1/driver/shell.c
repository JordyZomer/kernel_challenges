// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fd.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/miscdevice.h>

struct user_data {
	int	uid;
	char	cmd[100];
};

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


static void free_argv(struct subprocess_info *info)
{
	kfree(info->argv);
}

static long shell_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct miscdevice *misc = f->private_data;
	struct device *dev = misc->this_device;
	struct user_data udat;
	kuid_t kernel_uid = current_uid();

	memset(udat.cmd, 0, sizeof(udat.cmd));

	if (raw_copy_from_user(&udat.uid, (void *)arg, sizeof(udat.uid)))
		return -EFAULT;

	dev_info(dev, "CHECKING VALIDITY OF UID: %d\n", udat.uid);
	if (udat.uid == kernel_uid.val) {
		int rc;
		struct subprocess_info *sub_info;
		char **argv;
		static char *envp[] = {
			"HOME=/",
			"TERM=linux",
			"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
			NULL
		};

		dev_info(dev, "UID: %d EQUALS %d\n", udat.uid, kernel_uid.val);

		usleep_range(1000000, 1000001);

		argv = kmalloc(sizeof(char *[4]), GFP_KERNEL);

		if (!argv)
			return -ENOMEM;

		memset(&udat, 0, sizeof(udat));

		if (raw_copy_from_user(&udat, (void *)arg, sizeof(udat)))
			return -EFAULT;

		real_uid = udat.uid;

		argv[0] = "/bin/sh";
		argv[1] = "-c";
		argv[2] = udat.cmd;
		argv[3] = NULL;


		dev_info(dev, "CMD = %s\n", argv[2]);

		sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, init_func, free_argv, NULL);

		if (sub_info == NULL) {
			kfree(argv);
			return -ENOMEM;
		}

		rc = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);

		dev_info(dev, "RC = %d\n", rc);
		return rc;
	}

	return 0;
}

static struct file_operations query_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = shell_ioctl
};

static struct miscdevice shell_ioctl_misc = {
	.name		= "shell_ioctl",
	.fops		= &query_fops,
	.minor		= MISC_DYNAMIC_MINOR,
};

module_misc_device(shell_ioctl_misc);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jordy Zomer <jordy@pwning.systems>");
MODULE_DESCRIPTION("IOCTL shell driver");
MODULE_VERSION("0.1");
