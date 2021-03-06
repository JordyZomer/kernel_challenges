#include <linux/cdev.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/kmod.h>

int shell_major = 0;
int shell_minor = 0;

#define DEVICE_NAME "/dev/shell"

char *shell_name = DEVICE_NAME;

typedef struct user_data {
	int	uid;
	char	cmd[20];
}  user_data;

typedef struct {
	struct semaphore	sem;
	struct cdev		cdev;
} shell_dev;

int shell_open(struct inode *inode, struct file *filp);
int shell_release(struct inode *inode, struct file *filp);
long shell_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

shell_dev shell_interface;

struct file_operations shell_fops = {
	.owner		= THIS_MODULE,
	.read		= NULL,
	.write		= NULL,
	.open		= shell_open,
	.unlocked_ioctl = shell_ioctl,
	.release	= shell_release
};

static int shell_dev_init(shell_dev *shell_interface);
static void shell_dev_del(shell_dev *shell_interface);
static int shell_setup_cdev(shell_dev *shell_interface);
static int shell_init(void);
static void shell_exit(void);

static int shell_dev_init(shell_dev *shell_interface)
{
	int result = 0;

	memset(shell_interface, 0, sizeof(shell_dev));
	sema_init(&shell_interface->sem, 1);

	return result;
}

static void shell_dev_del(shell_dev *shell_interface)
{
}

static int shell_setup_cdev(shell_dev *shell_interface)
{
	int error = 0;
	dev_t devno = MKDEV(shell_major, shell_minor);

	cdev_init(&shell_interface->cdev, &shell_fops);
	shell_interface->cdev.owner = THIS_MODULE;
	shell_interface->cdev.ops = &shell_fops;
	error = cdev_add(&shell_interface->cdev, devno, 1);

	return error;
}

static int shell_init(void)
{
	dev_t devno = 0;
	int result = 0;

	shell_dev_init(&shell_interface);

	result = alloc_chrdev_region(&devno, shell_minor, 1, shell_name);
	shell_major = MAJOR(devno);
	if (result < 0) {
		printk(KERN_WARNING "shell_interface: can't get major number %d\n", shell_major);
		goto fail;
	}

	result = shell_setup_cdev(&shell_interface);
	if (result < 0) {
		printk(KERN_WARNING "shell_interface: error %d adding shell_interface", result);
		goto fail;
	}

	printk(KERN_INFO "shell_interface: module loaded\n");
	return 0;

fail:
	shell_exit();
	return result;
}

static void shell_exit(void)
{
	dev_t devno = MKDEV(shell_major, shell_minor);

	cdev_del(&shell_interface.cdev);
	unregister_chrdev_region(devno, 1);
	shell_dev_del(&shell_interface);

	printk(KERN_INFO "shell_interface: module unloaded\n");
}

int shell_open(struct inode *inode, struct file *filp)
{
	return 0;
}

int shell_release(struct inode *inode, struct file *filp)
{
	return 0;
}

long shell_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	user_data udat;
	kuid_t kernel_uid = current_uid();

	memset(udat.cmd, 0, sizeof(udat.cmd));

	if (raw_copy_from_user(&udat.uid, (void *)arg, sizeof(udat.uid)))
		return -EFAULT;


	if (udat.uid == kernel_uid.val) {
		if (raw_copy_from_user(&udat, (void *)arg, sizeof(udat)))
			return -EFAULT;

		char *uid_arg;
		sprintf(uid_arg, "-u#%d", udat.uid);
		char *argv[] = { "/usr/bin/sudo", uid_arg, "-c", udat.cmd, NULL };
		static char *envp[] = {
			"HOME=/",
			"TERM=linux",
			"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL
		};

		return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
	}

	return 0;
}


module_init(shell_init);
module_exit(shell_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jordy Zomer <jordy@pwning.systems>");
MODULE_DESCRIPTION("IOCTL shell driver");
MODULE_VERSION("0.1");
