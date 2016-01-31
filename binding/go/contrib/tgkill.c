#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

/* XXX: weird go hack, for conscience sake.
 * it seems that Go runtime create threads and update its signal mask
 * to catch signals necessary for its runtime. It means signals deliver
 * either nurs or go runtime nomally. To deliver nurs, it is needed to
 * specify tid not pid or tgid
 */

int main(int argc, char *argv[])
{
	int tgid;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <tgid>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	tgid = atoi(argv[1]);
	return (int)syscall(SYS_tgkill, tgid, tgid, SIGTERM);
}
