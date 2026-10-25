/*
 * fork_demo.c
 * Demonstrates Unix fork(): parent/child execution paths, separate memory,
 * and parent synchronization with wait().
 *
 * Compile: gcc -Wall -o fork_demo fork_demo.c
 * Run:     ./fork_demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    int counter = 100;
    pid_t pid;

    printf("[Before fork] PID=%ld, counter=%d\n", (long)getpid(), counter);
    fflush(stdout); /* Avoid duplicated buffered output after fork. */

    pid = fork();

    if (pid < 0) {
        fprintf(stderr, "[Parent] fork failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    } else if (pid == 0) {
        /* Child process branch. */
        printf("[Child ] PID=%ld, PPID=%ld\n", (long)getpid(), (long)getppid());
        counter += 50;
        printf("[Child ] counter after +50 = %d\n", counter);
        sleep(1); /* Simulate work. */
        exit(42);
    } else {
        int status;
        pid_t waited;

        /* Parent process branch. */
        printf("[Parent] PID=%ld, child PID=%ld\n", (long)getpid(), (long)pid);
        counter -= 30;
        printf("[Parent] counter after -30 = %d\n", counter);

        waited = wait(&status);
        if (waited < 0) {
            fprintf(stderr, "[Parent] wait failed: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (WIFEXITED(status)) {
            printf("[Parent] Child %ld exited normally with status %d\n",
                   (long)waited, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("[Parent] Child %ld terminated by signal %d\n",
                   (long)waited, WTERMSIG(status));
        }

        printf("[Parent] final counter = %d\n", counter);
    }

    return 0;
}
