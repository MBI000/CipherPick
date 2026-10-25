# `fork_demo.c` Explained (Beginner-Friendly)

## 1) What is `fork()`?

`fork()` is a Unix system call that creates a **new process**.

- The original process is the **parent**.
- The new process is the **child**.
- After `fork()`, **both processes continue from the next line** after the `fork()` call.

Small process-split diagram:

```text
Before fork:
  Parent process (PID 1000)

After fork:
              /-> Child process (PID 1001)
Parent (1000)-
              \-> Parent process continues (PID 1000)
```

---

## 2) Return values of `fork()`

| `fork()` return value | Meaning | Where seen |
|---|---|---|
| `< 0` | Fork failed (no child created) | Parent path handling error |
| `== 0` | You are in the child process | Child branch |
| `> 0` | You are in the parent; value is child PID | Parent branch |

---

## 3) Walkthrough of the code

### a) Before `fork()`

```c
int counter = 100;
printf("[Before fork] PID=%ld, counter=%d\n", (long)getpid(), counter);
fflush(stdout);
```

- `counter` starts at `100`.
- We print process info before forking.
- `fflush(stdout)` forces buffered output to be written now, so it is not accidentally duplicated by both processes after `fork()`.

### b) The `fork()` call

```c
pid = fork();
```

From here, two execution paths exist.

### c) Error handling (`pid < 0`)

```c
fprintf(stderr, "[Parent] fork failed: %s\n", strerror(errno));
return EXIT_FAILURE;
```

If creation fails, report the OS error and exit.

### d) Child branch (`pid == 0`)

```c
printf("[Child ] PID=%ld, PPID=%ld\n", (long)getpid(), (long)getppid());
counter += 50;
printf("[Child ] counter after +50 = %d\n", counter);
sleep(1);
exit(42);
```

- Child prints its PID and parent PID.
- Child changes its own `counter` to `150`.
- Child exits with code `42`.

Why call `exit()` in the child?
- It ends the child cleanly with a known status.
- It prevents the child from accidentally running parent-only logic later.

### e) Parent branch (`pid > 0`)

```c
printf("[Parent] PID=%ld, child PID=%ld\n", (long)getpid(), (long)pid);
counter -= 30;
printf("[Parent] counter after -30 = %d\n", counter);
```

- Parent prints itself and the child PID.
- Parent changes its own `counter` to `70`.

Then parent waits for child:

```c
waited = wait(&status);
```

and checks result:

```c
if (WIFEXITED(status)) {
    printf("... status %d\n", WEXITSTATUS(status));
} else if (WIFSIGNALED(status)) {
    printf("... signal %d\n", WTERMSIG(status));
}
```

---

## 4) Separate memory (copy + copy-on-write)

After `fork()`, child gets a copy of the parent's address space.
Modern systems use **copy-on-write**: memory pages are shared until one process writes, then that process gets its own private copy.

So with `counter`:
- Child updates its copy: `100 -> 150`
- Parent updates its copy: `100 -> 70`

These do **not** affect each other.

---

## 5) Why `wait()` matters

`wait()` lets parent collect child exit status and prevents a **zombie** process.

- **Zombie**: child finished, but parent has not collected status yet.
- **Orphan**: parent exits first; child is adopted by init/systemd.

Using `wait()` is the normal way to synchronize parent with child completion.

---

## 6) Build and run

From the `1st task` folder:

```bash
gcc -Wall -o fork_demo fork_demo.c
./fork_demo
```

Sample output (PIDs will differ, and the first Parent/Child lines after fork can appear in either order):

```text
[Before fork] PID=12345, counter=100
[Parent] PID=12345, child PID=12346
[Parent] counter after -30 = 70
[Child ] PID=12346, PPID=12345
[Child ] counter after +50 = 150
[Parent] Child 12346 exited normally with status 42
[Parent] final counter = 70
```

---

## 7) Key takeaways

1. `fork()` creates a new child process.
2. Parent and child both continue after the same `fork()` call.
3. Return value of `fork()` tells which process you are in.
4. Parent/child memory changes are separate after fork.
5. `wait()` is important for synchronization and cleanup.

---

## 8) Common extensions

- Use `exec*()` in the child after `fork()` to run a different program.
- Fork in a loop: each fork doubles process count (`2^n` after `n` forks).
- Use pipes (`pipe()`) so parent and child can communicate.
