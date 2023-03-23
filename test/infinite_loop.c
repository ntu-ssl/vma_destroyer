#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    pid_t pid = getpid();
    printf("Hello! I m an infinite loop\nMy PID: %d\n", pid);
    while (1) {
        printf("Tick\n");
        sleep(1);
        printf("Tock\n");
        sleep(1);
    }

    return 0;
}