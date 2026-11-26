#include <stdio.h>
#include <string.h>

/* Unique anchor so symbol-evidence checks have a stable named symbol. */
int mgate_exec_anchor(int value) {
    char buffer[64];
    /* Address-taken stack buffer forces a stack canary under
       -fstack-protector-strong. */
    snprintf(buffer, sizeof(buffer), "mgate:%d", value);
    return (int)strlen(buffer);
}

int main(int argc, char **argv) {
    const char *program = (argc > 0 && argv[0] != 0) ? argv[0] : "mgate";
    printf("%s:%d\n", program, mgate_exec_anchor(argc));
    return 0;
}
