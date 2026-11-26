#include <string.h>

int mgate_static_add(int a, int b) {
    return a + b + (int)strlen("mgate-static");
}

const char *mgate_static_banner(void) {
    return "multi-target-hardening-gate";
}

int mgate_static_copy(char *destination, const char *source) {
    char slot[48];
    /* Runtime-sized copy into a stack array forces a stack canary when
       built with -fstack-protector-strong. */
    strcpy(slot, source ? source : "");
    if (destination != 0) {
        strcpy(destination, slot);
    }
    return (int)strlen(slot);
}
