#include <stdio.h>
#include <string.h>

#define MGATE_LIB_VERSION "1.0.0"

const char *mgate_lib_version(void) {
    return MGATE_LIB_VERSION;
}

int mgate_lib_anchor(const char *input) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "lib:%s", input ? input : "null");
    return (int)strlen(buffer);
}
