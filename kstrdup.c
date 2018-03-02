#include <stdlib.h>
#include <string.h>
#include "kstrdup.h"

char *kstrdup(const char *s) {
    size_t size = strlen(s) + 1;
    char *p = malloc(size);
    if (p != NULL) {
        memcpy(p, s, size);
    }
    return p;
}

char *kstrndup(const char *s, size_t n) {
    char *p = memchr(s, '\0', n);
    if (p != NULL)
        n = p - s;
    p = malloc(n + 1);
    if (p != NULL) {
        memcpy(p, s, n);
        p[n] = '\0';
    }
    return p;
}
