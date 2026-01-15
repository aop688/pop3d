/* Linux compatibility header for pop3d */
#ifndef _LINUX_COMPAT_H_
#define _LINUX_COMPAT_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/* Define missing constants */
#ifndef MAXBSIZE
#define MAXBSIZE 8192
#endif

/* Define SHA1 digest string length for OpenSSL */
#define SHA1_DIGEST_STRING_LENGTH 41

/* Define strtonum replacement */
static inline long long
strtonum(const char *numstr, long long minval, long long maxval, const char **errstrp)
{
    long long ll = 0;
    char *ep;
    int error = 0;
    
    if (numstr == NULL) {
        error = 1;
        goto done;
    }
    
    ll = strtoll(numstr, &ep, 10);
    if (numstr == ep || *ep != '\0')
        error = 1;
    else if ((ll == LLONG_MAX && errno == ERANGE) || ll < minval || ll > maxval)
        error = 1;
    
done:
    if (errstrp != NULL)
        *errstrp = error ? "invalid" : NULL;
    
    return error ? 0 : ll;
}

/* Define fgetln replacement */
static inline char *
fgetln(FILE *fp, size_t *lenp)
{
    static char *buf = NULL;
    static size_t bufsize = 0;
    size_t len = 0;
    int ch;
    
    if (buf == NULL) {
        bufsize = 256;
        buf = (char *)malloc(bufsize);
        if (buf == NULL)
            return NULL;
    }
    
    while ((ch = fgetc(fp)) != EOF && ch != '\n') {
        if (len >= bufsize - 1) {
            bufsize *= 2;
            buf = (char *)realloc(buf, bufsize);
            if (buf == NULL)
                return NULL;
        }
        buf[len++] = ch;
    }
    
    if (len == 0 && ch == EOF) {
        return NULL;
    }
    
    buf[len] = '\0';
    *lenp = len;
    return buf;
}

/* Define SHA1 wrapper functions for OpenSSL 3.0 */
#define SHA1_CTX SHA_CTX
static inline void SHA1Init(SHA_CTX *c) { SHA1_Init(c); }
static inline void SHA1Update(SHA_CTX *c, const void *data, size_t len) { SHA1_Update(c, data, len); }
static inline char *SHA1End(SHA_CTX *c, char *buf) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Final(digest, c);
    if (buf == NULL) {
        buf = (char *)malloc(SHA1_DIGEST_STRING_LENGTH);
        if (buf == NULL) return NULL;
    }
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(buf + (i * 2), "%02x", digest[i]);
    }
    buf[SHA_DIGEST_LENGTH * 2] = '\0';
    return buf;
}

/* Define setproctitle as no-op */
#define setproctitle(x) do {} while(0)

#endif /* _LINUX_COMPAT_H_ */