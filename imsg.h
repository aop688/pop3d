/* Simplified imsg.h for Linux compatibility */
#ifndef __IMSG_H__
#define __IMSG_H__

#include <stdint.h>
#include <sys/types.h>

#define IMSG_HEADER_SIZE sizeof(struct imsg_hdr)

struct imsg_hdr {
    uint32_t type;
    uint32_t len;
    uint32_t peerid;
    uint32_t pid;
};

struct imsg {
    struct imsg_hdr hdr;
    int fd;
    void *data;
};

struct imsgbuf {
    int fd;
    struct imsg current;
    void *rbuf;
    size_t rbufsz;
    void *wbuf;
    size_t wbufsz;
    char *buf;
};

/* Basic imsg functions */
int imsg_compose(struct imsgbuf *, uint32_t, uint32_t, pid_t, int, 
    const void *, uint16_t);
int imsg_read(struct imsgbuf *);
int imsg_get(struct imsgbuf *, struct imsg *);
int imsg_forward(struct imsgbuf *, struct imsg *);
int imsg_flush(struct imsgbuf *);
void imsg_clear(struct imsgbuf *);
int imsg_add(struct imsgbuf *, const void *, uint16_t);

#endif /* __IMSG_H__ */