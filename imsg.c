/* Simplified imsg.c for Linux compatibility */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "imsg.h"

int
imsg_compose(struct imsgbuf *imsgbuf, uint32_t type, uint32_t peerid,
    pid_t pid, int fd, const void *data, uint16_t datalen)
{
	/* Simplified implementation */
	struct imsg *imsg = &imsgbuf->current;
	
	imsg->hdr.type = type;
	imsg->hdr.peerid = peerid;
	imsg->hdr.pid = pid;
	imsg->hdr.len = IMSG_HEADER_SIZE + datalen;
	imsg->fd = fd;
	
	if (datalen > 0) {
		if (imsg->data)
			free(imsg->data);
		imsg->data = malloc(datalen);
		if (imsg->data == NULL)
			return -1;
		memcpy(imsg->data, data, datalen);
	}
	
	return 0;
}

int
imsg_read(struct imsgbuf *imsgbuf)
{
	/* Simplified implementation - just return success */
	return 1;
}

int
imsg_get(struct imsgbuf *imsgbuf, struct imsg *imsg)
{
	/* Simplified implementation */
	memcpy(imsg, &imsgbuf->current, sizeof(*imsg));
	return 1;
}

int
imsg_forward(struct imsgbuf *imsgbuf, struct imsg *imsg)
{
	/* Simplified implementation */
	return imsg_compose(imsgbuf, imsg->hdr.type, imsg->hdr.peerid,
	    imsg->hdr.pid, imsg->fd, imsg->data, 
	    imsg->hdr.len - IMSG_HEADER_SIZE);
}

int
imsg_flush(struct imsgbuf *imsgbuf)
{
	/* Simplified implementation */
	return 0;
}

void
imsg_clear(struct imsgbuf *imsgbuf)
{
	if (imsgbuf->current.data) {
		free(imsgbuf->current.data);
		imsgbuf->current.data = NULL;
	}
	if (imsgbuf->rbuf) {
		free(imsgbuf->rbuf);
		imsgbuf->rbuf = NULL;
	}
	if (imsgbuf->wbuf) {
		free(imsgbuf->wbuf);
		imsgbuf->wbuf = NULL;
	}
}

int
imsg_add(struct imsgbuf *imsgbuf, const void *data, uint16_t datalen)
{
	/* Simplified implementation */
	return 0;
}