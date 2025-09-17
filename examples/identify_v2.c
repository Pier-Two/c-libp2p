#include "protocol/identify/identify_v2.h"
#include "protocol/connection_handler.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned char a2b[256]; size_t a2b_len; size_t a2b_pos;
                 unsigned char b2a[256]; size_t b2a_len; size_t b2a_pos; } pair_buf_t;
typedef struct { pair_buf_t *pair; int is_a; } stream_ctx_t;

static ssize_t sread(libp2p_stream_v2_t *s, void *buf, size_t len)
{ stream_ctx_t *ctx=s->impl; pair_buf_t *p=ctx->pair; unsigned char *src=ctx->is_a?p->b2a:p->a2b;
  size_t *pos=ctx->is_a?&p->b2a_pos:&p->a2b_pos; size_t *lenp=ctx->is_a?&p->b2a_len:&p->a2b_len;
  size_t avail=*lenp-*pos; size_t c=len<avail?len:avail; memcpy(buf,src+*pos,c); *pos+=c; return (ssize_t)c; }
static ssize_t swrite(libp2p_stream_v2_t *s, const void *buf, size_t len)
{ stream_ctx_t *ctx=s->impl; pair_buf_t *p=ctx->pair; unsigned char *dst=ctx->is_a?p->a2b:p->b2a;
  size_t *lenp=ctx->is_a?&p->a2b_len:&p->b2a_len; if(*lenp+len>256) return -1; memcpy(dst+*lenp,buf,len); *lenp+=len; return (ssize_t)len; }
static int sclose(libp2p_stream_v2_t *s){ free(s->impl); return 0; }
static const peer_id_t* sremote(libp2p_stream_v2_t*s){(void)s;return NULL;}
static const char* sproto(libp2p_stream_v2_t*s){(void)s;return LIBP2P_IDENTIFY_V2_PROTOCOL_ID;}
static int sinit(libp2p_stream_v2_t*s){(void)s;return 1;}
static libp2p_stream_v2_vtable_t vt={sread,swrite,sclose,sremote,sproto,sinit};

static void make_pair(libp2p_stream_v2_t **a, libp2p_stream_v2_t **b)
{ pair_buf_t *p=calloc(1,sizeof(*p)); stream_ctx_t *ca=calloc(1,sizeof(*ca)); stream_ctx_t *cb=calloc(1,sizeof(*cb));
  ca->pair=p; ca->is_a=1; cb->pair=p; cb->is_a=0; *a=libp2p_stream_v2_create(&vt,ca); *b=libp2p_stream_v2_create(&vt,cb); }

static void *server_thread(void *arg)
{
    libp2p_stream_v2_t *s=arg;
    libp2p_identify_t id={0};
    id.protocol_version=strdup("/test/1.0");
    id.agent_version=strdup("libp2p/0.1");
    libp2p_connection_handler_t *h=libp2p_identify_handler_new(NULL,&id);
    libp2p_connection_handler_on_stream(h,s);
    libp2p_connection_handler_on_close(h);
    libp2p_connection_handler_free(h);
    return NULL;
}

int main(void)
{
    libp2p_stream_v2_t *client,*server; make_pair(&client,&server);
    pthread_t th; pthread_create(&th,NULL,server_thread,server);
    libp2p_identify_t *resp=NULL;
    int rc=libp2p_identify_v2_send_request(client,&resp);
    libp2p_stream_v2_free(client);
    pthread_join(th,NULL);
    if(rc==0 && resp){
        printf("Identify protocol version: %s\n", resp->protocol_version);
        libp2p_identify_free(resp);
        return 0;
    }
    printf("Identify request failed\n");
    if(resp) libp2p_identify_free(resp);
    return 1;
}
