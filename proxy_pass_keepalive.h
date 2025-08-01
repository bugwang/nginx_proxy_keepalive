
/*
 * Copyright (C) 
 * Copyright (C) wangjianying, Inc.
 */

/*
* proxy_pass support keepalive
* configure constant parameter:
* timeout = 60000;
* requests = 600;
* max_cached = 200;
* nginx 1.18 tested
* ssl_session_cache   shared:SSL:1024m;
* ssl_session_timeout 10m;
* useage:
*   copy this file to nginx/src/http/  
*   open file : src/http/ngx_http_upstream_round_robin.c
*   #include "proxy_pass_keepalive.h"
*   go to function : ngx_http_upstream_create_round_robin_peer 
*   add a line of code in function end :
*   ngx_http_upstream_init_round_robin_keepalive(r,1);  
*   ./configure --prefix=/usr/local/test_server/ --add-module=/root/dsp_issue/ngx_lua_module-10.14.2  --add-module=/root/dsp_issue/ngx_devel_kit-0.3.0 --with-http_ssl_module --with-http_stub_status_module --with-openssl=/root/openssl-1.0.2u/
*/

/** because don't use request memory pool so build custom string array */
typedef struct {
    size_t      len;
    u_char     *data;
} string_t;


typedef struct {
    string_t   key;
    void       *value;
} item_t;

typedef struct {
    int length;
    int capacity;
    item_t *elements;
}string_array_t;

#define STRING_COMPARE(cmp_a,an,cmp_b,bn)  (an == bn && strncmp((const char *)cmp_a, (const char *)cmp_b,an) == 0)


/*
*  copy nginx module keepalive
*/
typedef struct {
    ngx_uint_t                         max_cached;
    ngx_uint_t                         requests;
    ngx_msec_t                         timeout;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_pt          original_init_upstream;
    ngx_http_upstream_init_peer_pt     original_init_peer;

} robin_upstream_keepalive_srv_conf_t;


typedef struct {
    robin_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

} robin_upstream_keepalive_cache_t;


typedef struct {
    robin_upstream_keepalive_srv_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

} robin_upstream_keepalive_peer_data_t;

//static robin_upstream_keepalive_peer_data_t  *keepalive_data = NULL;
static string_array_t *keepalive_upstream_array = NULL;



static int 
carray_init(string_array_t *array, size_t size);
static string_array_t *
carray_create( size_t size);
static int 
carray_insert(string_array_t *array, u_char *key, size_t klen, void *value);
static void *
carray_find(string_array_t *array, u_char *key, size_t klen) ;

/**
 * is_keepalive : is_keepalive is custom to decide for start or stop
 */
ngx_int_t
ngx_http_upstream_init_round_robin_keepalive(ngx_http_request_t *r, size_t is_keepalive);
void *
ngx_http_upstream_create_round_robin_keepalive(ngx_http_request_t *r);
static ngx_int_t 
ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data);
static void
ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state);

static void 
ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void 
ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev);
static void 
ngx_http_upstream_keepalive_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t 
ngx_http_upstream_keepalive_set_session( ngx_peer_connection_t *pc, void *data);
static void 
ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc,void *data);
#endif

static ngx_int_t
ngx_http_upstream_get_keepalive_random(ngx_peer_connection_t *pc, void *data);
static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_get_keeplive_random_peer(ngx_http_upstream_rr_peer_data_t *rrp);


static string_array_t *
carray_create( size_t size)
{
    string_array_t *a;

    a = malloc(sizeof(string_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (carray_init(a, size) != 0) {
        return NULL;
    }

    return a;
}


static int 
carray_init(string_array_t *array, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->elements = 0;
    
    array->length = 0;
    //array->elts = ngx_palloc(pool, n * size);
    array->elements = malloc(sizeof(item_t) * size);
    if (array->elements == NULL) {
        return -1;
    }

    memset(array->elements,0,sizeof(item_t) * size);

    array->capacity = size;
    return 0;
}

static int 
carray_insert(string_array_t *array, u_char *key, size_t klen, void *value)
{
    if (array == NULL || array->elements == NULL) {
        return -1;
    }
    if(array->length == array->capacity)
    {     
        size_t size = 2 * array->length;
        item_t *new_item = malloc(sizeof(item_t) * size);
        if (new_item == NULL) {
            return -1;
        }

        memset(new_item,0,sizeof(item_t) * size);
        
        array->capacity = size;


        memcpy(new_item, array->elements, sizeof(item_t)* array->length);
        free(array->elements);
        array->elements = new_item;
    }

    string_t *s = &(array->elements[array->length].key);
    s->data = malloc(klen+1);
    if(s->data == NULL)
    {
        return -1;
    }
    memcpy(s->data, key, klen);
    s->len = klen;
    s->data[klen]='\0';

    array->elements[array->length].value = value;

    array->length++;
    return 0;
}

static void *
carray_find(string_array_t *array, u_char *key, size_t klen) 
{
    if (array == NULL || array->elements == NULL) {
        return NULL;
    }
    int i = 0;
    string_t *s = NULL;

    for(i=0; i < array->length; i++)
    {
        s = &(array->elements[i].key);
        if(s == NULL)
        {
            return NULL;
        }
        if ( STRING_COMPARE(s->data,s->len,key,klen) )
        {
            return array->elements[i].value;
        }
    }

    return NULL;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_get_keeplive_random_peer(ngx_http_upstream_rr_peer_data_t *rrp)
{
    ngx_uint_t                    i=0;
    ngx_http_upstream_rr_peer_t  *peer, *best;
    if(rrp == NULL)
        return NULL;
    ngx_uint_t x = ngx_random()/rrp->peers->number;

    best = NULL;


    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
        best = peer;
        if (i >= x) {
            break;
        }
    }

    if (best == NULL) {
        return NULL;
    }

    rrp->current = best;

    return best;
}


static ngx_int_t
ngx_http_upstream_get_keepalive_random(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_rr_peer_data_t  *rrp = data;
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;


    pc->cached = 0;
    pc->connection = NULL;

    peers = rrp->peers;
    if(peers == NULL)
    {
        goto failed;
    }

    if (peers->single) {
        peer = peers->peer;
        rrp->current = peer;
        
    } else {
        //peer = rp->conf->ranges[i].peer;
        peer = ngx_http_upstream_get_keeplive_random_peer(rrp);
    }

    if (peer == NULL) {
        ngx_log_error(NGX_LOG_ERR, pc->log, 0,
                        "ngx_http_upstream_get_keepalive_random ngx_http_upstream_get_peer failed");
        goto failed;
    }

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;



    return NGX_OK;

failed:
    if(peers)
        pc->name = peers->name;

    return NGX_ERROR;//NGX_DONE;
}


static ngx_int_t
ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    robin_upstream_keepalive_peer_data_t  *kp = data;
    robin_upstream_keepalive_cache_t      *item;

    ngx_int_t          rc;
    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    /* ask balancer */
    //ngx_http_upstream_get_round_robin_peer
    //rc = kp->original_get_peer(pc, kp->data);
    rc = ngx_http_upstream_get_keepalive_random(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }
    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
         
        item = ngx_queue_data(q, robin_upstream_keepalive_cache_t, queue);
        
        
        c = item->connection;


        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {

            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->conf->free, q);

            goto found;
        }
    }

    return NGX_OK;

found:

    c->idle = 0;
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 0;

    return NGX_DONE;
}

static void
ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data, ngx_uint_t state)
{

    robin_upstream_keepalive_peer_data_t  *kp = data;
    robin_upstream_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;
    //ngx_http_upstream_t  *u;



    /* cache valid connections */

    //u = kp->upstream;
    c = pc->connection;

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        pc->tries = 0;
        goto invalid;
    }

    if (c->requests >= kp->conf->requests) {
        goto invalid;
    }

    //if (!u->keepalive) {
    //    goto invalid;
    //}

    //if (!u->request_body_sent) {
    //    goto invalid;
    //}

    if (ngx_terminate || ngx_exiting) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        pc->tries = 0;
        goto invalid;
    }

    if (ngx_queue_empty(&kp->conf->free)) {

        q = ngx_queue_last(&kp->conf->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, robin_upstream_keepalive_cache_t, queue);

        ngx_http_upstream_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, robin_upstream_keepalive_cache_t, queue);
    }

    ngx_queue_insert_head(&kp->conf->cache, q);
    //ngx_log_error(NGX_LOG_ERR, pc->log, 0,
    //               "free keepalive peer: saving connection %p ", c);
    item->connection = c;

    pc->connection = NULL;

    c->read->delayed = 0;
    ngx_add_timer(c->read, kp->conf->timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
    c->read->handler = ngx_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        ngx_http_upstream_keepalive_close_handler(c->read);
    }

invalid:

    //ngx_log_error(NGX_LOG_ERR, pc->log, 0,
    //               "ngx_http_upstream_free_keepalive_peer: ngx_http_upstream_free_round_robin_peer start");
    
    if (state & NGX_PEER_FAILED || c->read->timedout )
    {
        pc->tries = 0;
    }
    else
    {
        //kp->original_free_peer(pc, kp->data, state);//notice
    }
    //ngx_log_error(NGX_LOG_ERR, pc->log, 0,
    //               "ngx_http_upstream_free_keepalive_peer: ngx_http_upstream_free_round_robin_peer end ");
}


static void
ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    robin_upstream_keepalive_srv_conf_t  *conf;
    robin_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    ngx_http_upstream_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
}


static void
ngx_http_upstream_keepalive_close(ngx_connection_t *c)
{
    
#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}

void *
ngx_http_upstream_create_round_robin_keepalive(ngx_http_request_t *r)
{
    ngx_uint_t                         i;
    ngx_http_upstream_rr_peer_data_t  *rrp;
    robin_upstream_keepalive_peer_data_t  *kp = NULL;
    robin_upstream_keepalive_srv_conf_t  *kcf = NULL;
    robin_upstream_keepalive_cache_t     *cached;

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    //                      "ngx_http_upstream_create_round_robin_keepalive");
    rrp = r->upstream->peer.data;
    
    if (rrp == NULL || rrp->peers == NULL) {
        return NULL;
    }


    if (keepalive_upstream_array == NULL)
    {
        keepalive_upstream_array = carray_create(20);  
    }
    
    kp = carray_find(keepalive_upstream_array,rrp->peers->name->data,rrp->peers->name->len);
    if(kp == NULL)
    {
        kp = malloc(sizeof(robin_upstream_keepalive_peer_data_t));
        if (kp == NULL) {
            return NULL;
        }
        kcf = malloc(sizeof(robin_upstream_keepalive_srv_conf_t));
        if (kcf == NULL) {
            return NULL;
        }

        kcf->max_cached = 100;

        cached = malloc(
                    sizeof(robin_upstream_keepalive_cache_t) * kcf->max_cached);
        if (cached == NULL) {
            return NULL;
        }

        kp->conf = kcf;
        
        kcf->timeout = 60000;
        kcf->requests = 600;
        ngx_queue_init(&kcf->cache);
        ngx_queue_init(&kcf->free);

        for (i = 0; i < kcf->max_cached; i++) {
            ngx_queue_insert_head(&kcf->free, &cached[i].queue);
            cached[i].conf = kcf;
        }

        carray_insert(keepalive_upstream_array,rrp->peers->name->data,rrp->peers->name->len,kp);
        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        //                  "keepalive add %V",rrp->peers->name);
    }
    

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    //                      "ngx_http_upstream_create_round_robin_keepalive done");
    return kp;
}

ngx_int_t
ngx_http_upstream_init_round_robin_keepalive(ngx_http_request_t *r, size_t is_keepalive)
{
    
    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    //                      "ngx_http_upstream_init_round_robin_keepalive ");
    
    robin_upstream_keepalive_peer_data_t  *kp;
    robin_upstream_keepalive_srv_conf_t  *kcf;
    //ngx_http_upstream_rr_peer_data_t  *rrp;
    //ngx_http_upstream_rr_peers_t      *peers;

    if (r->upstream->upstream ){
        return NGX_OK;            
    }

    if(is_keepalive == 0)
    {
        return NGX_OK;
    }

    if (r->upstream->headers_in.connection_close ){
        return NGX_OK;
    }

    kp  =  ngx_http_upstream_create_round_robin_keepalive(r);
    if (kp == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ngx_http_upstream_init_round_robin_keepalive keepalive_data null");
        return NGX_ERROR;
    }

    kcf = kp->conf;
    if (kcf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ngx_http_upstream_init_round_robin_keepalive keepalive_data conf null");
        return NGX_ERROR;
    }
    

    //us is null  ngx_http_upstream_init_round_robin_peer
    //if (us && kcf->original_init_peer(r, us) != NGX_OK) {
    //    return NGX_ERROR;
    //}
    
    //rrp = r->upstream->peer.data;
    //rrp->peers->shpool = NULL;


    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;
    
    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = ngx_http_upstream_free_keepalive_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_keepalive_save_session;
#endif

    //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
    //                      "ngx_http_upstream_init_round_robin_keepalive done");
    return NGX_OK;
}

#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    robin_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    robin_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif



