
/*
 * Copyright (C) Dejian Xu
 * Copyright (C) www.xdf.cn, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_conf_t   upstream;
} ngx_http_ui_loc_conf_t;


typedef struct {
    ngx_http_request_t        *request;
    ngx_str_t                  key;
} ngx_http_ui_ctx_t;

typedef struct {
  int magic;
  char slot_id[12];
} ui_params_t;


static ngx_int_t ngx_http_ui_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ui_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ui_process_header(ngx_http_request_t *r);
static void ngx_http_ui_abort_request(ngx_http_request_t *r);
static void ngx_http_ui_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static void *ngx_http_ui_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_ui_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_ui_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_bitmask_t  ngx_http_ui_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("not_found"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_ui_commands[] = {

    { ngx_string("ui_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_ui_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ui_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ui_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("ui_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ui_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("ui_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ui_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("ui_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ui_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("ui_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ui_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("ui_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ui_loc_conf_t, upstream.next_upstream),
      &ngx_http_ui_next_upstream_masks },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ui_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_ui_create_loc_conf,           /* create location configuration */
    ngx_http_ui_merge_loc_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_ui_module = {
    NGX_MODULE_V1,
    &ngx_http_ui_module_ctx,               /* module context */
    ngx_http_ui_commands,                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_ui_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc;
    ngx_http_upstream_t            *u;
    ngx_http_ui_ctx_t              *ctx;
    ngx_http_ui_loc_conf_t         *mlcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    ngx_str_set(&u->schema, "ui://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_ui_module;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_ui_module);

    u->conf = &mlcf->upstream;

    u->create_request = ngx_http_ui_create_request;
    u->reinit_request = ngx_http_ui_reinit_request;
    u->process_header = ngx_http_ui_process_header;
    u->abort_request = ngx_http_ui_abort_request;
    u->finalize_request = ngx_http_ui_finalize_request;
    r->state = 0;

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_ui_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    ngx_http_set_ctx(r, ctx, ngx_http_ui_module);

    r->main->count++;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static int
get_slot_id(char *dst, int dlen, char *src, int len)
{
    char *p, *pend;
    dlen--;
    pend = src + len;
    if (*(pend-1) == '/') {
      pend--;
    }

    p = pend - 1;
    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }

    while(*p && *p >= '0' && *p <= '9' ) {
      p--;
    }
    p++;

    if (p == pend) {
        return NGX_ERROR;
    }
    len = pend - p;
    if (len > dlen) {
      len = dlen;
    }
    strncpy(dst, p, len);
    dst[len] = '\0';
    return NGX_OK;
}

static ngx_int_t
ngx_http_ui_create_request(ngx_http_request_t *r)
{
    int                             rv;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ui_params_t                    *ui_params;
    /*ngx_http_ui_ctx_t              *ctx;*/
    /*ngx_http_variable_value_t      *vv;*/
    /*ngx_http_ui_loc_conf_t         *mlcf;*/

    /*mlcf = ngx_http_get_module_loc_conf(r, ngx_http_ui_module);*/

    b = ngx_create_temp_buf(r->pool, sizeof(ui_params_t));
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    b->last = b->pos + sizeof(ui_params_t);
    ui_params = (ui_params_t *) b->pos;
    ui_params->magic = sizeof(ui_params_t);
    rv = get_slot_id(ui_params->slot_id, sizeof(ui_params->slot_id),
        (char*)r->uri.data, r->uri.len);
    if (rv == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "get \"slot_id\" fail");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ui request: slot \"%s\"", ui_params->slot_id);

    return NGX_OK;
}


static ngx_int_t
ngx_http_ui_reinit_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ui reinit request");

    return NGX_OK;
}


static ngx_int_t
ngx_http_ui_process_header(ngx_http_request_t *r)
{
    ngx_str_t                       line;
    ngx_http_upstream_t            *u;

    u = r->upstream;

    line.data = u->buffer.pos;
    line.len = u->buffer.last - u->buffer.pos;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ui: \"%V\" %d", &line, line.len);

    u->headers_in.content_length_n = line.len;
    if (u->headers_in.content_length_n == -1) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
          "ui sent invalid length in response \"%V\" ",
          &line);
      return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    if (u->headers_in.content_length_n < 2) {
      u->headers_in.status_n = 204;
      u->state->status = 204;
      u->keepalive = 1;

      return NGX_OK;
    }

    u->headers_in.status_n = 200;
    u->state->status = 200;
    u->keepalive = 1;

    return NGX_OK;
}


static void
ngx_http_ui_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http ui request");
    return;
}


static void
ngx_http_ui_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http ui request");
    return;
}


static void *
ngx_http_ui_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_ui_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ui_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

    conf->upstream.local = NGX_CONF_UNSET_PTR;
    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    return conf;
}


static char *
ngx_http_ui_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ui_loc_conf_t *prev = parent;
    ngx_http_ui_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ui_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ui_loc_conf_t *mlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_ui_handler;

    if (clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return NGX_CONF_OK;
}
