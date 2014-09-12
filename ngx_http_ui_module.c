
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
    ngx_http_variable_value_t *callback;
    int                        cb_jsonp_len;
} ngx_http_ui_ctx_t;

typedef struct {
  int magic;
  char query[12];
  long int slot_id;
  unsigned int ip;
	char need_merge;
	char need_pb;
} ui_params_t;


static ngx_int_t ngx_http_ui_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ui_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ui_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_ui_filter_init(void *data);
static ngx_int_t ngx_http_ui_filter(void *data, ssize_t bytes);
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

#define NGX_HTTP_UI_JSONP_BEGIN   (sizeof(ngx_http_ui_jsonp_begin) - 1)
static u_char  ngx_http_ui_jsonp_begin[] = "/**/ typeof === 'function' && (";

#define NGX_HTTP_UI_JSONP_END   (sizeof(ngx_http_ui_jsonp_end) - 1)
static u_char  ngx_http_ui_jsonp_end[] = ");";


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

    ngx_str_set(&r->headers_out.content_type, "application/javascript");
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

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_ui_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;
    ctx->callback = NULL;
    ctx->cb_jsonp_len = 0;

    ngx_http_set_ctx(r, ctx, ngx_http_ui_module);

    u->input_filter_init = ngx_http_ui_filter_init;
    u->input_filter = ngx_http_ui_filter;
    u->input_filter_ctx = ctx;

    r->main->count++;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static long int
get_slot_id(char *src, int len)
{
    char *p, *pend;
    pend = src + len;
    if (*(pend-1) == '/') {
      pend--;
    }

    p = pend - 1;
    if (*p < '0' || *p > '9') {
        return 0;
    }

    while(*p && *p >= '0' && *p <= '9' ) {
      p--;
    }
    p++;

    if (p == pend) {
        return 0;
    }
    return atol(p);
}

int get_valid_function_name_end(const u_char *str, int len) {
  if (len < 1) {
    return 0;
  }
  int i = 0;
  for (i=0; i<len && *str; i++) {
    if (isalnum(*str) || *str == '_' || *str == '.') {
      str++;
      continue;
    }
    return i;
  }
  return i;
}

static ngx_int_t
ngx_http_ui_create_request(ngx_http_request_t *r)
{
    int                             rv;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ui_params_t                    *ui_params;
    ngx_int_t                       key;
    ngx_str_t                       var;
    ngx_http_ui_ctx_t              *ctx;
    ngx_http_variable_value_t      *vv;
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
    ui_params->slot_id = get_slot_id((char*)r->uri.data, r->uri.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http ui request: slot \"%ld\"", ui_params->slot_id);

    ctx = ngx_http_get_module_ctx(r, ngx_http_ui_module);

    ngx_str_set(&var, "arg_q");
    key = ngx_hash_key(var.data, var.len);
    vv = ngx_http_get_variable(r, &var, key);

    if (vv && !vv->not_found && vv->len) {
      rv = sizeof(ui_params->query) - 1;
      if (rv > vv->len) {
        rv = vv->len;
      }
      memcpy(ui_params->query, vv->data, rv);
      ui_params->query[rv] = '\0';
    }

    if (ui_params->slot_id < 1 && !ui_params->query[0]) {
      return NGX_ERROR;
    }

    ngx_str_set(&var, "arg_callback");
    key = ngx_hash_key(var.data, var.len);
    vv = ngx_http_get_variable(r, &var, key);

    if (vv && !vv->not_found && vv->len) {
      rv = get_valid_function_name_end(vv->data, vv->len);
      if (rv > 0) {
        vv->len = rv;
      }
      ctx->callback = vv;
      ctx->cb_jsonp_len = NGX_HTTP_UI_JSONP_BEGIN + vv->len * 2 + NGX_HTTP_UI_JSONP_END;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ui_reinit_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "/////http ui reinit request");

    return NGX_OK;
}


static ngx_int_t
ngx_http_ui_process_header(ngx_http_request_t *r)
{
    ngx_str_t                       line;
    ngx_http_upstream_t            *u;
    ngx_http_ui_ctx_t              *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ui_module);
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

    /*if (u->headers_in.content_length_n < 3) {*/
      /*u->headers_in.status_n = NGX_HTTP_NO_CONTENT;*/
      /*u->state->status = NGX_HTTP_NO_CONTENT;*/
      /*u->keepalive = 1;*/

      /*return NGX_OK;*/
    /*}*/

    u->headers_in.content_length_n += ctx->cb_jsonp_len;
    u->headers_in.status_n = 200;
    u->state->status = 200;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ui_filter_init(void *data)
{
    ngx_http_ui_ctx_t  *ctx = data;

    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n;

    } else {
        u->length = 0;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "//////ui filter length:%z %d %d",
                   u->length, u->headers_in.content_length_n, ctx->cb_jsonp_len);
    return NGX_OK;
}


static ngx_int_t
ngx_http_ui_filter(void *data, ssize_t bytes)
{
    ngx_http_ui_ctx_t  *ctx = data;

    ngx_buf_t            *b;
    ngx_str_t             cb;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "//////ui filter length:%z %d %d bytes:%z",
                   u->length, u->headers_in.content_length_n,
                   ctx->cb_jsonp_len, bytes);
    if (u->length == 0) {
      u->keepalive = 1;
      return NGX_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;
    cl->buf->last_buf = 1;
    cl->next = NULL;

    *ll = cl;

    cl->buf->pos = b->last;
    b->last += bytes;

    if (ctx->callback) {
      b->last = ngx_copy(b->last, ngx_http_ui_jsonp_end, NGX_HTTP_UI_JSONP_END);
    }

    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (!ctx->callback) {
      u->length = 0;
      u->keepalive = 1;
      ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                     "ui filter bytes:%z size:%z",
                     bytes, b->last - b->pos);

      return NGX_OK;
    }

    cl = ngx_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;
    cl->buf->last_buf = 0;

    cl->buf->pos = b->last;
    ngx_str_set(&cb, "/**/ typeof ");
    b->last = ngx_copy(b->last, cb.data, cb.len);
    b->last = ngx_copy(b->last, ctx->callback->data, ctx->callback->len);
    ngx_str_set(&cb, " === 'function' && ");
    b->last = ngx_copy(b->last, cb.data, cb.len);
    b->last = ngx_copy(b->last, ctx->callback->data, ctx->callback->len);
    *b->last++ = '(';
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    cl->next = u->out_bufs;
    u->out_bufs = cl;

    u->length = 0;
    u->keepalive = 1;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "ui filter bytes:%z size:%z",
                   bytes, b->last - b->pos);

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
