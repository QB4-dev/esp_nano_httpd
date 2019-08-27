/*Copyright (c) 2018 qb4.dev@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.*/

#include "esp_nano_httpd.h"

#include <ip_addr.h>
#include <espconn.h>
#include <osapi.h>
#include <mem.h>

//#define NHTTPD_DEBUG
//#define NHTTPD_DEBUG_REQ

#ifdef  NHTTPD_DEBUG
#define NANO_HTTPD_DBG(fmt, args...)    os_printf(fmt, ## args)
#else
#define NANO_HTTPD_DBG(fmt, args...)    /* Don't do anything in release builds */
#endif

#ifdef  NHTTPD_DEBUG_REQ
#define NANO_HTTPD_DBG_REQ(fmt, args...)    os_printf(fmt, ## args)
#else
#define NANO_HTTPD_DBG_REQ(fmt, args...)    /* Don't do anything in release builds */
#endif

#define HTTP_RESP_CHUNK_LEN 2048 //set chunk size(no more than 2920)

static const http_callback_t *url_config;

static struct {
	char *buff;
	uint32_t bytes;
	uint32_t size;
} json_cache;

/* Taken from sprite_tm code:
"Copies len bytes over from dst to src, but does it using *only*
aligned 32-bit reads. Yes, it's no too optimized but it's short and sweet and it works" */
void ICACHE_FLASH_ATTR memcpy_aligned(char *dst, const char *src, int len) {
	uint32_t i;
	uint32_t w, b;
	for (i=0; i<len; i++) {
		b=((uint32_t)src&3);
		w=*((uint32_t *)(src-b));
		if(b==0) *dst=(w>>0);
		if(b==1) *dst=(w>>8);
		if(b==2) *dst=(w>>16);
		if(b==3) *dst=(w>>24);
		dst++; src++;
	}
}

static void ICACHE_FLASH_ATTR http_resp_free_after_tx(struct espconn *conn, char *arg){
	http_request_t * req = (http_request_t*)conn->reverse;
	if( req == NULL ) return;

	req->resp_alloc = arg;
}

static void ICACHE_FLASH_ATTR http_resp_chunk_tx(void *arg)
{
	char http_resp_buff[HTTP_RESP_CHUNK_LEN];
	struct espconn *conn;
	http_request_t *req;
	uint32 len;

	conn = (struct espconn *)arg;
	if(conn == NULL) return;

	req = (http_request_t*)conn->reverse;
	if( req == NULL ) return;

	if( req->resp_bytes_left > HTTP_RESP_CHUNK_LEN)
		len = HTTP_RESP_CHUNK_LEN;
	else
		len = req->resp_bytes_left;

	memcpy_aligned(http_resp_buff, req->resp_content, len);
	if( espconn_send(conn, (char*)http_resp_buff, len) == 0 ){
		req->resp_content += len;
		req->resp_bytes_left -= len;
	}
	//all data has been sent, free allocated memory
	if( len == 0 && req->resp_alloc != NULL){
		os_free(req->resp_alloc);
		req->resp_alloc = NULL;
	}
}


void ICACHE_FLASH_ATTR send_http_response(struct espconn *conn, const char *code, const char *cont_type, const char *content, uint32_t cont_len)
{
	http_request_t *req;
	uint32_t header_len;
	uint32_t bytes_free;
	uint32_t cont_bytes;
	char http_resp_buff[HTTP_RESP_CHUNK_LEN];
	const char http_header[] = "HTTP/1.1 %s\r\n"
				"Accept-Ranges: bytes\r\n"
				"Content-Type: %s; charset=UTF-8\r\n"
				"Content-Length: %i\r\n"
				"Connection: close\r\n\r\n";

	req = (http_request_t*)conn->reverse;
	if( req == NULL ) return;

	ets_snprintf(http_resp_buff, HTTP_RESP_CHUNK_LEN, http_header, code, cont_type, cont_len);
	header_len = strlen(http_resp_buff);

	bytes_free = HTTP_RESP_CHUNK_LEN-header_len;
	cont_bytes = (cont_len > bytes_free)?(bytes_free):cont_len;

    memcpy_aligned(http_resp_buff+header_len, content, cont_bytes);

	req->resp_bytes_left = (content != NULL)? (cont_len-cont_bytes) : 0;
	req->resp_content = content+cont_bytes;
	espconn_send(conn, http_resp_buff, header_len+cont_bytes); //start content tx chunk by chunk
}

void ICACHE_FLASH_ATTR resp_http_ok(struct espconn *conn){
	send_http_response(conn, "200 OK","text/html",NULL,0);
}

void ICACHE_FLASH_ATTR resp_http_404(struct espconn *conn){
	const char content[] = "Error 404 Not Found";
	send_http_response(conn, "404 Not Found","text/html",content,strlen(content));
}

void ICACHE_FLASH_ATTR resp_http_error(struct espconn *conn){
	const char content[] = "500 Internal Error";
	send_http_response(conn, "500 Internal Error", "text/html",content,strlen(content));
}

void ICACHE_FLASH_ATTR send_html(struct espconn *conn, void *html, uint32_t len){
	send_http_response(conn, "200 OK","text/html", html, len);
}

void ICACHE_FLASH_ATTR send_text(struct espconn *conn, void *txt, uint32_t len){
	send_http_response(conn, "200 OK","text/plain", txt, len);
}

void ICACHE_FLASH_ATTR send_css(struct espconn *conn, void *css, uint32_t len){
	send_http_response(conn, "200 OK","text/css", css, len);
}

void ICACHE_FLASH_ATTR send_svg(struct espconn *conn, void *svg, uint32_t len){
	send_http_response(conn, "200 OK","image/svg+xml", svg, len);
}

static int ICACHE_FLASH_ATTR json_putchar(int c)
{
    if(json_cache.buff != NULL && json_cache.bytes < json_cache.size) {
    	json_cache.buff[json_cache.bytes++] = c;
        return c;
    }
    return 0;
}

void ICACHE_FLASH_ATTR send_json_tree(struct espconn *conn, struct jsontree_object *js_tree, uint32_t cache_size)
{
	struct jsontree_context js_ctx;

	json_cache.buff = (char *)os_zalloc(cache_size);
	if(json_cache.buff == NULL)
		return resp_http_error(conn);

	json_cache.size=cache_size;
	json_cache.bytes=0;

	jsontree_setup(&js_ctx, (struct jsontree_value *)js_tree, json_putchar);
	while( jsontree_print_next(&js_ctx)){};

	http_resp_free_after_tx(conn, json_cache.buff);
	send_http_response(conn, "200 OK","application/json", json_cache.buff, json_cache.bytes);
}

static int ICACHE_FLASH_ATTR parse_request_header(http_request_t *req, char *data, uint32_t len)
{
	char *type, *path, *query, *http_ver;
	char *head_attr, *content_type, *content_len, *req_content;

	if( data == NULL )
		goto unknown_request;

	//find header attributes
	head_attr = strstr(data,"\r\n");
	if(head_attr != NULL){
		os_memset(head_attr,0,2);
		head_attr=head_attr+2;
	} else {
		goto unknown_request;
	}
	//find tokens
	type = strtok(data," ");
	path = strtok(NULL," ");
	http_ver = strtok(NULL," ");

	//get request type
	if( strcmp(type,"GET") == 0 )
		req->type = TYPE_GET;
	else if( strcmp(type,"POST") == 0 )
		req->type = TYPE_POST;
	else
		goto unknown_request;

	//check HTTP version
	if( strcmp(http_ver,"HTTP/1.1") != 0 )
		goto unknown_request;

	//set path and find query string
	if( path != NULL ){
		req->path = path;

		query = os_strchr(path,'?');
		if( query != NULL ){
			req->query = query+1;
			*query = 0;
		}
	} else {
		goto unknown_request;
	}

	//get request content information
	content_type = strstr(head_attr,"Content-Type:");
	content_len  = strstr(head_attr,"Content-Length:");
	req_content  = strstr(head_attr,"\r\n\r\n");
	if(req_content != NULL){
		memset(req_content,0,4);//mask  CR LF CR LF
		req_content+=4; 		//skip  CR LF CR LF
	}
	if(content_type != NULL){
		content_type = strtok(content_type,"\r\n");
		req->content_type = strchr(content_type,':')+1;
	}
	if(content_len != NULL){
		content_len = strtok(content_len,"\r\n");
		req->content_len = atoi(strchr(content_len,':')+1);
		req->cont_chunk_len = len - (req_content-data);
		req->cont_bytes_left = req->content_len - req->cont_chunk_len;
	}
	//set content pointer
	if(req_content == data+len)
		req->content=0; //no data expected
	else
		req->content=req_content;

	req->read_state = REQ_GOT_HEADER;
	return 0;

unknown_request:
	req->type = TYPE_UNKNOWN;
	return -1;
}

static void ICACHE_FLASH_ATTR receive_cb(void *arg, char *pdata, unsigned short len)
{
	struct espconn *conn = (struct espconn *)arg;
	const http_callback_t *recall_cb;
	const http_callback_t *url;
	http_request_t *req;

	NANO_HTTPD_DBG("got new request. req len %d Free heap size: %d\n", len, system_get_free_heap_size());
	NANO_HTTPD_DBG_REQ("request:\n%s\n", pdata);

	if(conn == NULL || pdata == NULL)
		return;

	req = (http_request_t*)conn->reverse;
	if( req == NULL ) return;

	if( req->read_state == REQ_GOT_HEADER ){
		if( parse_request_header(req,pdata,len) != 0 )
			return resp_http_error(conn);

		//try to find requested url in given url config
		for(url = url_config; url->path != NULL; url++){
			if( strcmp(req->path,url->path) == 0 ){
				NANO_HTTPD_DBG("url: %s found\n", req->path);

				if(url->handler != NULL)
					url->handler(conn, url->arg, url->arg_len);

				if(req->cont_bytes_left > 0){
					//not all content data received
					req->read_state = REQ_CONTENT_CHUNK;
					req->callback = url; //recall this url on next reqest part
				}
				return;//request handled
			}
		}
		return resp_http_404(conn); //url not found
	}

	//not all bytes received before, recall last callback
	if(req->read_state == REQ_CONTENT_CHUNK && req->cont_bytes_left > 0){
		req->content = pdata;
		req->cont_chunk_len = len;
		req->cont_bytes_left = req->cont_bytes_left - len;

		recall_cb = (http_callback_t*)req->callback;
		if(recall_cb != NULL)
			recall_cb->handler(conn, recall_cb->arg, recall_cb->arg_len);
		return;
	}
}


static void ICACHE_FLASH_ATTR disconnect_cb(void *arg){
    struct espconn *conn = (struct espconn *)arg;

    if( conn->reverse != NULL ){
    	os_free(conn->reverse);
    	conn->reverse = NULL;
    }
    NANO_HTTPD_DBG("disconnected. Free heap size: %d\n", system_get_free_heap_size());
}

static void ICACHE_FLASH_ATTR connection_listener(void *arg)
{
    struct espconn *conn = (struct espconn *)arg;

    espconn_set_opt(conn, ESPCONN_START|ESPCONN_KEEPALIVE);

    http_request_t *req = (http_request_t*) os_zalloc(sizeof(http_request_t));
    conn->reverse = req;

    espconn_regist_recvcb(conn, receive_cb );
    espconn_regist_sentcb(conn, http_resp_chunk_tx);
    espconn_regist_disconcb(conn, disconnect_cb);
}

/* Define content_info as in example below:

const http_callback_t url_cfg[] = {
	{"/", send_html, index_html, sizeof(index_html)},
	{"/led",  led_demo_callback, NULL, 0},
	{"/wifi", wifi_callback, NULL, 0},
	{0,0,0,0} //last callback
};

Always put NULL callback at the end of callback list */
void ICACHE_FLASH_ATTR esp_nano_httpd_register_content(const http_callback_t *content_info )
{
	url_config = content_info;
}

/* initialize nano httpd */
void ICACHE_FLASH_ATTR esp_nano_httpd_init(void)
{
	static struct espconn *conn;
	if(conn != NULL) return; //already initialized

	conn = (struct espconn *)os_zalloc(sizeof(struct espconn));
	if(conn == NULL) return;

	espconn_create(conn);
	espconn_regist_time(conn, 5, 1);

	conn->type =  ESPCONN_TCP;
	conn->state = ESPCONN_NONE;

	/* Listen TCP packets on port 80 */
	conn->proto.tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
	if(conn->proto.tcp == NULL)return;
	conn->proto.tcp->local_port = 80;

	espconn_regist_connectcb(conn, connection_listener);
	espconn_accept(conn);

	os_printf("nano httpd active on port %d\n", conn->proto.tcp->local_port);
}

/* initialize wifi AP and httpd. Use one of wifi modes defined in <user_interface.h>

NOTE: Two last bytes from device MAC address
will be added at the end to create unique AP names for multiple devices

For example:
AP_ssid defined as: "MY-ESP-DEV"

devices visible as:
	device 1: "MY-ESP-DEV-9FAE"
	device 2: "MY-ESP-DEV-A3C2"
	... */
void ICACHE_FLASH_ATTR esp_nano_httpd_init_AP(uint8_t wifi_mode, const char *AP_ssid, const char *AP_pass)
{
	struct softap_config ap_config = {0};
	char mac[6];

	if(wifi_mode == SOFTAP_MODE || wifi_mode == STATIONAP_MODE){
			wifi_get_macaddr(SOFTAP_IF, (unsigned char*)mac);
			wifi_softap_get_config(&ap_config);

			ets_snprintf(ap_config.ssid,32,"%s-%02X%02X", AP_ssid, mac[4],mac[5]);
			ets_strncpy(ap_config.password, AP_pass?AP_pass:"",64);
			ap_config.ssid_len = strlen(ap_config.ssid);
			ap_config.channel = 1;
			ap_config.authmode = AP_pass?AUTH_WPA_WPA2_PSK:AUTH_OPEN;
			ap_config.ssid_hidden = 0;
			ap_config.max_connection = 4;
			ap_config.beacon_interval = 100;

			wifi_set_opmode(NULL_MODE);
			wifi_set_opmode(wifi_mode);
			wifi_softap_set_config(&ap_config);
	}
	esp_nano_httpd_init();
}

