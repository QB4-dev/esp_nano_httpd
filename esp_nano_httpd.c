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

#ifndef ESP_NANO_HTTPD_AP_NAME
	#define ESP_NANO_HTTPD_AP_NAME	"ESP-DEV"
#endif

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

static const http_callback_t *url_config;
static volatile os_timer_t http_resp_tx_timer;

static char  *http_response_buff = NULL;
static uint32 http_response_len = 0;
static uint32 http_response_pos = 0;

static void ICACHE_FLASH_ATTR http_resp_chunk_tx(struct espconn *conn)
{
	uint32 len = http_response_len - http_response_pos;
	if( len > 256) len = 256; //set chunk size

	if( len <= 0 ){
		os_timer_disarm(&http_resp_tx_timer);
		os_free(http_response_buff);
		http_response_buff = NULL;
		espconn_disconnect(conn);
		return;
	}

	if( 0 == espconn_sent(conn, (char*)&http_response_buff[http_response_pos], len) )
		http_response_pos+=len;
}

void ICACHE_FLASH_ATTR send_http_response(struct espconn *conn, const char *code, const char *cont_type, const char *content, uint32_t cont_len)
{
	char header[] = "HTTP/1.1 %s\r\n"
			"Accept-Ranges: bytes\r\n"
			"Content-Type: %s; charset=UTF-8\r\n"
			"Content-Length: %i\r\n"
			"Connection: close\r\n\r\n";
	uint32_t content_len;
	uint32_t header_len;

	if( http_response_buff != NULL ){
		os_free(http_response_buff);
		http_response_buff = NULL;
	}

	content_len = (content != NULL)?(cont_len):(0);

	http_response_len = strlen(header)+strlen(code)+strlen(cont_type)+10+content_len+1; //10 for content length string
	http_response_buff = (char *)os_malloc(http_response_len);

	if(http_response_buff == NULL) return;
	http_response_pos = 0;

	ets_snprintf(http_response_buff, http_response_len, header, code, cont_type, content_len);
	header_len = strlen(http_response_buff);
	if( content_len > 0 )
		memcpy(http_response_buff+header_len, content, content_len);

	http_response_buff[header_len+content_len] = 0; //NULL terminated
	http_response_len = strlen(http_response_buff);

	NANO_HTTPD_DBG_REQ("request response: %s\n", http_response_buff);
	os_timer_disarm(&http_resp_tx_timer);
	os_timer_setfn(&http_resp_tx_timer, (os_timer_func_t *)http_resp_chunk_tx, conn);
	os_timer_arm (&http_resp_tx_timer, 10, 1);
}

void ICACHE_FLASH_ATTR resp_http_ok(struct espconn *conn) {
	send_http_response(conn, "200 OK","text/html",NULL,0);
}

void ICACHE_FLASH_ATTR resp_http_404(struct espconn *conn) {
	const char content[] = "Error 404 Not Found";
	send_http_response(conn, "404 Not Found","text/html",content,strlen(content));
}

void ICACHE_FLASH_ATTR resp_http_error(struct espconn *conn) {
	const char content[] = "500 Internal Error";
	send_http_response(conn, "500 Internal Error", "text/html",content,strlen(content));
}

void ICACHE_FLASH_ATTR send_html(struct espconn *conn, http_request_t *req, void *arg, uint32_t len){
	send_http_response(conn, "200 OK","text/html", arg, len);
}

static int ICACHE_FLASH_ATTR parse_http_request_header(http_request_t *req, char *data, unsigned short len){
	char *type, *path, *query, *http_ver;
	char *head_attr, *content_type, *content_len, *req_data;

	if( data == NULL ) goto unknown_request;

	//find header attributes
	head_attr = strstr(data,"\r\n");
	if(head_attr != NULL){
		os_memset(head_attr,0,2);
		head_attr=head_attr+2;
	} else
		goto unknown_request;

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
	} else
		goto unknown_request;

	//find header end
	req_data = strstr(head_attr,"\r\n\r\n");
	if(req_data != NULL){
		memset(req_data,0,4);
		if(req_data+4 == data+len)
			return 0; //no more data expected
		else
			req->content=req_data+4;
	}
	//get request content information
	content_type = strstr(head_attr,"Content-Type:");
	content_len =  strstr(head_attr,"Content-Length:");

	if(content_type != NULL){
		content_type = strtok(content_type,"\r\n");
		req->content_type = strchr(content_type,':')+1;
	}
	if(content_len != NULL){
		content_len = strtok(content_len,"\r\n");
		req->content_len = atoi(strchr(content_len,':')+1);
	}
	return 0;

unknown_request:
	req->type = TYPE_UNKNOWN;
	return -1;
}

static void ICACHE_FLASH_ATTR receive_cb(void *arg, char *pdata, unsigned short len)
{
	struct espconn *conn = (struct espconn *)arg;
	const http_callback_t *url;

	NANO_HTTPD_DBG("got new request. Free heap size: %d\n", system_get_free_heap_size());
	NANO_HTTPD_DBG_REQ("request:\n %s\n", pdata);

	http_request_t *req = (http_request_t *)conn->reverse;

	if ( pdata == NULL || req == NULL )
		return;

	parse_http_request_header(req,pdata,len);

	NANO_HTTPD_DBG("req type: %d \npath: %s\n query: %s\n content_type %s\n data %s\n",
			req->type, req->path, req->query, req->content_type, req->content);

	if(req->type == TYPE_UNKNOWN){
		resp_http_error(conn);
		return;
	}

	//try to find requested url in given url config
	for(url = url_config; url->path != NULL; url++){
		if( strcmp(req->path,url->path) == 0 ){
			NANO_HTTPD_DBG("url: %s found\n", req->path);
			if(url->handler__ != NULL) (*url->handler__)(conn, req, url->arg, url->arg_len);
			return;//request handled
		}
	}
	resp_http_404(conn); //url not found
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

    //espconn_set_opt(conn, ESPCONN_NODELAY);
    espconn_set_opt(conn, ESPCONN_COPY);
    //espconn_set_opt(conn, ESPCONN_REUSEADDR);

    http_request_t *req = (http_request_t*) os_zalloc(sizeof(http_request_t));
    conn->reverse = req;

    espconn_regist_recvcb(conn, receive_cb );
    espconn_regist_disconcb(conn, disconnect_cb);
}


void ICACHE_FLASH_ATTR esp_nano_httpd_register_content(const http_callback_t *content_info ){
	url_config = content_info;
}

/* initialize httpd server, use one of wifi modes defined in <user_interface.h> */
void ICACHE_FLASH_ATTR esp_nano_httpd_init(uint8_t wifi_mode){
	struct softap_config ap_config;
	char mac[6];

	struct espconn *conn;

	switch(wifi_mode){
		case SOFTAP_MODE:
		case STATIONAP_MODE:
			wifi_get_macaddr(SOFTAP_IF, (unsigned char*)mac);
			wifi_softap_get_config(&ap_config);

			ets_snprintf(ap_config.ssid,32,"%s-%02X%02X", ESP_NANO_HTTPD_AP_NAME, mac[4],mac[5]);
			ap_config.password[0] = 0;
			ap_config.ssid_len = strlen(ap_config.ssid);
			ap_config.channel = 1;
			ap_config.authmode = AUTH_OPEN;
			ap_config.ssid_hidden = 0;
			ap_config.max_connection = 4;
			ap_config.beacon_interval = 100;

			wifi_set_opmode(NULL_MODE);
			wifi_set_opmode(wifi_mode);
			wifi_softap_set_config(&ap_config);
			break;
		case STATION_MODE: //only init connection listener
			break;
		default:
			break;
	}
	conn = (struct espconn *)os_zalloc(sizeof(struct espconn));

	espconn_create(conn);
	espconn_regist_time(conn, 5, 0);

	conn->type =  ESPCONN_TCP;
	conn->state = ESPCONN_NONE;

	conn->proto.tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
	conn->proto.tcp->local_port = 80;

	espconn_regist_connectcb(conn, connection_listener);
	espconn_accept(conn);

	os_printf("nano httpd started\n");
}

