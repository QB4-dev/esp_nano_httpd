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

#include "nano_httpd_wifi_util.h"

#include <osapi.h>
#include <mem.h>
#include <ip_addr.h>
#include <espconn.h>
#include <json/jsontree.h>
#include "js.h"
#include "../esp_nano_httpd.h"

static struct bss_info *bss_link; //scan list
static struct espconn  *wifi_scan_conn; //to keep connection pointer for scan_done_cb

static int js_wifi_scan_list(struct jsontree_context *js_ctx);

static const char empty_str[] = "";
static struct jsontree_string js_conn_info = JSONTREE_STRING(empty_str);
static struct jsontree_string js_ssid_info = JSONTREE_STRING(empty_str);
static struct jsontree_string js_addr_info = JSONTREE_STRING(empty_str);
static struct jsontree_string js_save_info = JSONTREE_STRING(empty_str);
static struct jsontree_callback js_wifi_scan_cb = JSONTREE_CALLBACK(js_wifi_scan_list, NULL);
JSONTREE_OBJECT(json_tree,
	JSONTREE_PAIR("conn", &js_conn_info),
	JSONTREE_PAIR("SSID", &js_ssid_info),
	JSONTREE_PAIR("addr", &js_addr_info),
	JSONTREE_PAIR("save", &js_save_info),
	JSONTREE_PAIR("scan", &js_wifi_scan_cb),
);


static int ICACHE_FLASH_ATTR js_wifi_scan_list(struct jsontree_context *js_ctx)
{
	const char *auth_mode[] = { "OPEN", "WEP", "WPA-PSK", "WPA2-PSK", "WPA-PSK/WPA2-PSK" };
	char link_info[256];

	jsontree_write_atom(js_ctx, "[");
	while (bss_link != NULL){
		ets_snprintf(link_info,256,"{\"ssid\":\"%s\",\"auth\":\"%s\",\"rssi\":%d}", bss_link->ssid, auth_mode[bss_link->authmode], bss_link->rssi );
		jsontree_write_atom(js_ctx, link_info);

		if(bss_link->next.stqe_next != NULL) jsontree_write_atom(js_ctx, ",");
		bss_link = bss_link->next.stqe_next;
	}
	jsontree_write_atom(js_ctx, "]");
	return 0;
}

static void ICACHE_FLASH_ATTR resp_wifi_conn_status(void *arg)
{
	static struct station_config station_config;
	static struct ip_info ip_config;
	struct jsontree_context js_ctx;
	struct espconn *conn = arg;
	static char ip_addr[20];
	uint8_t st;
	const char *conn_status[]= {
		"IDLE",
		"CONNECTING",
		"WRONG_PASSWORD",
		"NO_AP_FOUND",
		"CONNECT_FAIL",
		"GOT_IP"
	};

	st = wifi_station_get_connect_status();
	js_conn_info.value = conn_status[st];

	wifi_get_ip_info(STATION_IF, &ip_config);
	os_sprintf(ip_addr,IPSTR,IP2STR(&ip_config.ip));
	js_addr_info.value = ip_addr;

	wifi_station_get_config(&station_config);
	js_ssid_info.value = station_config.ssid;
	json_tree_send(conn, &json_tree, 1024);
}

static void ICACHE_FLASH_ATTR wifi_scan_done(void *arg, STATUS status)
{
	if(wifi_scan_conn == NULL) return;
	if(status != OK) return resp_http_error(wifi_scan_conn);

	bss_link = (struct bss_info *)arg; //update bss_link list
	json_tree_send(wifi_scan_conn, &json_tree, 1024);
}


void ICACHE_FLASH_ATTR wifi_callback(struct espconn *conn, void *arg, uint32_t len)
{
    http_request_t *req = conn->reverse;
    struct station_config station_conf = {0};
    bool save_ok;
    char *param;
    char *action;

    if(req == NULL || wifi_get_opmode() == SOFTAP_MODE) return resp_http_error(conn);
    js_addr_info.value = empty_str;//reset addr info text
    js_save_info.value = empty_str;//reset save info text

    if(req->type == TYPE_GET && req->query != NULL){
		param=strtok((char*)req->query,"&");     //read request query string
		if( os_memcmp(param,"action=",7) == 0 ){
			action = strchr(param,'=')+1;

			if( os_strcmp(action,"scan") == 0){ //scan for available networks
				wifi_scan_conn = conn;
				wifi_station_scan(NULL,wifi_scan_done);
				return;
			} else if( os_strcmp(action,"save") == 0){ //save current config
				wifi_station_get_config(&station_conf);
				save_ok = wifi_station_set_config(&station_conf);
				js_save_info.value = save_ok?"OK":"ERROR";
			}
		}
    } else if(req->type == TYPE_POST){
		if(req->content == NULL) return resp_http_error(conn);
		/* in request content We expect serialized input form query like: ssid=MY_SSID&passwd=MY_PASSWD
		Use strtok to divide query into tokens*/
		param=strtok(req->content,"&");
		do {
			if( os_memcmp(param,"ssid=",5) == 0 )         //ssid value found
				ets_strncpy(station_conf.ssid, strchr(param,'=')+1,32);
			else if( os_memcmp(param,"passwd=",7) == 0 )  //password value found
				ets_strncpy(station_conf.password, strchr(param,'=')+1,64);
		} while( (param=strtok(NULL,"&")) != NULL);
		//now connect to network
		station_conf.bssid_set = 0; //do not look for specific router MAC address
		wifi_station_disconnect();
		wifi_station_set_config_current(&station_conf);
		wifi_station_connect();
    }
    resp_wifi_conn_status(conn);
}
