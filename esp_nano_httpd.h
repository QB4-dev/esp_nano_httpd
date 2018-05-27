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

#ifndef ESP_NANO_HTTPD_H_
#define ESP_NANO_HTTPD_H_

#include <c_types.h>
#include <ip_addr.h>
#include <espconn.h>
#include <user_interface.h>
#include <json/jsontree.h>

typedef struct {
	enum {
		TYPE_UNKNOWN= 0,
		TYPE_GET	= 1,
		TYPE_POST	= 2
	} type;
	const char* path;
	const char* query;

	const char* content_type;
	uint32_t content_len;
	void *content;
	enum {
		REQ_GOT_HEADER	= 0,
		REQ_CONTENT_PART= 1
	} read_state;
	uint32_t cont_part_len;
	uint32_t cont_bytes_left;
} http_request_t;

typedef struct {
	const char *path;
	void (*handler)(struct espconn *, void *, uint32_t);
	void *arg;
	uint32_t arg_len;
} http_callback_t;

void esp_nano_httpd_register_content(const http_callback_t *content_info );
void esp_nano_httpd_init(void);
void esp_nano_httpd_init_AP(uint8_t wifi_mode, const char *AP_ssid);

void send_http_response(struct espconn *conn, const char *code, const char *cont_type, const char *content, uint32_t cont_len);
void send_html(struct espconn *conn, void *html, uint32_t len);
void send_json_tree(struct espconn *conn, struct jsontree_object *js_tree, uint32_t cache_size);

void resp_http_ok(struct espconn *conn);
void resp_http_404(struct espconn *conn);
void resp_http_error(struct espconn *conn);

#endif /* ESP_NANO_HTTPD_H_ */
