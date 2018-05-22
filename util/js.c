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

#include <osapi.h>
#include <mem.h>
#include <ip_addr.h>

#include "js.h"

static struct {
	char *buff;
	uint32_t bytes;
	uint32_t size;
} json_cache;

static int ICACHE_FLASH_ATTR json_putchar(int c)
{
    if(json_cache.buff != NULL && json_cache.bytes < json_cache.size) {
    	json_cache.buff[json_cache.bytes++] = c;
        return c;
    }
    return 0;
}

void ICACHE_FLASH_ATTR json_tree_send(struct espconn *conn, struct jsontree_object *js, uint32_t cache_size)
{
	struct jsontree_context js_ctx;

	json_cache.buff = (char *)os_zalloc(cache_size);
	if(json_cache.buff == NULL){
		resp_http_error(conn);
		return;
	}

	json_cache.size=cache_size;
	json_cache.bytes=0;

	jsontree_setup(&js_ctx, (struct jsontree_value *)js, json_putchar);
	while( jsontree_print_next(&js_ctx)){};

	send_http_response(conn, "200 OK","application/json", json_cache.buff, json_cache.bytes);
	os_free(json_cache.buff);
}

