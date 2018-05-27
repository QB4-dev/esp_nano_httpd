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

#ifndef USER_NANO_HTTPD_FILE_UPLOAD_H_
#define USER_NANO_HTTPD_FILE_UPLOAD_H_

#include "../esp_nano_httpd/esp_nano_httpd.h"
#include <os_type.h>

typedef struct {
	const char *accept_cont_type;
	uint16_t base_sec;
	uint32_t upload_size;
	uint32_t max_f_size;
} file_info_t;

void file_upload_callback(struct espconn *conn, void *arg, uint32_t len);
void firmware_upgrade_callback(struct espconn *conn, void *arg, uint32_t len);

#endif /* USER_NANO_HTTPD_FILE_UPLOAD_H_ */
