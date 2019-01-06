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

/*
Description:
 - file_upload_callback is used to upload any file from web browser to ESP flash memory.

	You should define file info object like:

	file_info_t wav_file = {
		.accept_file_ext  = ".wav",				//accepted file extension
		.accept_cont_type = "audio",			//accepted content type
		.base_sec =   512,					//start sector in flash memory for uploaded file write
		.max_f_size = 128*SPI_FLASH_SEC_SIZE	//max length in bytes in flash memory for uploaded file
	};

	and then connect it to file upload callback:
	const http_callback_t url_cfg[] = {
		{"/file_upload", file_upload_callback, &wav_file, 0 },
		{0,0,0,0}
	};

	Now it is possible to upload files from file input in web browser to ESP flash memory

	Supported actions(CGI like) for javascript  xhttp requests:
	GET  request: /file_upload		return file upload info:

	Example response data(json format):
	{
		"file_extension":".wav",
		"ContentType":"audio",
		"flash_sector":512,
		"max_size":524288,
		"upload_status":"",
		"upload_bytes":0
	}

 - firmware_upgrade_callback is used to provide Firmware Over the Air feature.

	All You need to do is to connect this calback to URL like:
	const http_callback_t url_cfg[] = {
		{"/upgrade", firmware_upgrade_callback, on_upgrade_init, 0 },
		{0,0,0,0}
	};
	You can specify an action taken right before upgrade and pass it to
	firmware_upgrade_callback as optional argument like
	void on_upgrade_init(void) function in this example

	Supported actions(CGI like) for javascript  xhttp requests:

	GET  request: /upgrade		return firmware upgrade info:

	Example response data(json format):
	{
		"usrbin":"APP1",
		"flash_map":"FLASH_SIZE_32M_MAP_1024_1024",
		"upload_status":"",
		"upload_bytes":0
	}

	During file/firmware upload upload_status field in GET response is updated and
	following values are possible:

	UPLOAD_IN_PROGRESS
	UPLOAD_COMPLETE
	UPLOAD_ERR_NO_INPUT_FILE
	UPLOAD_ERR_WRONG_FILE_EXT
	UPLOAD_ERR_WRONG_CONTENT
	UPLOAD_ERR_FILE_TOO_BIG
	UPLOAD_ERR_FLASH_WRITE
	UPLOAD_STATE_UNKNOWN
*/

typedef struct {
	const char *accept_file_ext;
	const char *accept_cont_type;
	uint16_t base_sec;
	uint32_t uploaded_bytes;
	uint32_t max_f_size;
} file_info_t;

void file_upload_callback(struct espconn *conn, void *arg, uint32_t len);
void firmware_upgrade_callback(struct espconn *conn, void *arg, uint32_t len);

#endif /* USER_NANO_HTTPD_FILE_UPLOAD_H_ */
