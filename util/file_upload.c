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

#include "file_upload.h"

#include <ets_sys.h>
#include <osapi.h>
#include <spi_flash.h>
#include <mem.h>
#include <json/jsontree.h>
#include <upgrade.h>
#include "firmware_upgrade.h"


static const char empty_str[] = "";
static struct jsontree_string js_upload_f_ext		= JSONTREE_STRING(empty_str);
static struct jsontree_string js_upload_c_type		= JSONTREE_STRING(empty_str);
static struct jsontree_int	  js_upload_sec			= {.type= JSON_TYPE_INT, .value=0};
static struct jsontree_int 	  js_upload_max_size 	= {.type= JSON_TYPE_INT, .value=0};
static struct jsontree_string js_upload_status 		= JSONTREE_STRING(empty_str);
static struct jsontree_int 	  js_upload_bytes 		= {.type= JSON_TYPE_INT, .value=0};

JSONTREE_OBJECT(js_tree_upload,
	JSONTREE_PAIR("file_extension",&js_upload_f_ext),
	JSONTREE_PAIR("ContentType",   &js_upload_c_type),
	JSONTREE_PAIR("flash_sector",  &js_upload_sec),
	JSONTREE_PAIR("max_size", 	   &js_upload_max_size),
	JSONTREE_PAIR("upload_status", &js_upload_status),
	JSONTREE_PAIR("upload_bytes",  &js_upload_bytes)
);

static struct jsontree_string js_upgrade_usrbin    = JSONTREE_STRING(empty_str);
static struct jsontree_string js_upgrade_flash_map = JSONTREE_STRING(empty_str);

JSONTREE_OBJECT(js_tree_upgrade,
	JSONTREE_PAIR("usrbin", 		&js_upgrade_usrbin),
	JSONTREE_PAIR("flash_map", 		&js_upgrade_flash_map),
	JSONTREE_PAIR("upload_status",	&js_upload_status),
	JSONTREE_PAIR("upload_bytes",  	&js_upload_bytes)
);

#define EXTRA_BYTES		128 //additional bytes in sector buffer
#define SEC_BUFF_LEN	SPI_FLASH_SEC_SIZE+EXTRA_BYTES

typedef struct {
	uint16_t c_sec;		//current flash sector
	uint16_t sec_wr;	//sector write index
	uint32_t wr;		//total write index
	uint8_t  sec_buff[SEC_BUFF_LEN];
} flash_upload_t;

typedef struct {
	const char *boundary;
	enum {
		GET_CONTENT_BOUNDARY		=  0,
		GET_CONTENT_INFO			=  1,
		UPLOAD_IN_PROGRESS			=  2,
		UPLOAD_COMPLETE				=  3,
		UPLOAD_ERR_NO_INPUT_FILE	= -1,
		UPLOAD_ERR_WRONG_FILE_EXT 	= -2,
		UPLOAD_ERR_WRONG_CONTENT	= -3,
		UPLOAD_ERR_FILE_TOO_BIG		= -4,
		UPLOAD_ERR_FLASH_WRITE		= -5,
	} state;
	file_info_t    *f_info;
	flash_upload_t *flash;
} upload_state_t;


static uint8_t* ICACHE_FLASH_ATTR get_bound(const char *content_type)
{
    static char boundary[72];
    uint8_t *bound;

    if(content_type == NULL) return boundary;

	bound = strstr(content_type,"boundary=");
	if( bound != NULL && strstr(content_type,"multipart/form-data;") != NULL ){
		ets_snprintf(boundary,sizeof(boundary),"--%s",strchr(bound,'=')+1);
		return boundary;
	} else {
		return NULL;
	}
}

static uint8_t* ICACHE_FLASH_ATTR find_bound(uint8_t *data, uint32_t len, const char *bound)
{
	uint16_t bound_len = strlen(bound);
	uint8_t  match = 0;
	uint16_t i;

	for(i=0; i<len;i++){
		( data[i] == bound[match] )?(match++):( match=0 );
		if(match == bound_len)
			return &data[i]+1; //return bound end addr
	}
	return NULL;
}


static void ICACHE_FLASH_ATTR req_content_upload(uint8_t *content, uint32_t len, upload_state_t *upload, uint32_t bytes_left)
{
	char *tok, *cont_disposition, *input_name, *f_name, *content_type;
    uint8_t *p, *bound_end, *file_cont;
	uint32_t rx, page_wr, sector_wr;
	flash_upload_t *flash = upload->flash;
	uint16_t base_sec = upload->f_info->base_sec;

	switch(upload->state){
		case GET_CONTENT_BOUNDARY:
			bound_end = find_bound(content, len, upload->boundary);
			if( bound_end != NULL){
				rx = bound_end - content;  //count processed bytes
				upload->state = GET_CONTENT_INFO;
				if(rx < len) req_content_upload(bound_end, len-rx, upload, bytes_left);
			}
			break;
		case GET_CONTENT_INFO:
			p = content+2; //skip CR LF
			file_cont = strstr(p,"\r\n\r\n");
			if(file_cont == NULL || file_cont+4 > content+len)
				return;
			os_memset(file_cont,0,4); //mask  CR LF CR LF
			file_cont += 4;  		  //skip  CR LF CR LF
			rx = file_cont - content; //count processed bytes

			//find content info
			tok = strtok(p,";\r\n");
			do{
				if(strstr(tok,"Content-Disposition: "))
					cont_disposition = strchr(tok,' ')+1;
				else if(strstr(tok," name="))
					input_name = strchr(tok,'=')+1;
				else if(strstr(tok," filename=")){
					f_name = strchr(tok,'=')+1;
					os_printf("file name:%s\n",f_name);
				}
				else if(strstr(tok,"Content-Type: "))
					content_type = strchr(tok,' ')+1;
			} while( (tok = strtok(NULL,";\r\n")) != NULL);

			//check if file exists
			if( strcmp(f_name, "\"\"") == 0 ){
				os_printf("error: no file\n");
				upload->state = UPLOAD_ERR_NO_INPUT_FILE;
				return;
			}
			//check file extension
			if( upload->f_info->accept_file_ext && strstr(f_name, upload->f_info->accept_file_ext) == NULL ){
				os_printf("error: wrong file type != %s \n", upload->f_info->accept_file_ext);
				upload->state = UPLOAD_ERR_WRONG_FILE_EXT;
				return;
			}
			//skip content type check when: content type not specified/"application/octet-stream" - general binary data
			if( upload->f_info->accept_cont_type && strcmp(content_type, "application/octet-stream" ) != 0 ){
				//check content type
				if( strstr(content_type, upload->f_info->accept_cont_type) == 0 ){
					os_printf("Error: content type mismatch %s != %s\n", content_type, upload->f_info->accept_cont_type);
					upload->state = UPLOAD_ERR_WRONG_CONTENT;
					return;
				}
			}
			upload->state = UPLOAD_IN_PROGRESS;
			if(rx < len) req_content_upload(file_cont, len-rx, upload, bytes_left);
			break;
		case UPLOAD_IN_PROGRESS:
			page_wr = (flash->sec_wr+len < SEC_BUFF_LEN)?(len):(SEC_BUFF_LEN - flash->sec_wr);
			os_memcpy(flash->sec_buff+flash->sec_wr, content, page_wr); //write new bytes to buffer
			flash->sec_wr += page_wr;
			len-= page_wr;
			//check upload size
			if(flash->wr + flash->sec_wr > upload->f_info->max_f_size){
				upload->state = UPLOAD_ERR_FILE_TOO_BIG;
				return;
			}

			if(flash->sec_wr == SEC_BUFF_LEN || bytes_left == 0){ //page buffer full or no more req bytes left
				spi_flash_erase_sector(base_sec+flash->c_sec); //erase new sector

				bound_end = find_bound(flash->sec_buff, SEC_BUFF_LEN, upload->boundary); //try find end boundary
				if( bound_end != NULL){ //got bound end
					rx = bound_end - flash->sec_buff;  			   //count processed bytes
					sector_wr = rx - (strlen(upload->boundary)+2); // + CR LF
				} else {
					sector_wr = SPI_FLASH_SEC_SIZE;	//normal - full sector write
				}
				os_printf("upload: sec %x/%db %db left\n", base_sec+flash->c_sec, sector_wr, bytes_left);

				//flash sector write
				ets_intr_lock();
				if( SPI_FLASH_RESULT_OK == spi_flash_write( (base_sec+flash->c_sec)*SPI_FLASH_SEC_SIZE, (uint32_t *)flash->sec_buff, sector_wr) ){
					flash->wr+= sector_wr;
					//move extra bytes in buffer from end to start
					os_memcpy(flash->sec_buff, flash->sec_buff+SPI_FLASH_SEC_SIZE, EXTRA_BYTES);
					flash->sec_wr=EXTRA_BYTES;
					flash->c_sec++;
					// if bound-end found file upload is complete
					if( bound_end != NULL) upload->state = UPLOAD_COMPLETE;
				}else{
					upload->state = UPLOAD_ERR_FLASH_WRITE;
				}
				upload->f_info->uploaded_bytes = upload->flash->wr;
				ets_intr_unlock();
			}
			if(upload->state != UPLOAD_IN_PROGRESS)return;
			if(len > 0) req_content_upload(content+page_wr, len, upload, bytes_left);
			break;
		default:
			break;
	}
}

static const char ICACHE_FLASH_ATTR *get_upload_state_str(upload_state_t *upload )
{
	if(upload == NULL) return empty_str;

	switch(upload->state){
		case UPLOAD_IN_PROGRESS:   		return "UPLOAD_IN_PROGRESS";
		case UPLOAD_COMPLETE:   		return "UPLOAD_COMPLETE";
		case UPLOAD_ERR_NO_INPUT_FILE:  return "UPLOAD_ERR_NO_INPUT_FILE";
		case UPLOAD_ERR_WRONG_FILE_EXT: return "UPLOAD_ERR_WRONG_FILE_EXT";
		case UPLOAD_ERR_WRONG_CONTENT:  return "UPLOAD_ERR_WRONG_CONTENT";
		case UPLOAD_ERR_FILE_TOO_BIG: 	return "UPLOAD_ERR_FILE_TOO_BIG";
		case UPLOAD_ERR_FLASH_WRITE: 	return "UPLOAD_ERR_FLASH_WRITE";
		default: break;
	}
	return "UPLOAD_STATE_UNKNOWN";
}

static void ICACHE_FLASH_ATTR resp_upload_info(struct espconn *conn, file_info_t *f_info, upload_state_t *upload)
{
	js_upload_f_ext.value = f_info->accept_file_ext;
	js_upload_c_type.value = f_info->accept_cont_type;
	js_upload_sec.value = f_info->base_sec;
	js_upload_max_size.value = f_info->max_f_size;

	js_upload_status.value = get_upload_state_str(upload);
	js_upload_bytes.value  = (upload != NULL)? upload->flash->wr:0;

	send_json_tree(conn, &js_tree_upload, 256);
}


void ICACHE_FLASH_ATTR file_upload_callback(struct espconn *conn, void *arg, uint32_t len)
{
	http_request_t *req = conn->reverse;
	file_info_t *f_info = arg;
	upload_state_t *upload;

    if(req != NULL || f_info != NULL )
    	upload=(upload_state_t *)req->prv_data;
    else
    	return resp_http_error(conn);

    if(req->type == TYPE_GET )
    	return resp_upload_info(conn, f_info, upload);

    if(req->type != TYPE_POST )
    	return resp_http_error(conn);

    if( req->read_state == REQ_GOT_HEADER ){
    	upload = (upload_state_t*)os_zalloc(sizeof(upload_state_t));
    	if(upload == NULL) return resp_http_error(conn);

		upload->flash  = (flash_upload_t*)os_zalloc(sizeof(flash_upload_t));
		if(upload->flash == NULL) return resp_http_error(conn);

    	upload->boundary = get_bound(req->content_type);
    	if(upload->boundary == NULL) return resp_http_error(conn);

		upload->f_info = f_info;
		req->prv_data = upload;
		os_printf("file upload...\n");
    }
    req_content_upload(req->content, req->cont_chunk_len, upload, req->cont_bytes_left);

    if(req->cont_bytes_left == 0){
		os_printf("uploaded(%d bytes) %s\n", upload->f_info->uploaded_bytes, (upload->state==UPLOAD_COMPLETE)?("OK"):("ERR"));
		resp_upload_info(conn, f_info, upload);
		os_free(upload->flash);
		os_free(upload);
		upload = NULL;
    }
}


static void ICACHE_FLASH_ATTR resp_upgrade_info(struct espconn *conn, upload_state_t *upload)
{
	uint8_t fw_bin;
	enum flash_size_map flash_map;

	fw_bin = system_upgrade_userbin_check();
	flash_map = system_get_flash_size_map();

	js_upgrade_usrbin.value = (fw_bin == UPGRADE_FW_BIN1)?"APP1":"APP2";

	switch(flash_map){
		case FLASH_SIZE_4M_MAP_256_256:
		case FLASH_SIZE_2M:
			js_upgrade_flash_map.value = "FOTA_NOT_SUPPORTED";
			break;
		case FLASH_SIZE_8M_MAP_512_512:
			js_upgrade_flash_map.value = "FLASH_SIZE_8M_MAP_512_512";
			break;
		case FLASH_SIZE_16M_MAP_512_512:
			js_upgrade_flash_map.value = "FLASH_SIZE_16M_MAP_512_512";
			break;
		case FLASH_SIZE_32M_MAP_512_512:
			js_upgrade_flash_map.value = "FLASH_SIZE_32M_MAP_512_512";
			break;
		case FLASH_SIZE_16M_MAP_1024_1024:
			js_upgrade_flash_map.value = "FLASH_SIZE_16M_MAP_1024_1024";
			break;
		case FLASH_SIZE_32M_MAP_1024_1024:
			js_upgrade_flash_map.value = "FLASH_SIZE_32M_MAP_1024_1024";
			break;
		default:
			js_upgrade_flash_map.value = "FLASH_SIZE_MAP_UNKNOWN";
			break;
	}
	js_upload_status.value = get_upload_state_str(upload);
	js_upload_bytes.value  = (upload != NULL)?upload->flash->wr:0;

	send_json_tree(conn, &js_tree_upgrade, 256);
}


void ICACHE_FLASH_ATTR firmware_upgrade_callback(struct espconn *conn, void *arg, uint32_t len)
{
	http_request_t *req = conn->reverse;
	static file_info_t f_info;
	static upload_state_t *upload;
	enum flash_size_map flash_map;
    char *param, *action;
    void (*before_upgrade)(void) = arg;
    static os_timer_t reboot_timer;
	uint8_t fw_bin;

    if(req == NULL)
    	return resp_http_error(conn);

    //GET request - return upgrade info
    if(req->type == TYPE_GET && req->query == NULL)
    	return resp_upgrade_info(conn, upload);
    //POST request - firmware upload
    if(req->type != TYPE_POST )
      	return resp_http_error(conn);

    if( req->read_state == REQ_GOT_HEADER ){
    	//stop if another firmware upload not finished
    	if(upload != NULL )
    		return resp_http_error(conn);

    	f_info.accept_file_ext = ".bin";
    	f_info.accept_cont_type = NULL;
    	fw_bin    = system_upgrade_userbin_check();
    	flash_map = system_get_flash_size_map();
		os_printf("fw app bin: %s upgrade flash map %d\n", fw_bin?"APP1":"APP2", flash_map);

		switch(flash_map){
			case FLASH_SIZE_4M_MAP_256_256:
			case FLASH_SIZE_2M:
				return resp_http_error(conn); //FOTA not supported
			case FLASH_SIZE_8M_MAP_512_512:
			case FLASH_SIZE_16M_MAP_512_512:
			case FLASH_SIZE_32M_MAP_512_512:
				f_info.base_sec = (fw_bin == UPGRADE_FW_BIN2)? 0x0001:0x0081;
				f_info.max_f_size = 128*SPI_FLASH_SEC_SIZE;
				break;
			case FLASH_SIZE_16M_MAP_1024_1024:
			case FLASH_SIZE_32M_MAP_1024_1024:
				f_info.base_sec = (fw_bin == UPGRADE_FW_BIN2)? 0x0001:0x0101;
				f_info.max_f_size = 256*SPI_FLASH_SEC_SIZE;
				break;
			default:
				return resp_http_error(conn); //flash map unknown
		}
		//execute before upgrade action if specified
		if( before_upgrade != NULL ) before_upgrade();

    	upload = (upload_state_t*)os_zalloc(sizeof(upload_state_t));
    	if(upload == NULL) return resp_http_error(conn);

		upload->flash  = (flash_upload_t*)os_zalloc(sizeof(flash_upload_t));
		if(upload->flash == NULL) return resp_http_error(conn);

    	upload->boundary = get_bound(req->content_type);
    	if(upload->boundary == NULL) return resp_http_error(conn);

		upload->f_info = &f_info;
    }
    req_content_upload(req->content, req->cont_chunk_len, upload, req->cont_bytes_left);

    //request processing finished
    if(req->cont_bytes_left == 0){
		os_printf("firmware uploaded(%d bytes) %s\n", upload->f_info->uploaded_bytes, (upload->state==UPLOAD_COMPLETE)?("OK"):("ERR"));
		resp_upgrade_info(conn, upload);
		os_free(upload->flash);
		os_free(upload);
		//reboot to new firmware if firmware upload is complete
		if( upload->state == UPLOAD_COMPLETE ){
			system_upgrade_flag_set(UPGRADE_FLAG_FINISH);
			//delayed reboot - let ESP send response to client before restart
			os_printf("FOTA reboot...\n");
			os_timer_disarm(&reboot_timer);
			os_timer_setfn(&reboot_timer, (os_timer_func_t *)system_upgrade_reboot, NULL);
			os_timer_arm(&reboot_timer, 1000, 0);
		}
    }
}
