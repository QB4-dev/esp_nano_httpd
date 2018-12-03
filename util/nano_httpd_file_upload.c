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

#include <ets_sys.h>
#include <osapi.h>
#include <spi_flash.h>
#include <mem.h>
#include <json/jsontree.h>
#include <upgrade.h>

#include "nano_httpd_file_upload.h"

static const char empty_str[] = "";
static struct jsontree_string js_upload_f_ext		= JSONTREE_STRING(empty_str);
static struct jsontree_string js_upload_c_type		= JSONTREE_STRING(empty_str);
static struct jsontree_int	  js_upload_sec			= {.type= JSON_TYPE_INT, .value=0};
static struct jsontree_int 	  js_upload_max_size 	= {.type= JSON_TYPE_INT, .value=0};
static struct jsontree_string js_upload_info 		= JSONTREE_STRING(empty_str);

JSONTREE_OBJECT(js_tree_upload,
	JSONTREE_PAIR("file_extension",&js_upload_f_ext),
	JSONTREE_PAIR("ContentType",   &js_upload_c_type),
	JSONTREE_PAIR("flash_sector",  &js_upload_sec),
	JSONTREE_PAIR("max_size", 	   &js_upload_max_size),
	JSONTREE_PAIR("upload_status", &js_upload_info)
);

static struct jsontree_string js_upgrade_usrbin    = JSONTREE_STRING(empty_str);
static struct jsontree_string js_upgrade_flash_map = JSONTREE_STRING(empty_str);

JSONTREE_OBJECT(js_tree_upgrade,
	JSONTREE_PAIR("usrbin", &js_upgrade_usrbin),
	JSONTREE_PAIR("flash_map", &js_upgrade_flash_map),
	JSONTREE_PAIR("upload_status",&js_upload_info)
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
		GET_INIT_BOUND				=  0,
		GET_CONTENT_INFO			=  1,
		CONTENT_UPLOAD				=  2,
		UPLOAD_COMPLETE				=  3,
		UPLOAD_ERR_NO_INPUT_FILE	= -1,
		UPLOAD_ERR_WRONG_FILE_EXT 	= -2,
		UPLOAD_ERR_WRONG_CONTENT	= -3,
		UPLOAD_ERR_FILE_TOO_BIG		= -4,
		UPLOAD_FLASH_WRITE_ERROR	= -5,
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



static void ICACHE_FLASH_ATTR content_upload(uint8_t *content, uint32_t len, upload_state_t *upload, uint32_t bytes_left)
{
	char *tok, *cont_disposition, *input_name, *f_name, *content_type;
    uint8_t *p, *bound_end, *file_cont;
	uint32_t rx, page_wr, sector_wr;
	flash_upload_t *flash = upload->flash;
	uint16_t base_sec = upload->f_info->base_sec;

	switch(upload->state){
		case GET_INIT_BOUND:
			bound_end = find_bound(content, len, upload->boundary);
			if( bound_end != NULL){
				rx = bound_end - content;  //count processed bytes
				upload->state = GET_CONTENT_INFO;
				if(rx < len) content_upload(bound_end, len-rx, upload, bytes_left);
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
			if( strstr(f_name, upload->f_info->accept_file_ext) == NULL ){
				os_printf("error: wrong file type != %s \n", upload->f_info->accept_file_ext);
				upload->state = UPLOAD_ERR_WRONG_FILE_EXT;
				return;
			}
			//check content type
			if( strcmp(content_type, "application/octet-stream" ) != 0 ){ //general binary data/content type not specified
				if(strstr(content_type, upload->f_info->accept_cont_type) == 0 ){
					os_printf("Error: content type mismatch %s != %s\n", content_type, upload->f_info->accept_cont_type);
					upload->state = UPLOAD_ERR_WRONG_CONTENT;
					return;
				}
			}
			upload->state = CONTENT_UPLOAD;
			if(rx < len) content_upload(file_cont, len-rx, upload, bytes_left);
			break;
		case CONTENT_UPLOAD:
			page_wr = (flash->sec_wr+len < SEC_BUFF_LEN)?(len):(SEC_BUFF_LEN - flash->sec_wr);
			os_memcpy(flash->sec_buff+flash->sec_wr, content, page_wr); //write new bytes to buffer
			flash->sec_wr += page_wr;
			len-= page_wr;

			if(flash->wr + flash->sec_wr > upload->f_info->max_f_size){
				upload->state = UPLOAD_ERR_FILE_TOO_BIG;
				return;
			}

			if(flash->sec_wr == SEC_BUFF_LEN || bytes_left == 0){ //page buffer full or no more bytes left
				os_printf("upload: sector %x %d bytes left \n", base_sec+flash->c_sec, bytes_left);
				spi_flash_erase_sector(base_sec+flash->c_sec); //erase new sector

				bound_end = find_bound(flash->sec_buff, SEC_BUFF_LEN, upload->boundary); //try find end boundary
				if( bound_end != NULL){ //got bound end
					rx = bound_end - flash->sec_buff;  			   //count processed bytes
					sector_wr = rx - (strlen(upload->boundary)+2); // + CR LF
				} else {
					sector_wr = SPI_FLASH_SEC_SIZE;	//normal - full sector write
				}
				//flash sector write
				ets_intr_lock();
				if( spi_flash_write( (base_sec+flash->c_sec)*SPI_FLASH_SEC_SIZE,(uint32_t *)flash->sec_buff,sector_wr) == SPI_FLASH_RESULT_OK){
					flash->wr+= sector_wr;
					//move extra bytes in buffer from end to start
					os_memcpy(flash->sec_buff, flash->sec_buff+SPI_FLASH_SEC_SIZE, EXTRA_BYTES);
					flash->sec_wr=EXTRA_BYTES;
					flash->c_sec++;

					//if bound-end found file upload is complete
					if( bound_end != NULL) upload->state = UPLOAD_COMPLETE;
				}else{
					upload->state = UPLOAD_FLASH_WRITE_ERROR;
				}
				ets_intr_unlock();
			}
			if(upload->state != CONTENT_UPLOAD)return;
			if(len > 0) content_upload(content+page_wr, len, upload, bytes_left);
			break;
		default:
			break;
	}
}

static void ICACHE_FLASH_ATTR set_upload_info(upload_state_t *upload, char *info)
{
	switch(upload->state){
		case UPLOAD_COMPLETE:
			ets_snprintf(info,32,"uploaded %d bytes OK",upload->flash->wr);
			break;
		case UPLOAD_ERR_NO_INPUT_FILE:
			ets_snprintf(info,32,"no input file");
			break;
		case UPLOAD_ERR_WRONG_FILE_EXT:
			ets_snprintf(info,32,"wrong file type");
			break;
		case UPLOAD_ERR_WRONG_CONTENT:
			ets_snprintf(info,32,"wrong ContentType");
			break;
		case UPLOAD_ERR_FILE_TOO_BIG:
			ets_snprintf(info,32,"file too big");
			break;
		case UPLOAD_FLASH_WRITE_ERROR:
			ets_snprintf(info,32,"flash write error");
			break;
		default:
			ets_snprintf(info,32,"upload state %d", upload->state);
			break;
	}
	js_upload_info.value = info;
}

static void ICACHE_FLASH_ATTR resp_upload_info(struct espconn *conn, file_info_t *f_info, upload_state_t *upload)
{
	char info[32];

	js_upload_f_ext.value = f_info->accept_file_ext;
	js_upload_c_type.value = f_info->accept_cont_type;
	js_upload_sec.value = f_info->base_sec;
	js_upload_max_size.value = f_info->max_f_size;

	if(upload != NULL) set_upload_info(upload, info);
	send_json_tree(conn, &js_tree_upload, 256);
}


void ICACHE_FLASH_ATTR file_upload_callback(struct espconn *conn, void *arg, uint32_t len)
{
	http_request_t *req = conn->reverse;
	file_info_t *f_info = arg;

	static upload_state_t *upload;

    if(req == NULL || f_info == NULL )
    	return resp_http_error(conn);

    if(req->type == TYPE_GET )
    	return resp_upload_info(conn, f_info, upload);

    if( req->read_state == REQ_GOT_HEADER ){
    	upload = (upload_state_t*)os_zalloc(sizeof(upload_state_t));
    	if(upload == NULL) return resp_http_error(conn);

		upload->flash  = (flash_upload_t*)os_zalloc(sizeof(flash_upload_t));
		if(upload->flash == NULL) return resp_http_error(conn);

    	upload->boundary = get_bound(req->content_type);
    	if(upload->boundary == NULL) return resp_http_error(conn);

		upload->f_info = f_info;
		os_printf("file upload\n");
    }
    content_upload(req->content, req->cont_part_len, upload, req->cont_bytes_left);

    if(req->cont_bytes_left == 0){
    	upload->f_info->upload_size = upload->flash->wr;
		os_printf("uploaded(%d bytes) %s\n", upload->f_info->upload_size, (upload->state==UPLOAD_COMPLETE)?("OK"):("ERR"));
		resp_upload_info(conn, f_info, upload);
		os_free(upload->flash);
		os_free(upload);
		upload = NULL;
    }
}


static void ICACHE_FLASH_ATTR resp_upgrade_info(struct espconn *conn, upload_state_t *upload)
{
	char info[32];
	uint8_t fw_bin;
	enum flash_size_map flash_map;

	fw_bin = system_upgrade_userbin_check();
	flash_map = system_get_flash_size_map();

	js_upgrade_usrbin.value = (fw_bin == UPGRADE_FW_BIN1)?"APP1":"APP2";

	switch(flash_map){
		case FLASH_SIZE_4M_MAP_256_256:
		case FLASH_SIZE_2M:
			js_upgrade_flash_map.value = "FOTA not supported";
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
			break;
	}
	if(upload != NULL) set_upload_info(upload, info);
	send_json_tree(conn, &js_tree_upgrade, 256);
}


void ICACHE_FLASH_ATTR firmware_upgrade_callback(struct espconn *conn, void *arg, uint32_t len)
{
	http_request_t *req = conn->reverse;
	static file_info_t f_info;
	static upload_state_t *upload;
	enum flash_size_map flash_map;
    char *param, *action;
	uint8_t fw_bin;

    if(req == NULL) return resp_http_error(conn);

    if(req->type == TYPE_GET && req->query == NULL) //return upgrade info
    	return resp_upgrade_info(conn, upload);

    if(req->type == TYPE_GET && req->query != NULL){
  		param=strtok((char*)req->query,"&");     //read request query string
  		if( os_memcmp(param,"action=",7) == 0 ){
  			action = strchr(param,'=')+1;

  			if( os_strcmp(action,"reboot") == 0){ //FOTA reboot
  				os_printf("FOTA reboot\n");
  				resp_http_ok(conn);
  				system_upgrade_flag_set(UPGRADE_FLAG_FINISH);
  				system_upgrade_reboot();
  				return;
  			}
  		}
    }

    if( req->type == TYPE_POST  && req->read_state == REQ_GOT_HEADER ){
    	f_info.accept_file_ext = ".bin";
    	f_info.accept_cont_type = "application/octet-stream";
    	fw_bin    = system_upgrade_userbin_check();
    	flash_map = system_get_flash_size_map();
		os_printf("fw app bin: %s upgrade flash map %d\n", fw_bin?"APP1":"APP2", flash_map);

		switch(flash_map){
			case FLASH_SIZE_4M_MAP_256_256:
			case FLASH_SIZE_2M:
				resp_http_error(conn); //FOTA not supported
				return;
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
				break;
		}

    	upload = (upload_state_t*)os_zalloc(sizeof(upload_state_t));
    	if(upload == NULL) return resp_http_error(conn);

		upload->flash  = (flash_upload_t*)os_zalloc(sizeof(flash_upload_t));
		if(upload->flash == NULL) return resp_http_error(conn);

    	upload->boundary = get_bound(req->content_type);
    	if(upload->boundary == NULL) return resp_http_error(conn);

		upload->f_info = &f_info;
    }
    content_upload(req->content, req->cont_part_len, upload, req->cont_bytes_left);

    if(req->cont_bytes_left == 0){
    	upload->f_info->upload_size = upload->flash->wr;
		os_printf("firmware upload(%d bytes) %s\n", upload->f_info->upload_size, (upload->state==UPLOAD_COMPLETE)?("OK"):("ERR"));
		resp_upgrade_info(conn, upload);
		os_free(upload->flash);
		os_free(upload);
    }
}
