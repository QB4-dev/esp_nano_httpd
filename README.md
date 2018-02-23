# esp_nano_httpd
Yet another simple and minimalistic webserver for ESP8266

## Why do You need it?
In almost all your ESP8266 projects you need to setup WiFi connection parameters(SSID, password) to connect with your home router.
Hardcoding this parameters is definitely not a good idea. If you change router settings, or even take your device somewhere else you will need to recompile your code - sounds bad isn't it?

__esp_nano_httpd__ will help you ( ͡° ͜ʖ ͡°) 

## esp_nano_httpd features:
* small and easy to use - all you need to do is to copy __esp_nano_httpd__ directory into your project source, configure urls, and start it!
* designed to host minimalistic html interfaces - use it to host simple html pages to setup WiFi connection with your home router, create web browser user interface to control your device, or to handle and send data by CGI-like functions.

Thats all - its only simple and robust webserver. If you need more features like image hosting, web sockets and so on use fantastic libesphttpd by Sprite_tm.

## OK I like it, it's enough for me. How to use it?
1. Copy __esp_nano_httpd__ and __html__ directory into your project source directory.

2. Add __esp_nano_httpd__ module to be compiled in __Makefile__ (I recommend to use [this Makefile template for NONOS SDK projects](https://gist.github.com/QB4-dev/4081a836f87c80fa66e3dfd521e8ad5a))

```Makefile
# which modules (subdirectories) of the project to include in compiling
MODULES	= driver user esp_nano_httpd
```
3. Include __esp_nano_httpd.h__ header file in your __user_main.c__ file or wherever you need it.
```c
#include "../esp_nano_httpd/esp_nano_httpd.h
```
4. In __user_config.h__ define the name of WiFi Access Point when ESP8266 device is working as AP(in config mode for example) 
```c
#define NANO_HTTPD_AP_NAME "MY-ESP-DEV"
```
> __NOTE:__ Two last bytes of your ESP8266 device MAC address will be added at the end of AP name to create unique AP names for multiple ESP8266 devices.  
> For example:  
> #define NANO_HTTPD_AP_NAME __"ESP-LED"__  
>
> - device 1 AP name: __ESP-LED-13DF__  
> - device 2 AP name: __ESP-LED-C0A1__  
>  ...  
> - device x AP name: __ESP-LED-XXXX__  

5. Now it's time to prepare our HTML content...  
If you ever tried manually include HTML code inside C file you know the pain when you mixing two programming languages - all damn backslashes before quotation marks, no web browser preview, etc. (╯°□°）╯︵ ┻━┻  
Not this time... I'll show you the trick ( ͡~ ͜ʖ ͡°)  
...  
Go to __html__ directory. Add there your html files. You will find small and handy shell script __gen_includes.sh__
It will create C header files in __include__ directory from your html files by using Linux __xxd__ tool. Just use it!

6. Okay. We have our html content easy to include into C code, and __esp_nano_httpd__ . Lets connect them together.  
Create url config table inside your __user_main.c__ file:  
```c
#include "../esp_nano_httpd/esp_nano_httpd.h //to use esp_nano_httpd"

//include your html pages here
#include "../html/include/index.h" 
#include "../html/include/about.h"

//and create URL config table
const http_callback_t url_conf[] = {
    {"/", send_html, index_html, sizeof(index_html)},
    {"/about", send_html, about_html, sizeof(about_html)},
    {0,0,0,0} //last item always 0
};
```  
`const http_callback_t url_conf[]` explained:

| __server path__ | __callback function___ | __callback arg__  | __callback arg lenght__ |
| --------------- |:----------------------:| -----------------:| -----------------------:|
| "/"             | send_html              | index_html        | sizeof(index_html)      |
| "/about"        | send_html              | about_html        | sizeof(about_html)      |

- __server path__ - http request server path. When internet browser comunicates with ESP8266 device sends HTTP requests to *ESP_IP*__/path__ .  
__"/"__ is device root path. When you simply type *ESP_IP* for example http://192.168.4.1 into your web browser address bar it will request device root path and ESP device will respond by sending to the browser __index.html__ page.  
If you want to access some other pages by path add it after *ESP_IP* address. To see __about.html__ page type *ESP_IP*__/about__ for eg. http://192.168.4.1/about  
- __callback function___  - this function is called when ESP8266 device will recieve HTTP request with matching __server path__  
In this example We are using `send_html` function from __esp_nano_httpd__ API to make things easy. You can use your own callback functions, to do device function, or send json data etc. (see below).  
- __callback arg__  - calllback function argument passed to __callback function___ in this example its html page code in array index_html.  
- __callback arg lenght__ - calllback function argument length. __callback arg__ is not always null terminated string, it might be binary data, and sender needs to know its's length.  

7. Now it's time to tell __esp_nano_httpd__ how to handle requests:
```c
esp_nano_httpd_register_content(url_conf);
```
and start it when needed:
```c
esp_nano_httpd_init(STATIONAP_MODE); //when used as AP
//or
esp_nano_httpd_init(STATION_MODE);  //when used as router client
```  

## Using esp_nano_httpd:
The moment and mode when you need to init  __esp_nano_httpd__ is dependent on your application.
Typical workflow is:
- __esp_nano_httpd__ is called with __STATIONAP_MODE__ when you need to setup your device options at first time run, or reconfigure the device(for example by setting ESP8266 device into config mode when button is pressed for 5s).

and/or

- __esp_nano_httpd__ is called with __STATION_MODE__ when you need to always have access to your device special functions via web browser (for example setting GPIO, playing sounds etc)

## esp_nano_httpd API:  

`void esp_nano_httpd_register_content(const http_callback_t *content_info)` - used to pass to the __esp_nano_httpd__ bullit in URL table with callback functions.  

`void esp_nano_httpd_init(uint8_t wifi_mode)` - used to initialize  __esp_nano_httpd__ web server. 
- When `wifi_mode` = __STATIONAP_MODE__ - ESP8266 will create an open Access Point with SSID defined by `NANO_HTTPD_AP_NAME` in __user_config.h__  
- When `wifi_mode` = __STATION_MODE__ - ESP8266 will only create server and listen HTTP requests on port 80.

### Some useful functions to write CGI - like request callbacks: 
`void send_http_response(struct espconn *conn, const char *code, const char *cont_type, const char *content, uint32_t cont_len)` - used to send various HTTP response types.
- `struct espconn *conn` - pointer to current connection structure
- `const char *code` - response HTTP status code 
- `const char *cont_type` - response content type
- `const char *cont` - pointer to response content 
- `uint32_t cont_len` - response content length

`void send_html(struct espconn *conn, http_request_t *req, void *arg, uint32_t len)` - send HTML page(basic callback function - more details below)

`void resp_http_ok(struct espconn *conn)` - send HTTP OK status(status code: 200)

`void resp_http_404(struct espconn *conn)` - send HTTP Not Found status status(status code: 404)

`void resp_http_error(struct espconn *conn)` - send HTTP Internal Error status(status code: 500)

## Writing callback functions
Until now We know how to use __esp_nano_httpd__ to send our html files only. Here is how to write other functions that will handle another requests, and allow us to make some real actions on ESP8266 device like changing options, setting GPIOs, controling peripherials, reading sensors on web browser user demand.

### callback function prototype explained:

All callback functions should be designed like:
```c
void ICACHE_FLASH_ATTR http_callback_fun(struct espconn *conn, http_request_t *req, void *arg, uint32_t len)
{
}
```
Input arguments:
- `struct espconn *conn` - current TCP connection. It is used to point where to send requested data. 
- `http_request_t *req` - received and parsed HTTP request. Defined in __esp_nano_httpd.h__

Use it to check what type of request has been received, read request path, query string, and content
```c
typedef struct {
    enum req_type {
        TYPE_UNKNOWN = 0,
        TYPE_GET     = 1,
        TYPE_POST    = 2
    } type; 
    const char* path;
    const char* query;

    const char* content_type;
    uint32_t content_len;
    void *content;
} http_request_t;
```

- `void *arg` - callback function argument. It might be any data used in callback function. It might be pointer to LED driver, because this callback function is used to setup RGB led color, HTML page as in __html_send()__ function.

- ` uint32_t len` - callback function argument length in bytes

### Basic http request callback function
This example callback is used to change wifi station settings:
```c
#include "../html/include/wifi_connect_html.h" //here is our wifi connection status page

void ICACHE_FLASH_ATTR wifi_config_cb(struct espconn *conn, http_request_t *req, void *arg, uint32_t len)
{
    struct station_config station_conf = {0};
    static os_timer_t reboot_timer;
    char *param;

    //We only handle POST requests
        if(req->type != TYPE_POST || req->content == NULL){    
        resp_http_error(conn);
        return;
    }
    /* in request content We expect serialized input form query like: ssid=MY_SSID&passwd=MY_PASSWD
    Use strtok to divide query into tokens*/
    param=strtok(req->content,"&");
    do {
        if( os_memcmp(param,"ssid=",5) == 0 )         //ssid value found
            ets_strncpy(station_conf.ssid, strchr(param,'=')+1,32);
        else if( os_memcmp(param,"passwd=",7) == 0 )  //password value found
            ets_strncpy(station_conf.password, strchr(param,'=')+1,64);
    } while( (param=strtok(NULL,"&")) != NULL);

    station_conf.bssid_set = 0;               //do not look for specific router MAC address
    wifi_station_set_config(&station_conf);   //save new WiFi settings

    send_html(conn, wifi_connect_html, sizeof(wifi_connect_html)); //show HTML page
}
```  
Next we need to add the `<form>` in our __index.html__ file to get WiFi SSID and password:
```html
<p><strong>WiFi configuration:<strong></p>
<form method="post" action="/wifi_conf">
SSID<br>
<input type="text" name="ssid" pattern="[A-Za-z0-9]{1,32}" required="required" title="Access Point name"><br>
password<br>
<input type="text" name="passwd" pattern="^\S{0,64}$" title="password 0-64 characters"><br>
<input type="submit" value="WiFi connect">
</form>
```

When function is ready all you need to do is to connect it to path in __url_config__ in __user_main.c__
```c
const http_callback_t url_conf[] = {
    {"/", send_html, index_html, sizeof(index_html)},
    {"/about", send_html, about_html, sizeof(about_html)},
    {"/wifi_conf", wifi_config_cb, NULL, 0 },
    {0,0,0,0} //last item always 0
};
```




