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


#ifndef ESP_NANO_HTTPD_WIFI_UTIL_H_
#define ESP_NANO_HTTPD_WIFI_UTIL_H_

#include <c_types.h>
#include <user_interface.h>

/*
This callback is used to configure ESP8266 WiFi settings.
To use it add something like below in esp_nano_httpd URL table:
const http_callback_t url_cfg[] = {
	{"/wifi", wifi_callback, NULL, 0},
	{0,0,0,0}
};

Supported actions(CGI like) very handy for javascript  xhttp requests
GET  request: /wifi		return current connection info
GET  request: /wifi?action=scan	scan for available networks
POST request: /wifi		connect to network(POST request content: ssid=MY_SSID&passwd=MY_PASSWD)
GET  request: /wifi?action=save	save current WiFi config

Example response data(json format):
{
	"conn":"GOT_IP",
	"SSID":"Dom",
	"addr":"",
	"save":"",
	"scan":[
		{"ssid":"Dom","auth":"WPA-PSK/WPA2-PSK","rssi":-71},
		{"ssid":"PENTAGRAM_P_6351","auth":"OPEN","rssi":-35}
	]
}
*/
void wifi_callback(struct espconn *conn, void *arg, uint32_t len);

#endif /* ESP_NANO_HTTPD_WIFI_UTIL_H_ */
