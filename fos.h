#ifndef __FOS_H__
#define __FOS_H__
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include<sys/types.h> //! Types Aliass
#include<net/ethernet.h>
#include<unistd.h>
#include<net/if.h>
#include<net/if_media.h>
#include<string.h>
#include<errno.h>
#include<stdbool.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <assert.h>
#include <sys/reboot.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <json-c/json_object_iterator.h>
#include <openssl/hmac.h>
#include <sys/reboot.h>
#include <strings.h>
#include <yaml.h>
#include <openssl/sha.h>
#include <time.h>
#include <libusb.h>
#include <ctype.h>


#define FOS_VERSION "1.2"
#define FOS_VER_DATE "25-04-2024"

#define MIN_RANGE_DELAY 40
#define MAX_RANGE_DELAY 70
#define INTERNET_CHECK_HOST "pool.ntp.org"
#define MAX_TRIES 3
#define MAX_VALUE_SIZE 32
#define MAX_RESPONSE_SIZE 1024 * 2
#define MAX_POSSIBLE_LAYER2_ADDR      100
#define SINGLE_LAYER2_ADDR_SIZE_BYTES 20
#define TOTAL_FILE_SIZE               MAX_POSSIBLE_LAYER2_ADDR * SINGLE_LAYER2_ADDR_SIZE_BYTES
#define SUCCESS_COUNT                 2
#define FOS_PROTO_VENDOR_ID 0x0483
#define FOS_PROTO_VENDOR_STRING "ThingzEye"
#define FOS_PROTO_PRODUCT_ID 0x5740
#define FOS_PROTO_PRODUCT_STRING "SecurityKey"
//! Frame Properties
#define FOS_PROTO_SECURITY_KEY_MAGIC_H 0xCC
#define FOS_PROTO_SECURITY_KEY_MAGIC_L 0xDD
#define FOS_PROTO_QUERY_KEY_REQ_TYPE  0x6B
#define FOS_PROTO_QUERY_KEY_RESP_TYPE 0x73
//! USB Endpoints
#define BULK_EP_OUT     0x81
#define BULK_EP_IN      0x01

char LAYER2_VERIFICATION_URL[200];

//cc .c -o b -lcrypto -ljson-c -lcurl -lyaml -L/usr/local/lib -I/usr/local/include

typedef struct{
    char key[5];
        char layer2[MAX_VALUE_SIZE+MAX_VALUE_SIZE+1];
}Layer2StringAddress_t;
typedef struct{
        struct libusb_device* _device;
        struct libusb_device_handle* _device_handle;
        struct libusb_endpoint_descriptor* _ep_desc;
        int _interface_no;
        int _alt_interface;
}SecurityKey_t;
//! Prototypes

int FOS_load_all_layer2_address(Layer2StringAddress_t*, size_t*);
int FOS_calc_key(const uint8_t*, uint16_t*);
int FOS_toJSON(Layer2StringAddress_t*, size_t,char*);
int FOS_auth_and_fetch_init(const char*,const char*,char*);
int FOS_json_to_layer2_address(const char*, Layer2StringAddress_t*, size_t*);
int FOS_fjson_to_layer2_address(const char*, Layer2StringAddress_t*, size_t*);
int FOS_calc_digest(uint8_t*,unsigned int,uint8_t*,unsigned int, uint8_t*,unsigned int*);
int FOS_Verify_Integrity(Layer2StringAddress_t*, size_t,Layer2StringAddress_t*, size_t);
int FOS_read_and_parse_yaml(const char*, char*);
bool FOS_is_conn_cap(void);
int FOS_SecurityKey_isConnected(libusb_context*,SecurityKey_t*);
int FOS_SecurityKey_WriteFrame(SecurityKey_t*, uint8_t*, uint8_t);
int FOS_SecurityKey_ReadFrame(SecurityKey_t*, uint8_t*, uint8_t, int*);
uint16_t FOS_SecurityKey_CRC16(uint8_t*, uint8_t);
int FOS_SecurityKey_QueryKey(SecurityKey_t*,uint8_t*);
int FOS_SecurityKey_CheckResp(SecurityKey_t*,uint8_t*, char*);
int FOS_SecurityKey_Authenticate(const char*);
int FOS_LoadUserSecret(const char*, char*);
void FOS_DisplayLANConfigurationMenu(void);
int FOS_Killer(char arg1[], char arg2[]);
#endif
