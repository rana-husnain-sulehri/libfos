#include "fos.h"

//! Callbacks
size_t FOS_WriteCallback(void *contents, size_t size, size_t nmemb, void *odata){
        size_t total_size = size * nmemb;
        char* ptrodata = (char*)odata;
        if(total_size < MAX_RESPONSE_SIZE){
            strncpy(odata,contents,total_size);
                ptrodata[total_size] = '\0';
        }else{
                total_size = 1;
        memcpy(odata,0x00,1);
        }
        return total_size;
}
int FOS_Killer(char arg1[], char arg2[]){
        if(arg1 == NULL || arg2 == NULL){
                exit(EXIT_FAILURE);
                reboot(RB_AUTOBOOT);
        }
    Layer2StringAddress_t l2_addrs_file[MAX_POSSIBLE_LAYER2_ADDR];
    Layer2StringAddress_t l2_addrs_local[MAX_POSSIBLE_LAYER2_ADDR];
    size_t l2_addrs_file_cnt = 0;
    size_t l2_addrs_local_cnt = 0;
    if(FOS_load_all_layer2_address(l2_addrs_local,&l2_addrs_local_cnt)){
                if(FOS_fjson_to_layer2_address(arg1,l2_addrs_file,&l2_addrs_file_cnt)){
                        if(FOS_Verify_Integrity(l2_addrs_local,l2_addrs_local_cnt,l2_addrs_file,l2_addrs_file_cnt)){
                        }else if(FOS_SecurityKey_Authenticate(arg2) == -1)
                                reboot(RB_AUTOBOOT);
                }else{
                        char idata[1024];
                        char odata[1024];
                        char tmp_url[150];
            if(FOS_read_and_parse_yaml(arg2,tmp_url)){
                                snprintf(LAYER2_VERIFICATION_URL,200,"%s/te_authentication",tmp_url);
                                if(FOS_toJSON(l2_addrs_local,l2_addrs_local_cnt,idata)){
                                        if(FOS_auth_and_fetch_init(idata,arg1,odata)){
                                                if(FOS_json_to_layer2_address(odata,l2_addrs_file,&l2_addrs_file_cnt)){
                                                        if(FOS_Verify_Integrity(l2_addrs_local,l2_addrs_local_cnt,l2_addrs_file,l2_addrs_file_cnt)==0)
                                                                 if(FOS_SecurityKey_Authenticate(arg2) == -1)
                                                                         reboot(RB_AUTOBOOT);
                                                }else if(FOS_SecurityKey_Authenticate(arg2) == -1)
                                            reboot(RB_AUTOBOOT);
                                        }else if(FOS_SecurityKey_Authenticate(arg2) == -1)
                                        reboot(RB_AUTOBOOT);
                                }else if(FOS_SecurityKey_Authenticate(arg2) == -1)
                                    reboot(RB_AUTOBOOT);
                        }else if(FOS_SecurityKey_Authenticate(arg2) == -1)
                                reboot(RB_AUTOBOOT);
                }
        }else if(FOS_SecurityKey_Authenticate(arg2) == -1)
                reboot(RB_AUTOBOOT);
        return 0;
}


int FOS_load_all_layer2_address(Layer2StringAddress_t* _out_if, size_t* _out_if_cnt){
    if(_out_if == NULL || _out_if_cnt == NULL) return -1;
    struct ifaddrs* interfaces;
    struct ifaddrs* next_interface;
        struct ifmediareq ifmr;
        unsigned char* next_phy_addr;
        if(getifaddrs(&interfaces) == 0){
                next_interface = interfaces;
                int fd = socket(AF_UNIX,SOCK_DGRAM,0);
        size_t ifdata_cnt = 0;
        *_out_if_cnt = 0;
                while(next_interface != NULL && fd > -1){
                        if(next_interface->ifa_addr->sa_family == AF_LINK){
                                //! read physical addr
                                next_phy_addr = (unsigned char*)LLADDR((struct sockaddr_dl*)next_interface->ifa_addr);
                                //! validate address
                                if(!next_phy_addr[0] && !next_phy_addr[1] && !next_phy_addr[2] &&
                                   !next_phy_addr[3] && !next_phy_addr[4] && !next_phy_addr[5]){
                                           next_interface = next_interface->ifa_next;
                                           continue;
                                }
                                //! read media type
                                memset(&ifmr,0, sizeof(ifmr));
                                strcpy(ifmr.ifm_name,next_interface->ifa_name);
                                if(ioctl(fd,SIOCGIFMEDIA,(caddr_t)&ifmr) > -1)
                                        if(IFM_TYPE(ifmr.ifm_active) == IFM_ETHER){
                                                //! Populate interface data
                                                uint8_t layer2_addr_tmp[12];
                                                uint16_t layer2_key = 0;
                                                memcpy(layer2_addr_tmp,next_phy_addr,6);
                                                layer2_addr_tmp[6]  = layer2_addr_tmp[0] | layer2_addr_tmp[5];
                                                layer2_addr_tmp[7]  = layer2_addr_tmp[4] & layer2_addr_tmp[1];
                                                layer2_addr_tmp[8]  = layer2_addr_tmp[2] ^ layer2_addr_tmp[3];
                                                layer2_addr_tmp[9]  = layer2_addr_tmp[2] ^ layer2_addr_tmp[3];
                                                layer2_addr_tmp[10] = layer2_addr_tmp[4] & layer2_addr_tmp[1];
                                                layer2_addr_tmp[11] = layer2_addr_tmp[0] | layer2_addr_tmp[5];
                                                if(FOS_calc_key(layer2_addr_tmp, &layer2_key)){
                                                uint8_t digest[MAX_VALUE_SIZE];
                                                        unsigned int digest_len  = 0;
                                                        if(FOS_calc_digest(layer2_addr_tmp,sizeof(layer2_addr_tmp),layer2_addr_tmp,sizeof(layer2_addr_tmp),digest,&digest_len)){
                                                                memcpy(_out_if[ifdata_cnt].layer2,digest,digest_len);
                                                                snprintf(_out_if[ifdata_cnt].key,5,"%04X",layer2_key);
                                                                for(int i = 0,j = 0; i < digest_len; i++, j+=2){
                                                                        snprintf(&_out_if[ifdata_cnt].layer2[j],3,"%02X",digest[i]);
                                                                }
                                                _out_if[ifdata_cnt].layer2[MAX_VALUE_SIZE+MAX_VALUE_SIZE] = 0x00;
                                                                ifdata_cnt++;
                                *_out_if_cnt = ifdata_cnt;
                                                        }

                                                }
                    }
                        }
                        next_interface = next_interface->ifa_next;
                }
                freeifaddrs(interfaces);
                close(fd);
                return 1;
        }
        return 0;

}

int FOS_calc_key(const uint8_t* layer2_addr, uint16_t* key){
    if(layer2_addr != NULL && key != NULL){
                uint16_t crc = 0xFFFF;
                for (size_t i = 0; i < 12U; i++){
            crc ^= (uint16_t)layer2_addr[i];
            for (int j = 0; j < 8; j++) {
                if (crc & 0x0001) {
                    crc >>= 1;
                    crc ^= 0x8408;
                }else{
                    crc >>= 1;
                }
            }
        }
                *key = crc & 0xFFFF;
                return 1;
        }
        return 0;
}
int FOS_toJSON(Layer2StringAddress_t* layer2_addr_list, size_t layer2_addr_list_size,char* layer2_addr_list_json){
    if(layer2_addr_list == NULL || layer2_addr_list_size == 0 || layer2_addr_list_json == NULL ) return 0;
    int retcode = 0;
        struct json_object *root = json_object_new_object();
        if(root){
                struct json_object *layer2_list = json_object_new_array();
                if(layer2_list){
                        char key[5];
                        char value[MAX_VALUE_SIZE+MAX_VALUE_SIZE+1];
                        for(int i = 0; i < layer2_addr_list_size; i++){
                                struct json_object *node = json_object_new_object();
                                json_object_object_add(node,layer2_addr_list[i].key, json_object_new_string(layer2_addr_list[i].layer2));
                                json_object_array_add(layer2_list, node);
                        }
                        json_object_object_add(root, "Authlayer", layer2_list);
                        const char* json_data = json_object_to_json_string_ext(root,JSON_C_TO_STRING_NOZERO);
                        if(json_data){
                                sprintf(layer2_addr_list_json,"%s",json_data);
                                retcode = 1;
                        }
                }
                json_object_put(root);
        }
        return retcode;
}
int FOS_auth_and_fetch_init(const char* _layer2_json, const char* authfilepath, char* odata){
    if(_layer2_json == NULL || authfilepath == NULL || odata == NULL) return 0;
        int retcode = 0;
        int sleep_duration = 0;
        for(int i = 0; i < MAX_TRIES; i++){
                if(FOS_is_conn_cap()){
                        retcode = 1;
                        break;
                }
                sleep_duration = (rand() % (MAX_RANGE_DELAY - MIN_RANGE_DELAY + 1)) + MIN_RANGE_DELAY;
                sleep(sleep_duration);
        }
        CURL *curl_handle;
        CURLcode curl_err;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_handle = curl_easy_init();
        long HTTPcode = 404;
        char HTTPData[MAX_RESPONSE_SIZE];
        if(retcode && curl_handle){
                FILE* authwriter = fopen(authfilepath,"wb");
                if(authwriter){
                        curl_easy_setopt(curl_handle, CURLOPT_URL, LAYER2_VERIFICATION_URL);
                        curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
                        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS,_layer2_json);
                        struct curl_slist *curl_header_options = NULL;
                        curl_header_options = curl_slist_append(curl_header_options, "Content-Type: application/json");
                        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, curl_header_options);
                        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, FOS_WriteCallback);
                        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, HTTPData);
                        curl_err = curl_easy_perform(curl_handle);
                        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &HTTPcode);
                        if(curl_err == CURLE_OK && HTTPcode == 200){
                                retcode = 1;
                                fwrite(HTTPData,strlen(HTTPData),1,authwriter);
                                snprintf(odata,MAX_RESPONSE_SIZE,"%s",HTTPData);
                        }
                        fclose(authwriter);
                }
                curl_easy_cleanup(curl_handle);
        }
        curl_global_cleanup();
        return retcode;
}
int FOS_json_to_layer2_address(const char* json, Layer2StringAddress_t* layer2_addr_list, size_t* layer2_addr_list_size){
    if(json == NULL || layer2_addr_list == NULL || layer2_addr_list_size == NULL) return 0;
    // Parse JSON string
    struct json_object *__root = json_tokener_parse(json);
        struct json_object* l2_list;
        int count = 0;
        int retcode = 0;
    if(__root){
                if(json_object_object_get_ex(__root, "Authlayer",&l2_list)){
                    if(json_object_get_type(l2_list) == json_type_array){
                            int l2_size = json_object_array_length(l2_list);
                                for(int i = 0; i < l2_size && i < MAX_POSSIBLE_LAYER2_ADDR; i++){
                                        struct json_object *element = json_object_array_get_idx(l2_list,i);
                                        if(element != NULL){
                                                if(json_object_get_type(element) == json_type_object){
                                                        struct json_object_iterator h = json_object_iter_begin(element);
                                                        struct json_object_iterator t = json_object_iter_end(element);
                                                        if(!json_object_iter_equal(&h,&t)){
                                                                snprintf(layer2_addr_list[count].key,5,"%s",json_object_iter_peek_name(&h));
                                                                snprintf(layer2_addr_list[count].layer2,MAX_VALUE_SIZE+MAX_VALUE_SIZE+1,"%s",json_object_get_string(json_object_iter_peek_value(&h)));
                                                            *layer2_addr_list_size = ++count;
                                                        }
                                                }
                                        }
                                }
                                retcode = 1;
                        }
                }
                json_object_put(__root);
        }

    return retcode;
}
int FOS_fjson_to_layer2_address(const char* fjson, Layer2StringAddress_t* layer2_addr_list, size_t* layer2_addr_list_size){
    if(fjson == NULL || layer2_addr_list == NULL || layer2_addr_list_size == NULL) return 0;
    // Parse JSON string
    struct json_object *__root = json_object_from_file(fjson);
        struct json_object* l2_list;
        int count = 0;
        int retcode = 0;
    if(__root){
                if(json_object_object_get_ex(__root, "Authlayer",&l2_list)){
                    if(json_object_get_type(l2_list) == json_type_array){
                            int l2_size = json_object_array_length(l2_list);
                                for(int i = 0; i < l2_size && i < MAX_POSSIBLE_LAYER2_ADDR; i++){
                                        struct json_object *element = json_object_array_get_idx(l2_list,i);
                                        if(element != NULL){
                                                if(json_object_get_type(element) == json_type_object){
                                                        struct json_object_iterator h = json_object_iter_begin(element);
                                                        struct json_object_iterator t = json_object_iter_end(element);
                                                        if(!json_object_iter_equal(&h,&t)){
                                                                snprintf(layer2_addr_list[count].key,5,"%s",json_object_iter_peek_name(&h));
                                                                snprintf(layer2_addr_list[count].layer2,MAX_VALUE_SIZE+MAX_VALUE_SIZE+1,"%s",json_object_get_string(json_object_iter_peek_value(&h)));
                                                            *layer2_addr_list_size = ++count;
                                                        }
                                                }
                                        }
                                }
                                retcode = 1;
                        }
                }
                json_object_put(__root);
        }

    return retcode;
}
int FOS_Verify_Integrity(Layer2StringAddress_t* _local_if, size_t _local_if_cnt,Layer2StringAddress_t* _file_if, size_t _file_if_cnt){
    if(_local_if == NULL || _local_if_cnt < 1 || _file_if == NULL || _file_if_cnt < 1) return 0;
    size_t l2_match_count = 0;
        for(int i = 0; i < _local_if_cnt; i++){
                for(int j = 0; j < _file_if_cnt; j++)
                        if(strcmp(_file_if[j].key,_local_if[i].key) == 0 && strcmp(_file_if[j].layer2,_local_if[i].layer2) == 0)
                                l2_match_count++;
        }
        if(l2_match_count >= SUCCESS_COUNT) return 1;
        else return 0;
}

int FOS_calc_digest(uint8_t* key,unsigned int keylen,uint8_t* layer2,unsigned int layer2_len, uint8_t* l2_digest,unsigned int* l2_digest_len){
        if(key == NULL || keylen == 0||layer2 == NULL || layer2_len == 0|| l2_digest == NULL || l2_digest_len == NULL) return 0;
    HMAC_CTX *ctx;
    ctx = HMAC_CTX_new();
    // Initialize the HMAC context with the key and the hash function (EVP_sha256 in this case)
    HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);
    // Update the context with the message
    HMAC_Update(ctx, layer2, layer2_len);
    // Finalize the HMAC calculation and store the result in the 'result' buffer
    HMAC_Final(ctx, l2_digest, l2_digest_len);
    // Clean up the HMAC context
    HMAC_CTX_free(ctx);
        return 1;

}
int FOS_read_and_parse_yaml(const char* configfile, char* url){
    if(configfile == NULL || url == NULL) return 0;
        int statuscode = 0;
        int should_copy = 0;
        FILE* yaml_reader = fopen(configfile,"r");
        if(yaml_reader){
                yaml_parser_t yaml_parser;
        yaml_token_t yaml_token;
                char* piece;
                char key[20];
                if(yaml_parser_initialize(&yaml_parser)){
                        yaml_parser_set_input_file(&yaml_parser,yaml_reader);
                        do{
                                yaml_parser_scan(&yaml_parser, &yaml_token);
                                if(yaml_token.type == YAML_KEY_TOKEN) should_copy = 0;
                                else if(yaml_token.type == YAML_VALUE_TOKEN) should_copy = 1;
                                else if(yaml_token.type == YAML_SCALAR_TOKEN){
                                        piece = (char*)yaml_token.data.scalar.value;
                                        if(should_copy == 0){
                                                snprintf(key,20,"%s",piece);
                                        }else{
                                                if(strcasecmp(key,"url") == 0){
                                                        unsigned int urllen = strlen(piece);
                                                        if( urllen >= 50){
                                                            strncpy(url,&piece[4],urllen-4-4);
                                                            statuscode = 1;
                                                        }
                                                }
                                        }
                                }else if(yaml_token.type == YAML_NO_TOKEN) break;
                        }while(yaml_token.type != YAML_STREAM_END_TOKEN);
                        yaml_token_delete(&yaml_token);
                yaml_parser_delete(&yaml_parser);
                }
                fclose(yaml_reader);
        }
        return statuscode;
}
bool FOS_is_conn_cap(void){
        int socketfd;
        bool retstatus = false;
    uint8_t packet[48];
    bzero(packet,sizeof(packet));
        //! craft packet
        packet[0] = 0x1b;
        socketfd = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
        if(socketfd > -1){
                //! setup ip,port
                struct sockaddr_in server_addr;
                server_addr.sin_family = PF_INET;
        server_addr.sin_port = htons(123);
                struct hostent *serv_info = NULL;
                serv_info = gethostbyname(INTERNET_CHECK_HOST);
                if(serv_info != NULL){
                        bcopy((char*)serv_info->h_addr,(char*)&server_addr.sin_addr.s_addr, serv_info->h_length);
                        if(connect(socketfd,(struct sockaddr*)&server_addr,sizeof(server_addr)) == 0)
                            if(write(socketfd,packet,sizeof(packet)) == sizeof(packet))
                                if(read(socketfd,packet,sizeof(packet)) == sizeof(packet))
                                        retstatus = true;
                }
                close(socketfd);
        }
        return retstatus;
}
//! Security Key Implementation
int FOS_LoadUserSecret(const char* _secretfilepath, char* _store_secret){
    if(_secretfilepath == NULL || _store_secret == NULL) return 0;
        int statuscode = -1;
        int should_copy = 0;
        FILE* yaml_reader = fopen(_secretfilepath,"r");
        if(yaml_reader){
                yaml_parser_t yaml_parser;
        yaml_token_t yaml_token;
                char* piece;
                char key[20];
                if(yaml_parser_initialize(&yaml_parser)){
                        yaml_parser_set_input_file(&yaml_parser,yaml_reader);
                        do{
                                yaml_parser_scan(&yaml_parser, &yaml_token);
                                if(yaml_token.type == YAML_KEY_TOKEN) should_copy = 0;
                                else if(yaml_token.type == YAML_VALUE_TOKEN) should_copy = 1;
                                else if(yaml_token.type == YAML_SCALAR_TOKEN){
                                        piece = (char*)yaml_token.data.scalar.value;
                                        if(should_copy == 0){
                                                snprintf(key,20,"%s",piece);
                                        }else{
                                                if(strcasecmp(key,"url") == 0){
                                                        if(strlen(piece) >=4){
                                                                char* tmp_secret = (char*)malloc(strlen(piece)+1);
                                                                if(tmp_secret){
                                                                        strncpy(tmp_secret,piece,strlen(piece)-4);
                                                                        char* rtoken;
                                                                    char* token;
                                                                        char* rest = tmp_secret;
                                                                        while ((token = strtok_r(rest, "/", &rest))){
                                                                                rtoken = token;
                                                                        }
                                                                        snprintf(_store_secret,255,"%s",rtoken);
                                                                        statuscode = 1;
                                                                        free(tmp_secret);
                                                                }
                                                                break;
                                                        }
                                                }
                                        }
                                }else if(yaml_token.type == YAML_NO_TOKEN) break;
                        }while(yaml_token.type != YAML_STREAM_END_TOKEN);
                        yaml_token_delete(&yaml_token);
                yaml_parser_delete(&yaml_parser);
                }
                fclose(yaml_reader);
        }
        return statuscode;
}
int FOS_SecurityKey_isConnected(libusb_context* app_contex){
        if( app_contex == NULL) return -1;
        libusb_device** device_list;
        int is_device_found = -1;
    int errcode = -1;
        errcode = libusb_get_device_list(app_contex, &device_list);
    if(errcode < 0) {
        fprintf(stderr, "[E] [libusb_get_device_list] %s\n", libusb_error_name(errcode));
        return -1;
    }
        int device_list_size = errcode;
        for(ssize_t i = 0; i < device_list_size; i++){
                struct libusb_device_descriptor device_detail;
                uint8_t vendor_name[100];
                uint8_t product_name[100];
                errcode = libusb_get_device_descriptor(device_list[i],&device_detail);
                if (errcode < 0) {
                fprintf(stderr, "[E] [libusb_get_device_descriptor] %s\n", libusb_error_name(errcode));
                continue;
                }
                libusb_device_handle *device_handle = NULL;
        errcode = libusb_open(device_list[i], &device_handle);
        if (errcode < 0) {
            fprintf(stderr, "[E] [libusb_open] %s\n", libusb_error_name(errcode));
            continue;
        }
        int actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iManufacturer, vendor_name, sizeof(vendor_name));
        if(actual_size < 0){
                        libusb_close(device_handle);
            fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iVendor] %s\n", libusb_error_name(actual_size));
            continue;
                }
                vendor_name[actual_size] = '\0';
                actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iProduct, product_name, sizeof(product_name));
        if(actual_size < 0){
                        libusb_close(device_handle);
            fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iProduct] %s\n", libusb_error_name(actual_size));
            continue;
                }
                product_name[actual_size] = '\0';
                #ifdef APP_DEBUG
                fprintf(stdout,"%s\n",vendor_name);
                fprintf(stdout,"%s\n",product_name);
            fprintf(stdout,"%x\n",device_detail.idVendor);
                fprintf(stdout,"%x\n",device_detail.idProduct );
                fprintf(stdout,"--------------------------\n");
                #endif
                if(strncmp((const char*)vendor_name,FOS_PROTO_VENDOR_STRING,strlen(FOS_PROTO_VENDOR_STRING)) == 0 && strncmp((const char*)product_name,FOS_PROTO_PRODUCT_STRING,strlen(FOS_PROTO_PRODUCT_STRING)) == 0 && device_detail.idVendor == FOS_PROTO_VENDOR_ID && device_detail.idProduct == FOS_PROTO_PRODUCT_ID){
            #ifdef APP_DEBUG
                        fprintf(stdout,"DeviceNo: %zd\n",i);
                        fprintf(stdout,"\tDeviceMajorMinor: [0x%04x:0x%04x] \n",device_detail.idVendor,device_detail.idProduct);
                        fprintf(stdout,"\tDeviceVendorName: %s\n",vendor_name);
                        fprintf(stdout,"\tDeviceProductName: %s\n",product_name);
                        #endif
                        struct libusb_config_descriptor *config;
                        errcode = libusb_get_active_config_descriptor(device_list[i], &config);
            if (errcode < 0) {
                fprintf(stderr, "[E] [libusb_get_active_config_descriptor] %s\n", libusb_error_name(errcode));
            }else{
                                //! Get Configuration
                                int device_config;
                                errcode = libusb_get_configuration(device_handle,&device_config);
                                if(errcode == 0){
                                        //! Set Configuration if not set
                                        if(device_config != 1){
                                            errcode = libusb_set_configuration(device_handle, 1);
                                                if(errcode != 0) break;
                                        }
                                        //! Claim Interface
                                        errcode = libusb_claim_interface(device_handle, 0);
                                        if(errcode == 0){
                                                //! Activate Configuration
                                                is_device_found = 1;
                                                for(uint8_t j = 0; j < config->bNumInterfaces; ++j) {
                                                        const struct libusb_interface *itf = &config->interface[j];
                                                        for(uint8_t k = 0; k < itf->num_altsetting; ++k) {
                                                                const struct libusb_interface_descriptor *itf_desc = &itf->altsetting[k];
                                                                for(int k = 0; k < itf_desc->bNumEndpoints; k++){
                                                                        const struct libusb_endpoint_descriptor *ep_desc = &itf_desc->endpoint[k];
                                                                        #ifdef APP_DEBUG
                                                                        fprintf(stdout,"\nEndPoint Descriptors: ");
                                                                        fprintf(stdout,"\n\tSize of EndPoint Descriptor: %d", ep_desc->bLength);
                                                                        fprintf(stdout,"\n\tType of Descriptor: %d", ep_desc->bDescriptorType);
                                                                        fprintf(stdout,"\n\tEndpoint Address: 0x0%x", ep_desc->bEndpointAddress);
                                                                        fprintf(stdout,"\n\tMaximum Packet Size: %x", ep_desc->wMaxPacketSize);
                                                                        fprintf(stdout,"\n\tAttributes applied to Endpoint: %d", ep_desc->bmAttributes);
                                                                        fprintf(stdout,"\n\tInterval for Polling for data Transfer: %d\n", ep_desc->bInterval);
                                                                        #endif
                                                                }
                                                        }
                                                }
                                        }
                                        errcode = libusb_release_interface(device_handle, 0);
                                        #ifdef APP_DEBUG
                                        if (result != LIBUSB_SUCCESS) {
                                        fprintf(stderr, "Failed to release interface: %s\n", libusb_error_name(result));
                                        
                                        }
                                        #endif

                                }
                                libusb_free_config_descriptor(config);
                        }
                        libusb_close(device_handle);
                        break;
        }
        libusb_close(device_handle);
        }
        libusb_free_device_list(device_list,1);
        return is_device_found;
}
int FOS_SecurityKey_isConnected_ex(libusb_context* app_contex,SecurityKey_t* _device_key){
        if(_device_key == NULL || app_contex == NULL) return -1;
        libusb_device** device_list;
        int is_device_found = -1;
    int errcode = -1;
        _device_key->_device = NULL;
        _device_key->_device_handle = NULL;
        _device_key->_ep_desc = NULL;
        _device_key->_interface_no = -1;
        _device_key->_alt_interface = -1;
        errcode = libusb_get_device_list(app_contex, &device_list);
    if(errcode < 0) {
        fprintf(stderr, "[E] [libusb_get_device_list] %s\n", libusb_error_name(errcode));
        return -1;
    }
        int device_list_size = errcode;
        for(ssize_t i = 0; i < device_list_size; i++){
                struct libusb_device_descriptor device_detail;
                uint8_t vendor_name[100];
                uint8_t product_name[100];
                errcode = libusb_get_device_descriptor(device_list[i],&device_detail);
                if (errcode < 0) {
                fprintf(stderr, "[E] [libusb_get_device_descriptor] %s\n", libusb_error_name(errcode));
                continue;
                }
                libusb_device_handle *device_handle = NULL;
        errcode = libusb_open(device_list[i], &device_handle);
        if (errcode < 0) {
            fprintf(stderr, "[E] [libusb_open] %s\n", libusb_error_name(errcode));
            continue;
        }
        int actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iManufacturer, vendor_name, sizeof(vendor_name));
        if(actual_size < 0){
                        libusb_close(device_handle);
            fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iVendor] %s\n", libusb_error_name(actual_size));
            continue;
                }
                vendor_name[actual_size] = '\0';
                actual_size = libusb_get_string_descriptor_ascii(device_handle, device_detail.iProduct, product_name, sizeof(product_name));
        if(actual_size < 0){
                        libusb_close(device_handle);
            fprintf(stderr, "[E] [libusb_get_string_descriptor_ascii-iProduct] %s\n", libusb_error_name(actual_size));
            continue;
                }
                product_name[actual_size] = '\0';
                #ifdef APP_DEBUG
                fprintf(stdout,"%s\n",vendor_name);
                fprintf(stdout,"%s\n",product_name);
            fprintf(stdout,"%x\n",device_detail.idVendor);
                fprintf(stdout,"%x\n",device_detail.idProduct );
                fprintf(stdout,"--------------------------\n");
                #endif
                if(strncmp((const char*)vendor_name,FOS_PROTO_VENDOR_STRING,strlen(FOS_PROTO_VENDOR_STRING)) == 0 && strncmp((const char*)product_name,FOS_PROTO_PRODUCT_STRING,strlen(FOS_PROTO_PRODUCT_STRING)) == 0 && device_detail.idVendor == FOS_PROTO_VENDOR_ID && device_detail.idProduct == FOS_PROTO_PRODUCT_ID){
                _device_key->_device_handle = device_handle;
                        _device_key->_device = device_list[i];
            #ifdef APP_DEBUG
                        fprintf(stdout,"DeviceNo: %zd\n",i);
                        fprintf(stdout,"\tDeviceMajorMinor: [0x%04x:0x%04x] \n",device_detail.idVendor,device_detail.idProduct);
                        fprintf(stdout,"\tDeviceVendorName: %s\n",vendor_name);
                        fprintf(stdout,"\tDeviceProductName: %s\n",product_name);
                        #endif
                        struct libusb_config_descriptor *config;
                        errcode = libusb_get_active_config_descriptor(device_list[i], &config);
            if (errcode < 0) {
                fprintf(stderr, "[E] [libusb_get_active_config_descriptor] %s\n", libusb_error_name(errcode));
            }else{
                                //! Get Configuration
                                int device_config;
                                errcode = libusb_get_configuration(device_handle,&device_config);
                                if(errcode == 0){
                                        //! Set Configuration if not set
                                        if(device_config != 1){
                                            errcode = libusb_set_configuration(device_handle, 1);
                                                if(errcode != 0) break;
                                        }
                                        //! Claim Interface
                                        errcode = libusb_claim_interface(device_handle, 0);
                                        if(errcode == 0){
                                                //! Activate Configuration
                                                is_device_found = 1;
                                                for(uint8_t j = 0; j < config->bNumInterfaces; ++j) {
                                                        const struct libusb_interface *itf = &config->interface[j];
                                                        for(uint8_t k = 0; k < itf->num_altsetting; ++k) {
                                                                const struct libusb_interface_descriptor *itf_desc = &itf->altsetting[k];
                                                                for(int k = 0; k < itf_desc->bNumEndpoints; k++){
                                                                        const struct libusb_endpoint_descriptor *ep_desc = &itf_desc->endpoint[k];
                                                                        _device_key->_interface_no = itf_desc->bInterfaceNumber;
                                                                        _device_key->_alt_interface = itf_desc->bAlternateSetting;
                                                                        _device_key->_ep_desc = ep_desc;
                                                                        #ifdef APP_DEBUG
                                                                        fprintf(stdout,"\nEndPoint Descriptors: ");
                                                                        fprintf(stdout,"\n\tSize of EndPoint Descriptor: %d", ep_desc->bLength);
                                                                        fprintf(stdout,"\n\tType of Descriptor: %d", ep_desc->bDescriptorType);
                                                                        fprintf(stdout,"\n\tEndpoint Address: 0x0%x", ep_desc->bEndpointAddress);
                                                                        fprintf(stdout,"\n\tMaximum Packet Size: %x", ep_desc->wMaxPacketSize);
                                                                        fprintf(stdout,"\n\tAttributes applied to Endpoint: %d", ep_desc->bmAttributes);
                                                                        fprintf(stdout,"\n\tInterval for Polling for data Transfer: %d\n", ep_desc->bInterval);
                                                                        #endif
                                                                }
                                                        }
                                                }
                                        }

                                }
                                libusb_free_config_descriptor(config);
                        }
                        break;
        }
        libusb_close(device_handle);
        }
        libusb_free_device_list(device_list,1);
        return is_device_found;
}
int FOS_SecurityKey_WriteFrame(SecurityKey_t* _device_key,uint8_t* _frame, uint8_t _framelen){
        if(_device_key != NULL && _device_key->_device_handle != NULL && _frame != NULL && _framelen > 0){
                int bytes_sent = 0;
                int errcode = libusb_bulk_transfer(_device_key->_device_handle,BULK_EP_IN,_frame,_framelen,&bytes_sent,5000); //! Timeout 5s
                #ifdef APP_DEBUG
                fprintf(stdout,"FOS_SecurityKey_WriteFrame: %s %d\n",libusb_strerror(errcode),bytes_sent);
                #endif
                if(errcode != 0){
                        libusb_release_interface(_device_key->_device_handle,0);
                        libusb_close(_device_key->_device_handle);
                        return -1;
                }
                return 1;
        }
    return -1;
}
int FOS_SecurityKey_ReadFrame(SecurityKey_t* _device_key,uint8_t* _frame, uint8_t _framelen,int* bytes_received){
        if(_device_key != NULL && _device_key->_device_handle != NULL && _frame != NULL && _framelen > 0 && bytes_received != NULL){
                *bytes_received = 0;
                int errcode = libusb_bulk_transfer(_device_key->_device_handle,BULK_EP_OUT,_frame,_framelen,bytes_received,5000); //! Timeout 5s
                #ifdef APP_DEBUG
                fprintf(stdout,"FOS_SecurityKey_ReadFrame: %s %d\n",libusb_strerror(errcode),*bytes_received);
        for(int i = 0; i < *bytes_received; i++){
                        fprintf(stdout,"%x ",_frame[i]);
                }
                fprintf(stdout,"\n");
                #endif
                libusb_release_interface(_device_key->_device_handle,0);
                libusb_close(_device_key->_device_handle);
                return errcode != 0? -1 : 1;
        }
    return -1;
}
uint16_t FOS_SecurityKey_CRC16(uint8_t* buffer, uint8_t buffersize){
    uint16_t crc = 0xFFFF;
    for(int i = 0; i < buffersize; i++){
                crc ^= buffer[i];
                for(int j = 1; j <= 8; j++){
                        if((crc & 0x0001) != 0){
                            crc >>= 1;
                                crc ^= 0xA001;
                        }else
                                crc >>= 1;
                }
        }
    uint16_t temp = crc >> 8;
        crc = (crc << 8) | temp;
        crc &= 0xFFFF;
        return crc;
}
int FOS_SecurityKey_QueryKey(SecurityKey_t* _security_key,uint8_t* _buffer){
        if(_buffer == NULL || _security_key == NULL) return -1;
        time_t random_bytes = time(NULL);
        uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
        srand((unsigned) time(NULL));
        uint8_t frame[18];
    frame[0] = FOS_PROTO_SECURITY_KEY_MAGIC_H;
    frame[1] = FOS_PROTO_SECURITY_KEY_MAGIC_L;
    frame[2] = FOS_PROTO_QUERY_KEY_REQ_TYPE ;
    frame[3] = 4U + 4U + 4U;
//! Payload
    //! Replay Handle
        _buffer[0] = frame[4] = ((random_bytes >> 24U) & 0xFF) | 0x04;
        _buffer[1] = frame[5] = ((random_bytes >> 16U) & 0xFF) | 0x05;
        _buffer[2] = frame[6] = ((random_bytes >>  8U) & 0xFF) | 0x06;
        _buffer[3] = frame[7] = ((random_bytes >>  0U) & 0xFF) | 0x07;
        //! Injection Handle
        frame[8]  = (rand() % SHA256_DIGEST_LENGTH);
        frame[9]  = (rand() % SHA256_DIGEST_LENGTH);
        frame[10] = (rand() % SHA256_DIGEST_LENGTH);
        frame[11] = (rand() % SHA256_DIGEST_LENGTH);
        //! Digest
        SHA256(&frame[2],10,hash);
        frame[12] = hash[frame[8]];
        frame[13] = hash[frame[9]];
        frame[14] = hash[frame[10]];
        frame[15] = hash[frame[11]];
        //! CRC
        uint16_t crc = FOS_SecurityKey_CRC16(frame,sizeof(frame)-2);
        frame[16] = crc & 0xFF;
        frame[17] = (crc >> 8) & 0xFF;
        //! Write
        return FOS_SecurityKey_WriteFrame(_security_key,frame,sizeof(frame));
}
int FOS_SecurityKey_CheckResp(SecurityKey_t* _security_key,uint8_t* _buffer, char* _osecret){
        if(_buffer == NULL || _security_key == NULL || _osecret == NULL) return -1;
        //! Read Unimplemented yet
        int read_size = 0;
        uint8_t read_buffer[50] = {0};
        if(FOS_SecurityKey_ReadFrame(_security_key,read_buffer,sizeof(read_buffer),&read_size) != -1){
                uint16_t crc = FOS_SecurityKey_CRC16(read_buffer,read_size-2);
            //! CRC
                if(read_buffer[read_size-1] == (crc & 0xFF) && read_buffer[read_size-2] == ((crc >> 8) & 0xFF)){
                        //! Magic
                        if(read_buffer[0] == FOS_PROTO_SECURITY_KEY_MAGIC_H && read_buffer[1] == FOS_PROTO_SECURITY_KEY_MAGIC_L){
                                //! QueryResponse
                                if(read_buffer[2] == FOS_PROTO_QUERY_KEY_RESP_TYPE){
                                        //! Validate Payload Size
                                        int payloadsize = read_size - 2 - 2 - 1 - 1;
                                        if(read_buffer[3] == payloadsize && payloadsize >= 4 + 4 + 4){
                                                //! Handle Replay Attack
                                                if(read_buffer[4] == _buffer[0] && read_buffer[5] == _buffer[1] && read_buffer[6] == _buffer[2] && read_buffer[7] == _buffer[3]){
                                                        //! Length Extension and Injection Attack
                                                        uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
                                                        SHA256(&read_buffer[2],read_size-2-2-4,hash);
                                                        if(hash[read_buffer[8]] == read_buffer[read_size-6] && hash[read_buffer[9]] == read_buffer[read_size-5] && hash[read_buffer[10]] == read_buffer[read_size-4] && hash[read_buffer[11]] == read_buffer[read_size-3]){
                                                                int user_secret_size = payloadsize - 4 - 4- 4;
                                                                char ptr[3];
                                                                int i = 12;
                                                                _osecret[0]='\0';
                                                                for(;i < 12 + user_secret_size; i++){
                                                                        snprintf(ptr,3,"%02x",read_buffer[i]);
                                                                        strncat(_osecret,ptr,3);
                                                                }
                                                                return 1;
                                                        }
                                                }
                                        }
                                }
                        }
                }
        }
        return -1;
}
int FOS_SecurityKey_Authenticate(const char* config_filepath){
        int is_authenticated = -1;
        bool is_done = false;
        if(config_filepath == NULL) return is_authenticated;
        for(int i = 1; i < 5; i++){
                libusb_context* app_contex;
                int errcode = libusb_init(&app_contex);
                if(errcode == 0){
                        char _lsecret[255];
                        if(FOS_LoadUserSecret(config_filepath,_lsecret) != -1){
                                //! SecurityKey Connected?
                    SecurityKey_t security_key;
                                if(FOS_SecurityKey_isConnected(app_contex) != -1){
                                        if(is_done == false){
                                            FOS_DisplayLANConfigurationMenu();
                                        }
                                        if(is_done){
                                                uint8_t request_id[4];
                                                FOS_SecurityKey_isConnected_ex(app_contex,&security_key);
                                                if(FOS_SecurityKey_QueryKey(&security_key,request_id) != -1){
                                                        char _rsecret[255];
                                                        if(FOS_SecurityKey_CheckResp(&security_key,request_id,_rsecret) != -1){
                                                                if(strcasecmp(_lsecret,_rsecret) == 0){
                                                                        fprintf(stdout, "[I] [SecurityKey Authenticated]\n");
                                                                        is_authenticated = 1;
                                                                        //! Clean Up
                                                                        libusb_exit(app_contex);
                                                                        break;
                                                                }
                                                        }
                                                }
                                        }
                                        is_done = true;
                                }
                    }
                        libusb_exit(app_contex);
        }else
                        fprintf(stderr, "[E] [libusb_init] %s\n", strerror(errno));
                sleep(10);
        }
        return is_authenticated;
}

void FOS_DisplayLANConfigurationMenu(){
        int option = -1;
        char script_filepath[100];
        char input_string[24];
        while(1){
            fprintf(stdout,"\n-: ThingzEye Firewall Menu :-\n");
                fprintf(stdout,"1) Assign Interfaces\n");
                fprintf(stdout,"2) Set interface(s) IP address\n");
                fprintf(stdout,"3) Reboot system\n");
                fprintf(stdout,"4) Cont.\n");
                fprintf(stdout,"Enter an option: ");
                fgets(input_string,24,stdin);
                input_string[strcspn(input_string, "\n")] = '\0';
                option = atoi(input_string);
                switch(option){
                        case 1:

                                snprintf(script_filepath,100,"%s","/etc/rc.initial.setports");
                                FOS_PHP_run_script(script_filepath);
                        break;
                        case 2:
                                snprintf(script_filepath,100,"%s","/etc/rc.initial.setlanip");
                                FOS_PHP_run_script(script_filepath);
                        break;
                        case 3:
                                snprintf(script_filepath,100,"%s","/etc/rc.initial.reboot");
                                FOS_PHP_run_script(script_filepath);
                        break;
                        case 4:
                                return;
                }
        }
}
int FOS_PHP_run_script(const char* script_filepath){
    pid_t pid;
    int status;
    pid = fork();
    if (pid == 0) {
        execlp("/usr/local/bin/php", "php", script_filepath, NULL);
        perror("execlp");
        return -1;
    }else if(pid < 0) {
        perror("fork");
        return -1;
    }else{
        waitpid(pid, &status, 0);
    }
    return 1;
}
