#include "stdint.h"
#include "stdlib.h"
#include "string.h"
#include "des.h"
#include "jet_twofish.h"
#include "stdio.h"

#define M_DECRYPT   0
#define M_ENCRYPT   1

uint8_t vendor_key[32] = {0x54, 0xF5, 0x53, 0x12, 0xEA, 0xD4, 0xEC, 0x03, 0x28, 0x60, 0x80, 0x94, 0xD6, 0xC4, 0x3A, 0x48, 
                           0x43, 0x71, 0x28, 0x94, 0xF4, 0xE3, 0xAB, 0xC7, 0x36, 0x59, 0x17, 0x8E, 0xCC, 0x6D, 0xA0, 0x9B};

static void dump(uint8_t *title, uint8_t *data, size_t len){
	int i=0;
	printf("%s:\t",title);
	if(len > 16)
		puts("");
	for(i=0;i<len;i++){
		printf(" %02X",data[i]);
		if( (i % 16) == 15)printf("\n");
	}
	if((i % 16) != 0 && i > 0) printf("\n");
}


uint16_t crc16_table[256]={
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241, 
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440, 
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40, 
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841, 
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40, 
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41, 
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641, 
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040, 
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240, 
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441, 
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41, 
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840, 
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41, 
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40, 
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640, 
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041, 
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240, 
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441, 
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41, 
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840, 
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41, 
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40, 
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640, 
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041, 
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241, 
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440, 
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40, 
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841, 
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40, 
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41, 
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641, 
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};


static uint16_t calc_crc16(uint8_t* in, int len) {
        int i = 0;
	uint16_t crc_value = 0;
        while(len >= 0) {
            int j = len - 1;
            if(len <= 0) {
                return crc_value;
            }

            crc_value = ((uint16_t)(((crc_value & 0xFFFF) >> 8) ^ crc16_table[((0xFFFF & crc_value) ^ (in[i] & 0xFF)) & 0xFF]));
            ++i;
            len = j;
        }

        return crc_value;
    }

static size_t jet_encrypt(uint8_t tag, uint8_t *data, size_t len, uint8_t *out, size_t maxlen)
{
	uint8_t buf[256];
	size_t i;
	size_t aligned_len = (len + 15) / 16 * 16;
	if((aligned_len + 7) > maxlen || (aligned_len + 7) > 256)
		return 0;
	memset(buf, 0xFF, aligned_len + 7);

	out[0] = 0x84;
	out[1] = tag;
	out[2] = 0;
	out[3] = 0;
	out[4] = aligned_len & 0xFF;
	memcpy(buf, data, len);
	if(tag == 0x15){
		twofish(buf,len, out + 5,maxlen,vendor_key,sizeof(vendor_key),0);
	}
	else if(tag == 0x16){
		for(i = 0; i < (aligned_len / 8); i++)
			des_ecb_encrypt(buf + 8 * i, vendor_key + (i % 4) * 8, 8);
		memcpy(out + 5, buf, aligned_len);
	}
	out[aligned_len + 5] = 0x90;
	out[aligned_len + 6] = 0x00;

	return (aligned_len + 7);
}

static size_t jet_decrypt(uint8_t *data,  uint8_t *out, size_t maxlen)
{
	uint8_t buf[256];
	size_t i;
	uint8_t tag;
	int len = data[4];

	memset(buf, 0, sizeof(buf));
	memset(out, 0, maxlen);
	tag = data[1];

	memcpy(buf, data + 5, len);
	if(tag == 0x15){
		twofish(buf,len, out,maxlen,vendor_key,sizeof(vendor_key),1);
	}
	else if(tag == 0x16){
		for(i = 0; i < (len / 8); i++)
			des_ecb_encrypt(buf + 8 * i, vendor_key + (i % 4) * 8, 8);
		memcpy(out, buf, len);
	}
	else
		memcpy(out, buf, len);
	return (len);
}

int32_t gethexval(char c)
{
	if(c >= '0' && c <= '9') { return c - '0'; }
	if(c >= 'A' && c <= 'F') { return c - 'A' + 10; }
	if(c >= 'a' && c <= 'f') { return c - 'a' + 10; }
	return -1;
}

int32_t cs_atob(uint8_t *buf, char *asc, int32_t n)
{
	int32_t i,j,k, rc;
	for(i = 0, j = 0,k = 0; j < n; i++)
	{
		if(0 < asc[i] && asc[i] <= 0x20)
			continue;
		k++;
		
		if(k == 2){
			rc = rc << 4 | gethexval(asc[i]);
			buf[j++] = rc;
			k = 0;
		}
		else{
			rc = gethexval(asc[i]);
		}
	}
	return n;
}

int main(int argc, char* argv[])
{
	uint8_t data[256];
	uint8_t confname[256];
	uint8_t *out;
	int i,len;
	int mode=M_DECRYPT;
	int ignore_config = 0;
	struct twofish_ctx ctx;

	memset(data, 0xFF, sizeof(data));
	for(i=1,len=0; i < argc; i++){
		if(!strcmp(argv[i],"-d")){
			mode = M_DECRYPT;
			continue;
		}
		else if(!strcmp(argv[i],"-e")){
			mode = M_ENCRYPT;
			continue;
		}
		else if(!strcmp(argv[i],"-i")){
			ignore_config = 1;
			continue;
		}
		int c;
		if(sscanf(argv[i],"%X",&c)){
			data[len++] = c & 0xFF;
		}
	}
	if(!ignore_config){
		strncpy(confname,argv[0],sizeof(confname));
		strcat(confname,".conf");
		FILE *fp=fopen(confname,"rt");
		if(fp){
			char line[1024];
			while(NULL != fgets(line,sizeof(line),fp)){
				if(!strncmp(line,"vendor_key=",11)){
					memset(vendor_key,0, sizeof(vendor_key));
					cs_atob(vendor_key,line + 11,sizeof(vendor_key));
					dump("vendor_key update to", vendor_key,sizeof(vendor_key));
					break;
				}
			}
			fclose(fp);
		}
	}
	uint8_t buf[256];
	size_t aligned_len = (len + 15) / 16 * 16;
	if((aligned_len + 7) > 255 || (aligned_len + 7) > 256)
		return 0;
	twofish_setkey(&ctx, vendor_key, sizeof(vendor_key));
	if(mode == M_ENCRYPT){
		twofish_encrypt(&ctx, data, aligned_len, buf, sizeof(buf));
		dump("encrypt",buf, len);
	}
	else{
		twofish_decrypt(&ctx, data, len, buf, sizeof(buf));
		dump("decrypt",buf, len);
	}
	return 0;
}
