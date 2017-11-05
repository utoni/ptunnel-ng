#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "base64.h"


#if 0
static const char hextab[] = "0123456789ABCDEF";

void print_hexstr(unsigned char *buf, size_t siz) {
	char *out = (char *) calloc(3, siz+1);
	unsigned char high, low;

	for (size_t i = 0; i < siz; ++i) {
		high = (buf[i] & 0xF0) >> 4;
		low  = buf[i] & 0x0F;

		out[i  ] = hextab[high];
		out[i+1] = hextab[low];
		out[i+2] = ' ';
	}

	printf("%s\n", out);
	free(out);
}
#endif


static void build_decoding_table(void);

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};


char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
	*output_length = 4 * ((input_length + 2) / 3);

	char *encoded_data = (char *) calloc(*output_length, sizeof(char));
	if (encoded_data == NULL) return NULL;

	for (size_t i = 0, j = 0; i < input_length; i += 3, j += 4) {

		uint32_t octet_a = i < input_length ? (unsigned char)data[i] : 0;
		uint32_t octet_b = i < input_length ? (unsigned char)data[i+1] : 0;
		uint32_t octet_c = i < input_length ? (unsigned char)data[i+2] : 0;
		uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		encoded_data[j]   = encoding_table[(triple >> 3 * 6) & 0x3F];
		encoded_data[j+1] = encoding_table[(triple >> 2 * 6) & 0x3F];
		encoded_data[j+2] = encoding_table[(triple >> 1 * 6) & 0x3F];
		encoded_data[j+3] = encoding_table[(triple >> 0 * 6) & 0x3F];
	}

	for (int i = 0; i < mod_table[input_length % 3]; i++)
		encoded_data[*output_length - 1 - i] = '=';

	return encoded_data;
}

unsigned char *base64_decode(const char *data, size_t input_length, size_t *output_length) {
	if (decoding_table == NULL) build_decoding_table();
	if (input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') (*output_length)--;
	if (data[input_length - 2] == '=') (*output_length)--;

	unsigned char *decoded_data = (unsigned char *) calloc(*output_length, sizeof(char));
	if (decoded_data == NULL) return NULL;

	for (size_t i = 0, j = 0; i < input_length; i += 4, j += 3) {
		uint32_t sextet_a = data[i] == '=' ? 0 & i     : decoding_table[(size_t)data[i]];
		uint32_t sextet_b = data[i] == '=' ? 0 & (i+1) : decoding_table[(size_t)data[i+1]];
		uint32_t sextet_c = data[i] == '=' ? 0 & (i+2) : decoding_table[(size_t)data[i+2]];
		uint32_t sextet_d = data[i] == '=' ? 0 & (i+3) : decoding_table[(size_t)data[i+3]];

		uint32_t triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}

static void build_decoding_table(void) {
	decoding_table = (char *) calloc(256, sizeof(*decoding_table));

	for (int i = 0; i < 64; i++)
		decoding_table[(unsigned char) encoding_table[i]] = i;
}

void base64_cleanup(void) {
	free(decoding_table);
}
