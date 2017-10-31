/*
 * CryptoinoSHA256.cpp - This file is part of Cryptoino
 * Copyright (C) 2014 Matthias Kruk
 *
 * Cryptoino is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * Cryptoino is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Cryptoino; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/* !!! HERE BE DRAGONS !!!
 * 
 * Cryptoino is a library that implements some cryptographic primitives
 * and mechanisms for use with Arduino boards. IT HAS NEVER BEEN AUDITED
 * OR OTHERWISE SCRUTINISED. YOU SHOULD CONSIDER IT UNSAFE AND PRONE TO
 * ANY KIND OF SIDE CHANNEL ATTACKS AND ABSOLUTELY NOT USE IT IN ANY KIND
 * OF ADVERSARIAL ENVIRONMENT. FURTHERMORE, IT HAS NEVER BEEN OPTIMISED
 * FOR PERFORMANCE. USE IT AT YOUR OWN RISK AND FOR TESTING/EDUCATIONAL
 * PURPOSES ONLY! YOU HAVE BEEN WARNED.
 */
 
#include <CryptoinoSHA256.h>
#include <string.h>
#include <Arduino.h>

#define RORW(x)	((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8))
#define RORD(x)	((((x) & 0xffff0000) >> 16) | (((x) & 0x0000ffff) << 16))
#define RORQ(x)	((((x) & 0xffffffff00000000) >> 32) | (((x) & 0x00000000ffffffff) << 32))
#define CH(x,y,z)	(((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define E0(x)		(ror((x), 2) ^ ror((x), 13) ^ ror((x), 22))
#define E1(x)		(ror((x), 6) ^ ror((x), 11) ^ ror((x), 25))
#define S0(x)		(ror((x), 7) ^ ror((x), 18) ^ ((x) >> 3))
#define S1(x)		(ror((x), 17) ^ ror((x), 19) ^ ((x) >> 10))

const static uint32_t K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t ror(uint32_t x, int n)
{
	return(((x & ((2 << n) - 1)) << (32 - n)) | (x >> n));
}

static inline uint64_t be64(uint64_t le)
{
	union foo {
		uint64_t _le64;
		uint32_t _le32[2];
		uint16_t _le16[4];
	} *ple = (union foo*)&le;

	ple->_le64 = RORQ(ple->_le64);
	ple->_le32[0] = RORD(ple->_le32[0]);
	ple->_le32[1] = RORD(ple->_le32[1]);
	ple->_le16[0] = RORW(ple->_le16[0]);
	ple->_le16[1] = RORW(ple->_le16[1]);
	ple->_le16[2] = RORW(ple->_le16[2]);
	ple->_le16[3] = RORW(ple->_le16[3]);

	return(le);
}

static inline uint32_t be32(uint32_t le)
{
	union foo {
		uint32_t _le32;
		uint16_t _le16[2];
	} *ple = (union foo*)&le;

	ple->_le32 = RORD(ple->_le32);
	ple->_le16[0] = RORW(ple->_le16[0]);
	ple->_le16[1] = RORW(ple->_le16[1]);

	return(le);
}

SHA256::SHA256(void)
{
	this->zero();
	return;
}

SHA256::~SHA256(void)
{
	this->zero();
	return;
}

void SHA256::zero(void)
{
	memset(this->sha_h, 0, sizeof(this->sha_h));
	memset(this->sha_buffer, 0, sizeof(this->sha_buffer));
	this->sha_buffered = 0;
	this->sha_bytes = 0;

	this->sha_h[0] = 0x6a09e667;
	this->sha_h[1] = 0xbb67ae85;
	this->sha_h[2] = 0x3c6ef372;
	this->sha_h[3] = 0xa54ff53a;
	this->sha_h[4] = 0x510e527f;
	this->sha_h[5] = 0x9b05688c;
	this->sha_h[6] = 0x1f83d9ab;
	this->sha_h[7] = 0x5be0cd19;

	return;
}

int SHA256::feed(const char *data, size_t n)
{
	uint32_t h[8];
	uint32_t *ptr;
	uint32_t fed;

	this->sha_bytes += n;
	fed = 0;

	if(!n) {
		if(this->sha_buffered >= 64) {
			return(-1);
		}

		if(this->sha_buffered < 0) {
			this->sha_buffered = 0;
		}

		this->sha_buffer[this->sha_buffered] = 0x80;
		if(this->sha_buffered < 56) {
			*((uint64_t*)(this->sha_buffer+56)) = be64(this->sha_bytes << 3);
			this->sha_buffered = 64;
		} else {
			*((uint64_t*)(this->sha_buffer+120)) = be64(this->sha_bytes << 3);
			this->sha_buffered = 128;
		}
	}

	while(this->sha_buffered + n >= 64) {
		uint32_t block[16];
		int j;

		ptr = (uint32_t*)(data + fed);

		if(this->sha_buffered > 0) {
			if(this->sha_buffered < 64) {
				memcpy(block, this->sha_buffer, this->sha_buffered);
				memcpy(((char*)block)+this->sha_buffered, ptr, 64 - this->sha_buffered);
				fed += 64 - this->sha_buffered;
				n -= this->sha_buffered;
				this->sha_buffered = 0;
			} else {
				memcpy(block, this->sha_buffer, 64);
				memcpy(this->sha_buffer, this->sha_buffer+64, this->sha_buffered - 64);
				this->sha_buffered -= 64;
			}
			ptr = block;
		} else {
			fed += 64;
			n -= 64;
		}

		for(j = 0; j < 8; j++) {
			h[j] = this->sha_h[j];
		}

		for(j = 0; j < 64; j++) {
			uint32_t ch, maj, e0, e1, t1, t2;
			uint32_t w[64];
			int ii;

			ch = CH(h[4], h[5], h[6]);
			maj = MAJ(h[0], h[1], h[2]);
			e0 = E0(h[0]);
			e1 = E1(h[4]);

			for(ii = 0; ii < 16; ii++) {
				w[ii] = be32(ptr[ii]);
			}
			for(ii = 16; ii < 64; ii++) {
				w[ii] = S1(w[ii-2]) + w[ii-7] + S0(w[ii-15]) + w[ii-16];
			}

			t1 = h[7] + e1 + ch + K[j] + w[j];
			t2 = e0 + maj;
			h[7] = h[6];
			h[6] = h[5];
			h[5] = h[4];
			h[4] = h[3] + t1;
			h[3] = h[2];
			h[2] = h[1];
			h[1] = h[0];
			h[0] = t1 + t2;
		}

		for(j = 0; j < 8; j++) {
			this->sha_h[j] += h[j];
		}
	}

	if(n > 0 && data) {
		memcpy(this->sha_buffer, data+fed, n);
		this->sha_buffered = n;
	}

	return(0);
}

int SHA256::digest(char *dst)
{
	uint32_t *d;
	int i;

	if(!dst) {
		return(-1);
	}

	i = 0;

	while(this->sha_buffered > 0) {
		if(i++ >= 3) {
			return(-1);
		}
		if(this->feed(NULL, 0) < 0) {
			return(-1);
		}
	}

	d = (uint32_t*)dst;
	for(i = 0; i < 8; i++) {
		d[i] = be32(this->sha_h[i]);
	}
	this->zero();
	
	return(0);
}
