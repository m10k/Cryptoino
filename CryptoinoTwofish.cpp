/*
 * CryptoinoTwofish.cpp - This file is part of Cryptoino
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

#include <CryptoinoTwofish.h>
#include <CryptoinoErrno.h>
#include <string.h>
#include <stdint.h>

static const uint32_t RO = 0x01010101;

#define	ROL32(a,b)	(((a) << (b)) | ((a) >> (32 - (b))))
#define ROR4(a,b)	((((a) & 0xf) >> (b)) | (((a) & 0xf) << (4 - (b))))
#define ROR32(a,b)	(((a) >> (b)) | ((a) << (32 - (b))))

/* FIXME: Lookup tables make for great side-channels, if the architecture has caches */
static const uint8_t MDS[] = {
	0x01, 0xEF, 0x5B, 0x5B,
	0x5B, 0xEF, 0xEF, 0x01,
	0xEF, 0x5B, 0x01, 0xEF,
	0xEF, 0x01, 0xEF, 0x5B
};

static const uint8_t RS[] = {
	0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E,
	0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5,
	0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19,
	0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03
};

static const uint8_t Q0_T0[] = {
	0x8, 0x1, 0x7, 0xD, 0x6, 0xf, 0x3, 0x2, 0x0, 0xb, 0x5, 0x9, 0xe, 0xc, 0xa, 0x4
};

static const uint8_t Q0_T1[] = {
	0xe, 0xc, 0xb, 0x8, 0x1, 0x2, 0x3, 0x5, 0xf, 0x4, 0xa, 0x6, 0x7, 0x0, 0x9, 0xd
};

static const uint8_t Q0_T2[] = {
	0xb, 0xa, 0x5, 0xe, 0x6, 0xd, 0x9, 0x0, 0xc, 0x8, 0xf, 0x3, 0x2, 0x4, 0x7, 0x1
};

static const uint8_t Q0_T3[] = {
	0xd, 0x7, 0xf, 0x4, 0x1, 0x2, 0x6, 0xe, 0x9, 0xb, 0x3, 0x0, 0x8, 0x5, 0xc, 0xa
};

static const uint8_t Q1_T0[] = {
	0x2, 0x8, 0xb, 0xd, 0xf, 0x7, 0x6, 0xe, 0x3, 0x1, 0x9, 0x4, 0x0, 0xa, 0xc, 0x5
};

static const uint8_t Q1_T1[] = {
	0x1, 0xe, 0x2, 0xb, 0x4, 0xc, 0x3, 0x7, 0x6, 0xd, 0xa, 0x5, 0xf, 0x9, 0x0, 0x8
};

static const uint8_t Q1_T2[] = {
	0x4, 0xc, 0x7, 0x5, 0x1, 0x6, 0x9, 0xa, 0x0, 0xe, 0xd, 0x8, 0x2, 0xb, 0x3, 0xf
};

static const uint8_t Q1_T3[] = {
	0xb, 0x9, 0x5, 0x1, 0xc, 0x3, 0xd, 0xe, 0x6, 0x4, 0x7, 0xf, 0x2, 0x0, 0x8, 0xa
};

/* 
 * FIXME: This is quite possibly the slowest implementation of GF2^8 computations 
 * anyone has ever written.
 */
static uint16_t gf28_mul(uint8_t a, uint8_t b)
{
	uint8_t x;
	uint16_t res;

	res = 0;
	for(x = 0x80; x; x >>= 1) {
		if(a & x) {
			uint16_t tmp;

			tmp = 0x0000 | b;
			if(x > 1) {
				int shift;

				shift = 1;
				while((1 << shift) != x) {
					shift++;
				}
				tmp <<= shift;
			}
			res ^= tmp;
		}
	}
	return(res);
}

static uint16_t gf28_mod(uint16_t a, uint16_t b)
{
	uint16_t div;
	uint16_t x;

        if(b == 0) {
          return(0);
        }

	div = b;
	while(!(div & 0x8000)) {
		div <<= 1;
	}

	x = 0x8000;
	while(1) {
		if(a & x) {
			a ^= div;
		}
		if(div & 1) {
			break;
		}
		x >>= 1;
		div >>= 1;
	}
	return(a);
}

static uint8_t Q0(uint8_t x)
{
	uint8_t a0, b0, a1, b1, a2, b2, a3, b3, a4, b4;

	a0 = x >> 4;
	b0 = x & 0xf;
	a1 = a0 ^ b0;
	b1 = a0 ^ ROR4(b0, 1) ^ (a0 << 3);
	a2 = Q0_T0[a1 & 0xf];
	b2 = Q0_T1[b1 & 0xf];
	a3 = a2 ^ b2;
	b3 = a2 ^ ROR4(b2, 1) ^ (a2 << 3);
	a4 = Q0_T2[a3 & 0xf];
	b4 = Q0_T3[b3 & 0xf];

	return((b4 << 4) | (a4 & 0xf));
}

static uint8_t Q1(uint8_t x)
{
	uint8_t a0, b0, a1, b1, a2, b2, a3, b3, a4, b4;

	a0 = x >> 4;
	b0 = x & 0xf;
	a1 = a0 ^ b0;
	b1 = a0 ^ ROR4(b0, 1) ^ (a0 << 3);
	a2 = Q1_T0[a1 & 0xf];
	b2 = Q1_T1[b1 & 0xf];
	a3 = a2 ^ b2;
	b3 = a2 ^ ROR4(b2, 1) ^ (a2 << 3);
	a4 = Q1_T2[a3 & 0xf];
	b4 = Q1_T3[b3 & 0xf];

	return((b4 << 4) | (a4 & 0xf));
}

uint32_t H(uint32_t X, uint32_t *L)
{
	union {
		uint32_t dw;
		uint8_t b[4];
	} z, y;

	y.b[0] = X % 256;
	y.b[1] = (X >> 8) % 256;
	y.b[2] = (X >> 16) % 256;
	y.b[3] = (X >> 24) % 256;

	y.b[0] = Q1(y.b[0]);
	y.b[1] = Q0(y.b[1]);
	y.b[2] = Q0(y.b[2]);
	y.b[3] = Q1(y.b[3]);
	y.dw ^= L[3];

	y.b[0] = Q1(y.b[0]);
	y.b[1] = Q1(y.b[1]);
	y.b[2] = Q0(y.b[2]);
	y.b[3] = Q0(y.b[3]);
	y.dw ^= L[2];

	y.b[0] = Q0(y.b[0]);
	y.b[1] = Q1(y.b[1]);
	y.b[2] = Q0(y.b[2]);
	y.b[3] = Q1(y.b[3]);

	y.dw ^= L[1];

	y.b[0] = Q0(y.b[0]);
	y.b[1] = Q0(y.b[1]);
	y.b[2] = Q1(y.b[2]);
	y.b[3] = Q1(y.b[3]);
	y.dw ^= L[0];

	y.b[0] = Q1(y.b[0]);
	y.b[1] = Q0(y.b[1]);
	y.b[2] = Q1(y.b[2]);
	y.b[3] = Q0(y.b[3]);

	z.b[0] = gf28_mod(gf28_mul(y.b[0], MDS[0]), 0x169) ^ gf28_mod(gf28_mul(y.b[1], MDS[1]), 0x169) ^ gf28_mod(gf28_mul(y.b[2], MDS[2]), 0x169) ^ gf28_mod(gf28_mul(y.b[3], MDS[3]), 0x169);
	z.b[1] = gf28_mod(gf28_mul(y.b[0], MDS[4]), 0x169) ^ gf28_mod(gf28_mul(y.b[1], MDS[5]), 0x169) ^ gf28_mod(gf28_mul(y.b[2], MDS[6]), 0x169) ^ gf28_mod(gf28_mul(y.b[3], MDS[7]), 0x169);
	z.b[2] = gf28_mod(gf28_mul(y.b[0], MDS[8]), 0x169) ^ gf28_mod(gf28_mul(y.b[1], MDS[9]), 0x169) ^ gf28_mod(gf28_mul(y.b[2], MDS[10]), 0x169) ^ gf28_mod(gf28_mul(y.b[3], MDS[11]), 0x169);
	z.b[3] = gf28_mod(gf28_mul(y.b[0], MDS[12]), 0x169) ^ gf28_mod(gf28_mul(y.b[1], MDS[13]), 0x169) ^ gf28_mod(gf28_mul(y.b[2], MDS[14]), 0x169) ^ gf28_mod(gf28_mul(y.b[3], MDS[15]), 0x169);

	return(z.dw);
}

Twofish::Twofish(void)
{
	this->__init = 0;
	return;
}

Twofish::~Twofish(void)
{
	this->destroy();
	return;
}

int Twofish::init(const uint32_t *key, const uint8_t len)
{
	uint32_t i, j, k;
	uint8_t *m, *S;

	if(len != TWOFISH_KEY_LENGTH) {
		return(CEINVALKEYLEN);
	}

	m = (uint8_t*)key;

	this->tf_ME[0] = key[0];
	this->tf_MO[0] = key[1];
	this->tf_ME[1] = key[2];
	this->tf_MO[1] = key[3];
	this->tf_ME[2] = key[4];
	this->tf_MO[2] = key[5];
	this->tf_ME[3] = key[6];
	this->tf_MO[3] = key[7];

	for(i = 0; i < 4; i++) {
		S = (uint8_t*)&(this->tf_S[3-i]);
		for(j = 0; j < 4; j++) {
			S[j] = gf28_mod(gf28_mul(RS[j << 3], m[i << 3]), 0x14d);
			for(k = 1; k < 8; k++) {
				S[j] ^= gf28_mod(gf28_mul(RS[(j << 3) + k], m[(i << 3) + k]), 0x14d);
			}
		}
	}

	for(i = 0; i < 20; i++) {
		uint32_t ai, bi;

		ai = H(RO * (i << 1), this->tf_ME);
		bi = ROL32(H(RO * ((i << 1) + 1), this->tf_MO), 8);

		this->tf_K[i << 1] = ai + bi;
		this->tf_K[(i << 1)+1] = ROL32(ai + (bi << 1), 9);
	}

	this->__init = 1;
	
	return(0);
}

int Twofish::encrypt(const uint32_t *src, uint32_t *dst)
{
	if(!this->__init) {
		return(CEINVALSTATE);
	}

	uint32_t p[4];
	uint32_t round;

	p[0] = src[0] ^ this->tf_K[0];
	p[1] = src[1] ^ this->tf_K[1];
	p[2] = src[2] ^ this->tf_K[2];
	p[3] = src[3] ^ this->tf_K[3];

	for(round = 0; round < 16; round++) {
		uint32_t F0, F1, T0, T1;

		T0 = H(p[0], this->tf_S);
		T1 = H(ROL32(p[1], 8), this->tf_S);

		F0 = T0 + T1 + this->tf_K[round * 2 + 8];
		F1 = T0 + (T1 << 1) + this->tf_K[round * 2 + 9];

		p[2] ^= F0;
		p[2] = ROR32(p[2], 1);
		p[3] = ROL32(p[3], 1) ^ F1;

		F0 = p[0];
		F1 = p[1];
		p[0] = p[2];
		p[1] = p[3];
		p[2] = F0;
		p[3] = F1;
	}

	dst[0] = p[2] ^ this->tf_K[4];
	dst[1] = p[3] ^ this->tf_K[5];
	dst[2] = p[0] ^ this->tf_K[6];
	dst[3] = p[1] ^ this->tf_K[7];

	return(0);
}

int Twofish::decrypt(const uint32_t *src, uint32_t *dst)
{
	if(!this->__init) {
		return(CEINVALSTATE);
	}

	uint32_t p[4];
	uint32_t round;

	p[2] = src[0] ^ this->tf_K[4];
	p[3] = src[1] ^ this->tf_K[5];
	p[0] = src[2] ^ this->tf_K[6];
	p[1] = src[3] ^ this->tf_K[7];

	for(round = 15; round <= 15; round--) {
		uint32_t F0, F1, T0, T1;

		T0 = p[0];
		T1 = p[1];
		p[0] = p[2];
		p[1] = p[3];
		p[2] = T0;
		p[3] = T1;

		T0 = H(p[0], this->tf_S);
		T1 = H(ROL32(p[1], 8), this->tf_S);

		F0 = T0 + T1 + this->tf_K[round * 2 + 8];
		F1 = T0 + (T1 << 1) + this->tf_K[round * 2 + 9];

		p[2] = ROL32(p[2], 1) ^ F0;
		p[3] ^= F1;
		p[3] = ROR32(p[3], 1);
	}

	dst[0] = p[0] ^ this->tf_K[0];
	dst[1] = p[1] ^ this->tf_K[1];
	dst[2] = p[2] ^ this->tf_K[2];
	dst[3] = p[3] ^ this->tf_K[3];

	return(0);
}

void Twofish::destroy(void)
{
	memset(this->tf_MO, 0, sizeof(this->tf_MO));
	memset(this->tf_ME, 0, sizeof(this->tf_ME));
	memset(this->tf_K, 0, sizeof(this->tf_K));
	memset(this->tf_S, 0, sizeof(this->tf_S));
	this->__init = 0;

	return;
}
