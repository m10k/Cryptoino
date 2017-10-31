/*
 * CryptoinoHMAC.cpp - This file is part of Cryptoino
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
#include <CryptoinoHMAC.h>
#include <CryptoinoErrno.h>
#include <string.h>
#include <stdint.h>
#include <Arduino.h>

/*
 * FIXME: These values have been deliberately choosen 
 * without of any further considerations 
 */
#define HMAC_OUTER_PAD	0x5c5c5c5c
#define HMAC_INNER_PAD	0x36363636

HMAC::HMAC(void)
{
	this->zero();
	
	return;
}

HMAC::~HMAC(void)
{
	this->zero();
	
	return;
}

void HMAC::zero(void)
{
	this->hm_errno = 0;
	memset(this->hm_opad, 0, sizeof(this->hm_opad));
	memset(this->hm_ipad, 0, sizeof(this->hm_ipad));
	this->__init = 0;

	return;
}

int HMAC::init(const void *key, const int len)
{
	uint32_t *k;
	
	if(len != HMAC_KEY_SIZE) {
		this->hm_errno = CEINVALKEYLEN;
		return(-1);
	}

	k = (uint32_t*)key;

	this->hm_opad[0] = k[0] ^ HMAC_OUTER_PAD;
	this->hm_opad[1] = k[1] ^ HMAC_OUTER_PAD;
	this->hm_opad[2] = k[2] ^ HMAC_OUTER_PAD;
	this->hm_opad[3] = k[3] ^ HMAC_OUTER_PAD;
	this->hm_opad[4] = k[4] ^ HMAC_OUTER_PAD;
	this->hm_opad[5] = k[5] ^ HMAC_OUTER_PAD;
	this->hm_opad[6] = k[6] ^ HMAC_OUTER_PAD;
	this->hm_opad[7] = k[7] ^ HMAC_OUTER_PAD;
	this->hm_ipad[0] = k[0] ^ HMAC_INNER_PAD;
	this->hm_ipad[1] = k[1] ^ HMAC_INNER_PAD;
	this->hm_ipad[2] = k[2] ^ HMAC_INNER_PAD;
	this->hm_ipad[3] = k[3] ^ HMAC_INNER_PAD;
	this->hm_ipad[4] = k[4] ^ HMAC_INNER_PAD;
	this->hm_ipad[5] = k[5] ^ HMAC_INNER_PAD;
	this->hm_ipad[6] = k[6] ^ HMAC_INNER_PAD;
	this->hm_ipad[7] = k[7] ^ HMAC_INNER_PAD;

	this->__init = 1;

	return(0);
}

int HMAC::authenticate(const void *buf, const size_t len, void *hash, const size_t size)
{
	SHA256 ctx;
	char ihash[HMAC_OUTPUT_SIZE];

	if(!this->__init) {
		this->hm_errno = CEINVALSTATE;
		return(-1);
	}

	if(size < HMAC_KEY_SIZE) {
		this->hm_errno = CENOSPC;
		return(-1);
	}

	/* the calculation of the hmac works roughly like this:
	 *
	 * sha256((k ^ a) ## sha256((k ^ b) ## m))
	 *
	 * where k is the secret key used for authentication, ^ means XOR,
	 * a and b are constants defined in this file (look at the top) and
	 * ## is the concatenation operation */

	ctx.zero();
	ctx.feed((const char*)this->hm_ipad, sizeof(this->hm_ipad));
	ctx.feed((const char*)buf, len);
	ctx.digest(ihash);
	
	/* zero() is called at the end of digest(), so no need to call it manually */
	ctx.feed((const char*)this->hm_opad, sizeof(this->hm_opad));
	ctx.feed(ihash, sizeof(ihash));
	ctx.digest((char*)hash);

	this->hm_errno = 0;
	
	return(0);
}

int HMAC::verify(const void *msg, const size_t msg_len, const void *mac, const size_t mac_len)
{
	char expectation[HMAC_OUTPUT_SIZE];

	if(mac_len != HMAC_OUTPUT_SIZE) {
		this->hm_errno = CEINVALMACLEN;
		return(-1);
	}

	if(this->authenticate(msg, msg_len, expectation, sizeof(expectation)) < 0) {
		return(-1);
	}

	if(memcmp(mac, expectation, mac_len) != 0) {
		this->hm_errno = CEINVALMAC;
		return(-1);
	}

	this->hm_errno = 0;
	
	return(0);
}

const char* HMAC::strerror(void)
{
	return(strcerror(this->hm_errno));
}
