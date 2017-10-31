/*
 * CryptoinoCipher.h - This file is part of Cryptoino
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
 
#ifndef __CRYPTOINO_CIPHER_H
#define __CRYPTOINO_CIPHER_H

#include <CryptoinoErrno.h>
#include <CryptoinoTwofish.h>

#define CIPHER_BLOCK_SIZE	TWOFISH_BLOCK_SIZE
#define CIPHER_KEY_LENGTH	TWOFISH_KEY_LENGTH

enum cipher_mode {
	CIPHER_MODE_NONE	= 0,
	CIPHER_MODE_CBC		= 1,
	CIPHER_MODE_CTR		= 2
};

typedef enum cipher_mode cipher_mode_t;

class Cipher {
	private:
	Twofish			ci_context;
	cipher_mode_t	ci_mode;
	uint32_t		ci_iv[TWOFISH_BLOCK_SIZE / sizeof(uint32_t)];
	uint32_t		ci_ctr;
	int				__init;

	public:
	int				ci_errno;
	
	Cipher(void);
	~Cipher(void);

	int init(const uint32_t*, const uint8_t);
	void destroy(void);
	
	int setMode(cipher_mode_t);
	cipher_mode_t getMode(void);

	int setIV(const uint32_t*, const uint8_t);
	int setCounter(const uint32_t);

	int32_t encrypt(const void*, const uint32_t, void*, const uint32_t);
	int32_t decrypt(const void*, const uint32_t, void*, const uint32_t);

	const char* strerror(void);
};

#endif /* __CRYPTOINO_CIPHER_H */
