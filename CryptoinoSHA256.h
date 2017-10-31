/*
 * CryptoinoSHA256.h - This file is part of Cryptoino
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
 
#ifndef __CRYPTOINO_SHA256_H
#define __CRYPTOINO_SHA256_H

#include <stdint.h>
#include <Arduino.h>

class SHA256 {
	private:
	uint32_t	sha_h[8];
	uint8_t		sha_buffer[128];
	int32_t		sha_buffered;
	uint64_t	sha_bytes;

	public:
	SHA256(void);
	~SHA256(void);

	void zero(void);
	int feed(const char*, size_t);
	int digest(char*);
};

#endif /* __CRYPTOINO_SHA256_H */
