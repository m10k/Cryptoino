/*
 * CryptoinoHMAC.h - This file is part of Cryptoino
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
 
#ifndef __CRYPTOINO_HMAC_H
#define __CRYPTOINO_HMAC_H

#include <stdint.h>
#include <Arduino.h>

#define HMAC_KEY_SIZE		32
#define HMAC_OUTPUT_SIZE	32

class HMAC {
	private:
	uint32_t	hm_opad[HMAC_KEY_SIZE / sizeof(uint32_t)];
	uint32_t	hm_ipad[HMAC_KEY_SIZE / sizeof(uint32_t)];
	int			__init;
	
	public:
	int			hm_errno;
	
	HMAC(void);
	~HMAC(void);

	void zero(void);

	int init(const void*, const int);
	int authenticate(const void*, const size_t, void*, const size_t);
	int verify(const void*, const size_t, const void*, const size_t);

	const char* strerror(void);
};

#endif /* __CRYPTOINO_HMAC_H */
