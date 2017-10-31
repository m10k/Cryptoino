/*
 * CryptoinoTwofish.h - This file is part of Cryptoino
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

#ifndef __CRYPTOINO_TWOFISH_H
#define __CRYPTOINO_TWOFISH_H

#include <stdint.h>

#define TWOFISH_KEY_LENGTH	32
#define TWOFISH_BLOCK_SIZE	16

class Twofish {
	private:
	int			__init;
	uint32_t	tf_ME[4];
	uint32_t	tf_MO[4];
	uint32_t	tf_S[4];
	uint32_t	tf_K[40];

	public:
	Twofish(void);
	~Twofish(void);

	int 	init(const uint32_t*, const uint8_t);
	int		encrypt(const uint32_t*, uint32_t*);
	int		decrypt(const uint32_t*, uint32_t*);
	void	destroy(void);
};

#endif /* __CRYPTOINO_TWOFISH_H */
