/*
 * CryptoinoErrno.cpp - This file is part of Cryptoino
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
 
#include <CryptoinoErrno.h>

static const char *cerror_str[] = {
	"Success",
	"Not implemented",
	"Bad message",
	"Not enough space",
	"Invalid padding",
	"Invalid counter",
	"Invalid IV length",
	"Invalid state",
	"Invalid mode",
	"Invalid key length",
	"Invalid MAC length",
	"Invalid MAC",
	"Invalid argument",
	"Transport error",
	0
};

static const char *cerror_unknown = "Unknown error number";

const char *strcerror(int errno)
{
	if(errno >= 0 && errno <= CERRNO_MAX) {
		return(cerror_str[errno]);
	}
	
	return(cerror_unknown);
}
