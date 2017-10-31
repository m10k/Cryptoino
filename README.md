# Cryptoino

**This is an EXPERIMENTAL crypto library written for Arduino-like boards. It has never been seriously tested,
let alone audited, nor has it been optimized for performance. The code works, but is very slow and likely
contains several side-channels. You are hereby STRONGLY discouraged from using it for anything but
experimentation. You have been warned.**

The library provides two classes called *Cipher* and *HMAC*, which can be used for encryption, decryption, and
authentication of data. These classes use the Twofish and SHA256 algorithms, respectively, to do their work.
The *Cipher* class implements the CBC and CTR modes, which means it allows Twofish to be used as a block
cipher or as a stream cipher. The only supported key size is 256 bits.

The library has been tested to work on Arduino Uno R3, Intel Galileo Gen2, and Texas Instruments CC3200 boards.

## Example CBC encryption / decryption

**Note: For brevity's sake, error checking, key generation, etc. is omitted**

    uint8_t key[32], iv[16];
    uint8_t plaintext_a[128];
    uint8_t plaintext_b[128];
    uint8_t ciphertext[128];
    int32_t clen, plen;
    Cipher ciph;

    /* Need to generate key, IV here */
    
    ciph.init(key, sizeof(key));
    
    ciph.setMode(CIPHER_MODE_CBC);
    ciph.setIV(iv, sizeof(iv));
    
    clen = ciph.encrypt(plaintext_a, sizeof(plaintext_a), ciphertext, sizeof(ciphertext));
    
    ciph.setIV(iv, sizeof(iv));
    plen = ciph.decrypt(ciphertext, clen, plaintext_b, sizeof(plaintext_b));


## Example CTR encryption / decryption

    uint8_t key[32];
    uint32_t ctr;
    uint8_t plaintext_a[128];
    uint8_t plaintext_b[128];
    uint8_t ciphertext[128];
    int32_t clen, plen;
    Cipher ciph;
    
    /* need to generate key here, and set `ctr' */
    
    ciph.init(key, sizeof(key));
    
    ciph.setMode(CIPHER_MODE_CTR);
    ciph.setCounter(ctr);
    
    clen = ciph.encrypt(plaintext_a, sizeof(plaintext_a), ciphertext, sizeof(ciphertext));
    
    ciph.setCounter(ctr);
    plen = ciph.decrypt(ciphertext, clen, plaintext_b, sizeof(plaintext_b));


## Example HMAC

    uint8_t key[32];
    uint8_t data[128];
    uint8_t hash[HMAC_OUTPUT_SIZE];
    HMAC hmac;
    
    /* Need to generate key here */
    
    hmac.init(key, sizeof(key));
    
    hmac.authenticate(data, sizeof(data), hash, sizeof(hash));
    
    if(hmac.verify(data, sizeof(data), hash, sizeof(hash)) < 0) {
        /* Verification failed */
    } else {
        /* HMAC looks good */
    }

