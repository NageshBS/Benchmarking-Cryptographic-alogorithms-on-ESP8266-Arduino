
#ifndef CRYPTO_CHACHAPOLY_H
#define CRYPTO_CHACHAPOLY_H

#include "AuthenticatedCipher.h"
#include "ChaCha.h"
#include "Poly1305.h"

class ChaChaPoly : public AuthenticatedCipher
{
public:
    ChaChaPoly();
    virtual ~ChaChaPoly();

    size_t keySize() const;
    size_t ivSize() const;
    size_t tagSize() const;

    bool setKey(const uint8_t *key, size_t len);
    bool setIV(const uint8_t *iv, size_t len);

    void encrypt(uint8_t *output, const uint8_t *input, size_t len);
    void decrypt(uint8_t *output, const uint8_t *input, size_t len);

    void addAuthData(const void *data, size_t len);

    void computeTag(void *tag, size_t len);
    bool checkTag(const void *tag, size_t len);

    void clear();

private:
    ChaCha chacha;
    Poly1305 poly1305;
    struct {
        uint8_t nonce[16];
        uint64_t authSize;
        uint64_t dataSize;
        bool dataStarted;
        uint8_t ivSize;
    } state;
};

#endif
