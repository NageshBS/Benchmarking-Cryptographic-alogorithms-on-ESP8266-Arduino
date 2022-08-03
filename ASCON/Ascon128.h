#ifndef CRYPTO_ASCON128_H
#define CRYPTO_ASCON128_H

#include "AuthenticatedCipher.h"

class Ascon128 : public AuthenticatedCipher
{
public:
    Ascon128();
    virtual ~Ascon128();

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
    struct {
        uint64_t K[2];
        uint64_t S[5];
    } state;
    uint8_t posn;
    uint8_t authMode;

    void permute(uint8_t first);
    void endAuth();
};

#endif
