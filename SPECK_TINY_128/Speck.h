#ifndef CRYPTO_SPECK_H
#define CRYPTO_SPECK_H

#include "BlockCipher.h"

class Speck : public BlockCipher
{
public:
    Speck();
    virtual ~Speck();

    size_t blockSize() const;
    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

    void encryptBlock(uint8_t *output, const uint8_t *input);
    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

private:
    uint64_t k[34];
    uint8_t rounds;
};

#endif
