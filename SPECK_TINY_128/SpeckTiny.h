#ifndef CRYPTO_SPECK_TINY_H
#define CRYPTO_SPECK_TINY_H

#include "BlockCipher.h"

class SpeckSmall;

class SpeckTiny : public BlockCipher
{
public:
    SpeckTiny();
    virtual ~SpeckTiny();

    size_t blockSize() const;
    size_t keySize() const;

    bool setKey(const uint8_t *key, size_t len);

    void encryptBlock(uint8_t *output, const uint8_t *input);
    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

private:
    uint64_t k[4];
    uint8_t rounds;

    friend class SpeckSmall;
};

#endif
