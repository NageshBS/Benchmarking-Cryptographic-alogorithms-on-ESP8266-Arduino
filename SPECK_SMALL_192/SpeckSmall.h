#ifndef CRYPTO_SPECK_SMALL_H
#define CRYPTO_SPECK_SMALL_H

#include "SpeckTiny.h"

class SpeckSmall : public SpeckTiny
{
public:
    SpeckSmall();
    virtual ~SpeckSmall();

    bool setKey(const uint8_t *key, size_t len);

    void decryptBlock(uint8_t *output, const uint8_t *input);

    void clear();

private:
    uint64_t l[4];
};

#endif
