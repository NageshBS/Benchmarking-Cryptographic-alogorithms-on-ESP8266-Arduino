
#ifndef CRYPTO_CHACHA_h
#define CRYPTO_CHACHA_h

#include "Cipher.h"

class ChaChaPoly;

class ChaCha : public Cipher
{
public:
    explicit ChaCha(uint8_t numRounds = 20);
    virtual ~ChaCha();

    size_t keySize() const;
    size_t ivSize() const;

    uint8_t numRounds() const { return rounds; }
    void setNumRounds(uint8_t numRounds) { rounds = numRounds; }

    bool setKey(const uint8_t *key, size_t len);
    bool setIV(const uint8_t *iv, size_t len);
    bool setCounter(const uint8_t *counter, size_t len);

    void encrypt(uint8_t *output, const uint8_t *input, size_t len);
    void decrypt(uint8_t *output, const uint8_t *input, size_t len);

    void clear();

    static void hashCore(uint32_t *output, const uint32_t *input, uint8_t rounds);

private:
    uint8_t block[64];
    uint8_t stream[64];
    uint8_t rounds;
    uint8_t posn;

    void keystreamBlock(uint32_t *output);

    friend class ChaChaPoly;
};

#endif
