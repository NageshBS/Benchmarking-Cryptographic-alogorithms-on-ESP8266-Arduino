#include <Crypto.h>
#include <ChaCha.h>
#include <string.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#define MAX_PLAINTEXT_SIZE  64
#define MAX_CIPHERTEXT_SIZE 64

struct TestVector
{
    const char *name;
    byte key[32];
    size_t keySize;
    uint8_t rounds;
    byte plaintext[MAX_PLAINTEXT_SIZE];
    byte ciphertext[MAX_CIPHERTEXT_SIZE];
    byte iv[8];
    byte counter[8];
    size_t size;
};

static TestVector const testVectorChaCha20_128 PROGMEM = {
    .name        = "ChaCha20 128-bit",
    .key         = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    .keySize     = 16,
    .rounds      = 20,
    .plaintext   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .ciphertext  = {0x1C, 0x91, 0xE7, 0x99, 0x71, 0xC0, 0x1C, 0x2A,
                    0xEC, 0xE9, 0x24, 0x35, 0xB1, 0x6E, 0xBF, 0xFD,
                    0x33, 0x05, 0xCC, 0x17, 0x24, 0x9D, 0x66, 0xA7,
                    0xA0, 0xCA, 0xB8, 0x36, 0x03, 0xA6, 0x9D, 0x93,
                    0x9A, 0x4C, 0x10, 0x40, 0xD9, 0x2A, 0x86, 0x78,
                    0x3A, 0xAD, 0x71, 0x87, 0x55, 0x9F, 0x5B, 0x9A,
                    0x68, 0x52, 0xA0, 0xAD, 0x59, 0xAE, 0x04, 0x10,
                    0x25, 0x74, 0x5C, 0x05, 0x62, 0x78, 0xF4, 0x8A},
    .iv          = {101,102,103,104,105,106,107,108},
    .counter     = {109, 110, 111, 112, 113, 114, 115, 116},
    .size        = 64
};


static TestVector const testVectorChaCha12_128 PROGMEM = {
    .name        = "ChaCha12 128-bit",
    .key         = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    .keySize     = 16,
    .rounds      = 12,
    .plaintext   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .ciphertext  = {0xCB, 0xC1, 0xCF, 0x63, 0xE8, 0xD0, 0x62, 0x83,
                    0xFC, 0x12, 0x87, 0x8C, 0x62, 0x09, 0x5B, 0xF8,
                    0x84, 0x93, 0x30, 0xC6, 0xE6, 0x26, 0x87, 0x99,
                    0xB0, 0xD9, 0xC1, 0xE1, 0xD7, 0x58, 0xCA, 0x05,
                    0xFE, 0x46, 0x40, 0xD1, 0xDC, 0x14, 0x68, 0x3C,
                    0xFF, 0x25, 0xF7, 0x70, 0x5F, 0xBF, 0x37, 0xC5,
                    0x29, 0x8F, 0x3C, 0x55, 0x74, 0xDF, 0xF7, 0x49,
                    0x8D, 0xD8, 0xE9, 0xBA, 0x5D, 0xF1, 0x9F, 0xA5},
    .iv          = {101,102,103,104,105,106,107,108},
    .counter     = {109, 110, 111, 112, 113, 114, 115, 116},
    .size        = 64
};

static TestVector const testVectorChaCha8_128 PROGMEM = {
    .name        = "ChaCha8 128-bit",
    .key         = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
    .keySize     = 16,
    .rounds      = 8,
    .plaintext   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .ciphertext  = {0x76, 0x42, 0x84, 0xB4, 0x87, 0x1F, 0x54, 0xAE,
                    0x33, 0xBF, 0x79, 0x3C, 0xE2, 0x78, 0x5B, 0x4D,
                    0xE7, 0x90, 0xF3, 0x8C, 0xB8, 0xF4, 0xA1, 0x56,
                    0x87, 0x8B, 0x54, 0x06, 0xBE, 0x5A, 0x1B, 0x1C,
                    0x30, 0x31, 0xD3, 0xCD, 0x90, 0x34, 0xC8, 0x93,
                    0x2C, 0x0A, 0x5E, 0xC9, 0x4A, 0x1A, 0x66, 0x4C,
                    0x28, 0x94, 0xA9, 0x61, 0xBB, 0xB4, 0xF0, 0x2D,
                    0x59, 0x73, 0x9F, 0xC9, 0xF1, 0xF0, 0x66, 0x05},
    .iv          = {101,102,103,104,105,106,107,108},
    .counter     = {109, 110, 111, 112, 113, 114, 115, 116},
    .size        = 64
};

TestVector testVector;

ChaCha chacha;

byte buffer[128];

bool testCipher_N(ChaCha *cipher, const struct TestVector *test, size_t inc)
{
    byte output[MAX_CIPHERTEXT_SIZE];
    size_t posn, len;

    cipher->clear();
    if (!cipher->setKey(test->key, test->keySize)) {
        Serial.print("setKey ");
        return false;
    }
    if (!cipher->setIV(test->iv, cipher->ivSize())) {
        Serial.print("setIV ");
        return false;
    }
    if (!cipher->setCounter(test->counter, 8)) {
        Serial.print("setCounter ");
        return false;
    }

    memset(output, 0xBA, sizeof(output));

    for (posn = 0; posn < test->size; posn += inc) {
        len = test->size - posn;
        if (len > inc)
            len = inc;
        cipher->encrypt(output + posn, test->plaintext + posn, len);
    }

    if (memcmp(output, test->ciphertext, test->size) != 0) {
        Serial.print(output[0], HEX);
        Serial.print("->");
        Serial.print(test->ciphertext[0], HEX);
        return false;
    }

    cipher->setKey(test->key, test->keySize);
    cipher->setIV(test->iv, cipher->ivSize());
    cipher->setCounter(test->counter, 8);

    for (posn = 0; posn < test->size; posn += inc) {
        len = test->size - posn;
        if (len > inc)
            len = inc;
        cipher->decrypt(output + posn, test->ciphertext + posn, len);
    }

    if (memcmp(output, test->plaintext, test->size) != 0)
        return false;

    return true;
}

void testCipher(ChaCha *cipher, const struct TestVector *test)
{
    bool ok;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    Serial.print(test->name);
    Serial.print(" ... ");

    cipher->setNumRounds(test->rounds);

    ok  = testCipher_N(cipher, test, test->size);
    ok &= testCipher_N(cipher, test, 1);
    ok &= testCipher_N(cipher, test, 2);
    ok &= testCipher_N(cipher, test, 5);
    ok &= testCipher_N(cipher, test, 8);
    ok &= testCipher_N(cipher, test, 13);
    ok &= testCipher_N(cipher, test, 16);

    if (ok)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

void perfCipherSetKey(ChaCha *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    //Serial.print(test->name);
    Serial.print(" SetKey.... ");

    cipher->setNumRounds(test->rounds);
    start = micros();
    for (count = 0; count < 1000; ++count) {
        cipher->setKey(test->key, test->keySize);
        cipher->setIV(test->iv, 8);
    }
    elapsed = micros() - start;

    Serial.print(elapsed / 1000.0);
    Serial.print("us per operation, ");
    Serial.print((1000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");
}

void perfCipherEncrypt(ChaCha *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

   // Serial.print(test->name);
    Serial.print(" Encryption.... ");

    cipher->setNumRounds(test->rounds);
    cipher->setKey(test->key, test->keySize);
    cipher->setIV(test->iv, cipher->ivSize());
    start = micros();
    for (count = 0; count < 500; ++count) {
        cipher->encrypt(buffer, buffer, sizeof(buffer));
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (sizeof(buffer) * 500.0));
    Serial.print("us per byte, ");
    Serial.print((sizeof(buffer) * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt(ChaCha *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

   // Serial.print(test->name);
    Serial.print(" Decryption.... ");

    cipher->setNumRounds(test->rounds);
    cipher->setKey(test->key, test->keySize);
    cipher->setIV(test->iv, cipher->ivSize());
    start = micros();
    for (count = 0; count < 500; ++count) {
        cipher->decrypt(buffer, buffer, sizeof(buffer));
    }
    elapsed = micros() - start;

    Serial.print(elapsed / (sizeof(buffer) * 500.0));
    Serial.print("us per byte, ");
    Serial.print((sizeof(buffer) * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipher(ChaCha *cipher, const struct TestVector *test)
{
    perfCipherSetKey(cipher, test);
    perfCipherEncrypt(cipher, test);
    perfCipherDecrypt(cipher, test);
}

void setup()
{
    Serial.begin(115200);
    Serial.print("State Size ...");
    Serial.println(sizeof(ChaCha));

    /*Serial.println("Test Vectors:");
    testCipher(&chacha, &testVectorChaCha20_128);
    testCipher(&chacha, &testVectorChaCha20_256);
    testCipher(&chacha, &testVectorChaCha12_128);
    testCipher(&chacha, &testVectorChaCha12_256);
    testCipher(&chacha, &testVectorChaCha8_128);
    testCipher(&chacha, &testVectorChaCha8_256);*/

   // Serial.println();

    Serial.println("Performance Tests:");
    perfCipher(&chacha, &testVectorChaCha20_128);
    perfCipher(&chacha, &testVectorChaCha12_128);
    perfCipher(&chacha, &testVectorChaCha8_128);
}

void loop()
{
  setup();
  delay(5000);
}
