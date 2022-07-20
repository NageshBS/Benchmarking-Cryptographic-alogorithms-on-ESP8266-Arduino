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

static TestVector const testVectorChaCha20_256 PROGMEM = {
    .name        = "ChaCha20 256-bit",
    .key         = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
                    211, 212, 213, 214, 215, 216},
    .keySize     = 32,
    .rounds      = 20,
    .plaintext   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .ciphertext  = {0x2A, 0x7E, 0x73, 0xC2, 0x2A, 0xE5, 0xCF, 0x4E,
                    0x21, 0x75, 0xB1, 0x26, 0x38, 0x3F, 0x60, 0x84,
                    0x11, 0x25, 0xFC, 0xAD, 0xFD, 0x16, 0x54, 0xF2,
                    0xD7, 0x8C, 0x5D, 0x49, 0x8D, 0x96, 0xBE, 0x15,
                    0xC9, 0x00, 0x12, 0x09, 0x14, 0x43, 0x2D, 0x6D,
                    0x64, 0x33, 0x88, 0xA6, 0x16, 0x39, 0x86, 0xFD,
                    0xD8, 0x85, 0x4D, 0x76, 0x42, 0xEC, 0x0A, 0x0C,
                    0x8A, 0xF2, 0x99, 0x2E, 0x54, 0xAE, 0xB4, 0xD9},
    .iv          = {101,102,103,104,105,106,107,108},
    .counter     = {109, 110, 111, 112, 113, 114, 115, 116},
    .size        = 64
};

static TestVector const testVectorChaCha12_256 PROGMEM = {
    .name        = "ChaCha12 256-bit",
    .key         = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
                    211, 212, 213, 214, 215, 216},
    .keySize     = 32,
    .rounds      = 12,
    .plaintext   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .ciphertext  = {0xB8, 0x49, 0xD4, 0x70, 0xE0, 0xFF, 0x57, 0x12,
                    0x95, 0xBF, 0xD9, 0xCD, 0x26, 0xFD, 0x4D, 0x6E,
                    0x70, 0xA2, 0xBC, 0x58, 0x63, 0xF6, 0x2C, 0xC3,
                    0xC7, 0x1C, 0x9B, 0x1A, 0x54, 0xDC, 0xF9, 0xF8,
                    0xFD, 0x59, 0xEA, 0xC9, 0xC3, 0x10, 0xA1, 0xDE,
                    0xD1, 0x53, 0x84, 0xD6, 0x8D, 0xC6, 0x61, 0x09,
                    0x2E, 0x62, 0x14, 0xC5, 0x77, 0x4B, 0x6B, 0x5B,
                    0x0D, 0x35, 0xE6, 0x17, 0x41, 0x51, 0xA6, 0xA4},
    .iv          = {101,102,103,104,105,106,107,108},
    .counter     = {109, 110, 111, 112, 113, 114, 115, 116},
    .size        = 64
};

static TestVector const testVectorChaCha8_256 PROGMEM = {
    .name        = "ChaCha8 256-bit",
    .key         = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                    201, 202, 203, 204, 205, 206, 207, 208, 209, 210,
                    211, 212, 213, 214, 215, 216},
    .keySize     = 32,
    .rounds      = 8,
    .plaintext   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    .ciphertext  = {0x38, 0x0F, 0x75, 0xD6, 0x32, 0xF8, 0xBB, 0x2C,
                    0x44, 0x81, 0xF4, 0x27, 0x90, 0xB8, 0xAA, 0xE3,
                    0x09, 0xD1, 0xB9, 0x55, 0xC2, 0xF5, 0x85, 0x27,
                    0xBB, 0x8F, 0x43, 0x00, 0x68, 0x2B, 0x2A, 0x1B,
                    0x7A, 0xC1, 0x5B, 0xC3, 0xA3, 0xFF, 0x29, 0xC9,
                    0xD2, 0x95, 0x98, 0xF6, 0x3C, 0xAC, 0x9B, 0x2C,
                    0xA3, 0xF1, 0x40, 0x1E, 0xFA, 0x7C, 0xAC, 0xA3,
                    0xB1, 0x61, 0x27, 0x50, 0xBB, 0x03, 0x24, 0x36},
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
    perfCipher(&chacha, &testVectorChaCha20_256);
    perfCipher(&chacha, &testVectorChaCha12_256);
    perfCipher(&chacha, &testVectorChaCha8_256);
}

void loop()
{
  setup();
  delay(5000);
}
