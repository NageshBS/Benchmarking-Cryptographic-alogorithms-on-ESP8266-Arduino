#include <Crypto.h>
#include <Speck.h>
#include <SpeckSmall.h>
#include <SpeckTiny.h>
#include <string.h>

struct TestVector
{
    const char *name;
    byte key[32];
    byte plaintext[16];
    byte ciphertext[16];
};

static TestVector const testVectorSpeck256 = {
    .name        = "Speck-256-ECB",
    .key         = {0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
                    0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
                    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
                    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00},
    .plaintext   = {0x65, 0x73, 0x6f, 0x68, 0x74, 0x20, 0x6e, 0x49,
                    0x20, 0x2e, 0x72, 0x65, 0x6e, 0x6f, 0x6f, 0x70},
    .ciphertext  = {0x41, 0x09, 0x01, 0x04, 0x05, 0xc0, 0xf5, 0x3e,
                    0x4e, 0xee, 0xb4, 0x8d, 0x9c, 0x18, 0x8f, 0x43}
};

SpeckSmall speckSmall;

byte buffer[16];

void testCipher(BlockCipher *cipher, const struct TestVector *test, size_t keySize, bool decryption = true)
{
    Serial.print(test->name);
    Serial.print(" Encryption ... ");
    cipher->setKey(test->key, keySize);
    cipher->encryptBlock(buffer, test->plaintext);
    for(int i=0;i<sizeof(buffer);i++){
        Serial.print(buffer[i],HEX);
    }
    if (memcmp(buffer, test->ciphertext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");

    if (!decryption)
        return;

    Serial.print(test->name);
    Serial.print(" Decryption ... ");
    cipher->decryptBlock(buffer, test->ciphertext);
    for(int i=0;i<sizeof(buffer);i++){
        Serial.print(buffer[i],HEX);
    }
    if (memcmp(buffer, test->plaintext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}

void perfCipher(BlockCipher *cipher, const struct TestVector *test, size_t keySize, bool decryption = true)
{
    unsigned long start;
    unsigned long elapsed;
    int count;
    Serial.print(test->name);
    Serial.print(" Set Key ... ");
    start = micros();
    for (count = 0; count < 10000; ++count) {
        cipher->setKey(test->key, keySize);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / 10000.0);
    Serial.print("us per operation, ");
    Serial.print((10000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");

    Serial.print(test->name);
    Serial.print(" Encrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->encryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    if (!decryption) {
        Serial.println();
        return;
    }

    Serial.print(test->name);
    Serial.print(" Decrypt ... ");
    start = micros();
    for (count = 0; count < 5000; ++count) {
        cipher->decryptBlock(buffer, buffer);
    }
    elapsed = micros() - start;
    Serial.print(elapsed / (5000.0 * 16.0));
    Serial.print("us per byte, ");
    Serial.print((16.0 * 5000.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");

    Serial.println();
}

void setup()
{
    Serial.begin(115200);

    Serial.println();

    Serial.println("State Sizes:");
    Serial.print("SpeckSmall ... ");
    Serial.println(sizeof(SpeckSmall));
    Serial.println();

    Serial.println("SpeckSmall Test Vectors:");
    testCipher(&speckSmall, &testVectorSpeck256, 32);
    Serial.println();

    Serial.println("SpeckSmall Performance Tests:");
    perfCipher(&speckSmall, &testVectorSpeck256, 32);
    Serial.println();
   
}

void loop()
{
  setup();
  delay(5000);
}
