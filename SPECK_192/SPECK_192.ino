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

static TestVector const testVectorSpeck192 = {
    .name        = "Speck-192-ECB",
    .key         = {0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
                    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
                    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00},
    .plaintext   = {0x72, 0x61, 0x48, 0x20, 0x66, 0x65, 0x69, 0x68,
                    0x43, 0x20, 0x6f, 0x74, 0x20, 0x74, 0x6e, 0x65},
    .ciphertext  = {0x1b, 0xe4, 0xcf, 0x3a, 0x13, 0x13, 0x55, 0x66,
                    0xf9, 0xbc, 0x18, 0x5d, 0xe0, 0x3c, 0x18, 0x86}
};

Speck speck;

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
    Serial.print("Speck ... ");
    Serial.println(sizeof(Speck));
    Serial.println();

    Serial.println("Speck Test Vectors:");
    testCipher(&speck, &testVectorSpeck192, 24);
    Serial.println();

    Serial.println("Speck Performance Tests:");
    perfCipher(&speck, &testVectorSpeck192, 24);
    Serial.println();

}

void loop()
{
  setup();
  delay(5000);
}
