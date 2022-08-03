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

static TestVector const testVectorSpeck128 = {
    .name        = "Speck-128-ECB",
    .key         = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
                    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00},
    .plaintext   = {0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20,
                    0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20},
    .ciphertext  = {0xa6, 0x5d, 0x98, 0x51, 0x79, 0x78, 0x32, 0x65,
                    0x78, 0x60, 0xfe, 0xdf, 0x5c, 0x57, 0x0d, 0x18}
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
    testCipher(&speckSmall, &testVectorSpeck128, 16);
    Serial.println();

    Serial.println("SpeckSmall Performance Tests:");
    perfCipher(&speckSmall, &testVectorSpeck128, 16);
    Serial.println();


   
}

void loop()
{
  setup();
  delay(5000);
}
