#include <Crypto.h>
#include <ChaCha.h>
#include <string.h>
#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#define MAX_PLAINTEXT_SIZE  16
#define MAX_CIPHERTEXT_SIZE 16

unsigned long startTime;
unsigned long lastYield = 0;
bool useRNG = true;

int randomBitRaw(void) {
  // Needed to keep wifi stack running smoothly
  // And to avoid wdt reset
  if (lastYield == 0 || millis() - lastYield >= 50) {
    yield();
    lastYield = millis();
  }
  uint8_t bit = analogRead(A0); 
      //using A0 / TOUT

  return bit & 1;
}
int randomBi(void) {
  // Software whiten bits using Von Neumann algorithm
  //
  // von Neumann, John (1951). "Various techniques used in connection
  // with random digits". National Bureau of Standards Applied Math Series
  // 12:36.
  //
  for(;;) {
    int a = randomBitRaw() | (randomBitRaw()<<1);
    if (a==1) return 0; // 1 to 0 transition: log a zero bit
    if (a==2) return 1; // 0 to 1 transition: log a one bit
    // For other cases, try again.
  }
  return 0;
}

char randomByt(void) {
  char result = 0;
  uint8_t i;
  for (i=8; i--;) result += result + randomBi();
  return result;
}
int rando(int howBig) {
  int randomValue;
  int topBit;
  int bitPosition;

  if (!howBig) return 0;
  randomValue = 0;
  if (howBig & (howBig-1)) {
    // Range is not a power of 2 - use slow method
    topBit = howBig-1;
    topBit |= topBit>>1;
    topBit |= topBit>>2;
    topBit |= topBit>>4;
    topBit |= topBit>>8;
    topBit |= topBit>>16;
    topBit = (topBit+1) >> 1;

    bitPosition = topBit;
    do {
      // Generate the next bit of the result
      if (randomBi()) randomValue |= bitPosition;

      // Check if bit
      if (randomValue >= howBig) {
        // Number is over the top limit - start again.
        randomValue = 0;
        bitPosition = topBit;
      } else {
        // Repeat for next bit
        bitPosition >>= 1;
      }
    } while (bitPosition);
  } else {
    // Special case, howBig is a power of 2
    bitPosition = howBig >> 1;
    while (bitPosition) {
      if (randomBi()) randomValue |= bitPosition;
      bitPosition >>= 1;
    }
  }
  return randomValue;
}

struct TestVector
{
    const char *name;
    byte key[8];
    size_t keySize;
    uint8_t rounds;
    byte plaintext[MAX_PLAINTEXT_SIZE];
    byte ciphertext[MAX_CIPHERTEXT_SIZE];
    byte iv[4];
    byte counter[4];
    size_t size;
};

// Use the test vectors from section 9 of the Salsa20 specification,
// http://cr.yp.to/snuffle/spec.pdf, but modify the ciphertext to
// the expected output from ChaCha20/12/8.  Unfortunately the ChaCha
// specification doesn't contain test vectors - these were generated
// using the reference implementation from http://cr.yp.to/chacha.html.

static TestVector const testVectorChaCha20_128 PROGMEM = {
    .name        = "ChaCha20 128-bit",
    .key         ={1,2,3,4},
    .keySize     = 4,
    .rounds      = 5,
    .plaintext   = {0x02, 0x04, 0x05, 0x03,
                    0x00, 0x00, 0x07, 0x08, 
                    0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00},
    .ciphertext  = {0x1C, 0x91, 0xE7, 0x99, 
                    0xEC, 0xE9, 0x24, 0x35, 
                    0x33, 0x05, 0xCC, 0x17,
                    0xA0, 0xCA, 0xB8, 0x36},
    .iv          = {101,102,103,104},
    .counter     = {109, 110, 111, 112},
    .size        = 16
};

TestVector testVector;

ChaCha chacha;

byte buffer[32];

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
   /* Serial.print("\nAfter Encryption :\n ");
    for(int i=0;i<sizeof(output);i++){
      Serial.print(output[i],HEX);
    }
    /*if (memcmp(output, test->ciphertext, test->size) != 0) {
        /*Serial.print(output[0], HEX);
        Serial.print("->");
        Serial.print(test->ciphertext[0], HEX);
        return false;
    
    
    cipher->setKey(test->key, test->keySize);
    cipher->setIV(test->iv, cipher->ivSize());
    cipher->setCounter(test->counter, 8);

    for (posn = 0; posn < test->size; posn += inc) {
        len = test->size - posn;
        if (len > inc)
            len = inc;
        cipher->decrypt(output + posn, test->ciphertext + posn, len);
    }
   /* Serial.print("\nAfter Decryption :\n ");
    for(int k = 0 ; k < sizeof(output) ; k++){
      Serial.print(output[k],HEX);
    }
    Serial.println();
    if (memcmp(output, test->plaintext, test->size) != 0)
        return false;

    return true;
}

void testCipher(ChaCha *cipher, const struct TestVector *test)
{
    bool ok;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    /*Serial.print(test->name);
    Serial.print(" ... ");

    cipher->setNumRounds(test->rounds);

    ok  = testCipher_N(cipher, test, test->size);
    ok &= testCipher_N(cipher, test, 1);
    ok &= testCipher_N(cipher, test, 2);
    ok &= testCipher_N(cipher, test, 5);
    ok &= testCipher_N(cipher, test, 8);
    ok &= testCipher_N(cipher, test, 13);
    ok &= testCipher_N(cipher, test, 16);

}*/

void perfCipherSetKey(ChaCha *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;
    for(int i=0;i<sizeof(test->plaintext);i++){
      Serial.print(test->plaintext[i],HEX);
    }
    //Serial.print(test->name);
    //Serial.print(" SetKey ... ");

    cipher->setNumRounds(test->rounds);
    start = micros();
    for (count = 0; count < 100; ++count) {
        cipher->setKey(test->key, test->keySize);
        cipher->setIV(test->iv, 8);
    }
    elapsed = micros() - start;

    /*Serial.print(elapsed / 1000.0);
    Serial.print("us per operation, ");
    Serial.print((1000.0 * 1000000.0) / elapsed);
    Serial.println(" per second");*/
}

void perfCipherEncrypt(ChaCha *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;

    /*Serial.print(test->name);
    Serial.print(" Encrypt ... ");*/

    cipher->setNumRounds(test->rounds);
    cipher->setKey(test->key, test->keySize);
    cipher->setIV(test->iv, cipher->ivSize());
    start = micros();
    for (count = 0; count < 50; ++count) {
        cipher->encrypt(test->ciphertext, test->plaintext, sizeof(test->ciphertext));
    }
    Serial.println("\nAfter ENcryption");
    for(int i = 0 ; i < sizeof(test->ciphertext) ; i++){
      Serial.print(test->ciphertext[i],HEX);
    }
    elapsed = micros() - start;

    /*Serial.print(elapsed / (sizeof(buffer) * 500.0));
    Serial.print("us per byte, ");
    Serial.print((sizeof(buffer) * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");*/
}

void perfCipherDecrypt(ChaCha *cipher, const struct TestVector *test)
{
    unsigned long start;
    unsigned long elapsed;
    int count;

    memcpy_P(&testVector, test, sizeof(TestVector));
    test = &testVector;
      
    //Serial.print(test->name);
    //Serial.print(" Decrypt ... ");

    cipher->setNumRounds(test->rounds);
    cipher->setKey(test->key, test->keySize);
    cipher->setIV(test->iv, cipher->ivSize());
    start = micros();
    for (count = 0; count < 50; ++count) {
        cipher->decrypt(buffer, buffer, sizeof(buffer));
    }
    Serial.print("\nAfter decryption\n");
    for(int i=0;i<sizeof(buffer);i++){
      Serial.print(buffer[i],HEX);
    }
    elapsed = micros() - start;

    /*Serial.print(elapsed / (sizeof(buffer) * 500.0));
    Serial.print("us per byte, ");
    Serial.print((sizeof(buffer) * 500.0 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");*/
}

void perfCipher(ChaCha *cipher, const struct TestVector *test)
{
    perfCipherSetKey(cipher, test);
    perfCipherEncrypt(cipher, test);
    perfCipherDecrypt(cipher, test);
}
void setup()
{
    Serial.begin(9600);

   /* Serial.println();

    Serial.print("State Size ...");
    Serial.println(sizeof(ChaCha));
    Serial.println();*/

    //Serial.println("Test Vectors:");
//    testCipher(&chacha, &testVectorChaCha20_128);
    /*testCipher(&chacha, &testVectorChaCha20_256);
    testCipher(&chacha, &testVectorChaCha12_128);
    testCipher(&chacha, &testVectorChaCha12_256);
    testCipher(&chacha, &testVectorChaCha8_128);
    testCipher(&chacha, &testVectorChaCha8_256);*/

    //Serial.println();

    //Serial.println("Performance Tests:");
    perfCipher(&chacha, &testVectorChaCha20_128);
}

void loop()
{
  setup();
  delay(5000);
}
