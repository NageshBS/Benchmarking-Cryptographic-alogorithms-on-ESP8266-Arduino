#include <Crypto.h>
#include <AES.h>
#include <string.h>

//key[16] cotain 16 byte key(128 bit) for encryption
byte key[16]={0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
//plaintext[16] contain the text we need to encrypt
byte plaintext[16]={0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
//cypher[16] stores the encrypted text
byte cypher[16];
//decryptedtext[16] stores decrypted text after decryption
byte decryptedtext[16];
//creating an object of AES128 class
AES aes;


void setup() {
  Serial.begin(115200);
  aes.set_key(key,16);// Setting Key for AES
  
  Serial.print("\nBefore Encryption:");
  for(int i=0; i<sizeof(plaintext); i++){
    Serial.print(plaintext[i]);
   }
   
  aes.encrypt(cypher,plaintext);//cypher->output block and plaintext->input block
  Serial.println();
  Serial.print("After Encryption:");
  for(int j=0;j<sizeof(cypher);j++){
      Serial.write(cypher[j]);
    }
    
   aes.decrypt(decryptedtext,cypher);
   
  Serial.println();
  Serial.print("After Dencryption:");
  for(int i=0; i<sizeof(decryptedtext); i++){
    Serial.print(decryptedtext[i]);
   }

}
void loop() {
  // put your main code here, to run repeatedly:
  setup();
  delay(5000);
}
