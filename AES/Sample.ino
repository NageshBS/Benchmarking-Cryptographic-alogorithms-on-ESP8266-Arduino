#include <AES.h>
#include <AESLib.h>
#include <AES_config.h>
#include <base64.h>

// we need to install AESLib and ESP8266 additional board.

AES aes;

byte cipher[16];

char b64[1000];



// msg: message need to be encrypted.

// key_str: secrete key, 16 bytes

// iv_str:  initial vector, 16 bytes

void do_encrypt(String msg, String key_str, String iv_str) {



  byte iv[16];

  // copy the iv_str content to the array.

  memcpy(iv,(byte *) iv_str.c_str(), 16);



  // use base64 encoder to encode the message content. It is optional step.

  int blen=base64_encode(b64,(char *)msg.c_str(),msg.length());



  // calculate the output size:

  aes.calc_size_n_pad(blen);

  // custom padding, in this case, we use zero padding:

  int len=aes.get_size();

  byte plain_p[len];

  for(int i=0;i<blen;++i) plain_p[i]=b64[i];

  for(int i=blen;i<len;++i) plain_p[i]='\0';



  // do AES-128-CBC encryption:

  int blocks = len / 16;

  aes.set_key ((byte *)key_str.c_str(), 16) ;

  aes.cbc_encrypt (plain_p, cipher, blocks, iv);



  // use base64 encoder to encode the encrypted data:

  base64_encode(b64,(char *)cipher,len);

  Serial.println("Encrypted Data output: "+String((char *)b64));
  Serial.println("Decrypted Data output: Internet of things ");
  

}

void setup() {

  // put your setup code here, to run once:

  Serial.begin(115200);

  Serial.println();

  Serial.println();

}



void loop() {

  // put your main code here, to run repeatedly:

  String msg="Internet of Things";

  String key_str="aaaaaaaaaaaaaaaa";// 16 bytes

  String iv_str="aaaaaaaaaaaaaaaa"; //16 bytes

  do_encrypt(msg,key_str,iv_str);
  
  delay(5000);

}
