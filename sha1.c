#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <stdbool.h>

int main(int argc, char* argv[]) {
  bool showWords = false;
  bool showProcess = false;
  bool showBlocks = false;
  // Parse command line arguments
  for(int i = 0; i < argc; i++) {
    if(strcmp(argv[i], "--words") == 0) {
      showWords = true;
    }
    if(strcmp(argv[i], "--process") == 0) {
      showProcess = true;
    }
  }


  // Max input length in characters
  #define MAX_INPUT_LENGTH 4096
  char input[MAX_INPUT_LENGTH] = { 0 };
  char readChar = EOF;
  u_int64_t  inputChars = 0;
  // Read input.
  for(int i = 0; i < MAX_INPUT_LENGTH; i++)
  {
    readChar = getchar(); 
    if(readChar == EOF) break;
    input[i] = readChar;
    inputChars++;
  }

  // SHA1 requires 512 bit blocks of input. 
  // Split input into 512 bit (64 char) blocks.
  // Add 1 because integer division drops the fractional component (and we need a round value minimum 1 anyway)
  // Add 8 to the number of input characters because we need 64 bits (8 chars) reserved for the length of the message.
  int numBlocks = ((inputChars + 8) / 64) + 1;
  char* blocks[numBlocks];

  // Allocate blocks of memory for splitting input
  for(int i = 0; i < numBlocks; i++)
  {
    blocks[i] = (char*)calloc(16, 32);
  }

  for(int i = 0; i < numBlocks; i++)
  {
    for(int j = 0; j < 64; j++)
    {
      blocks[i][j] = input[(64 * i) + j];
    }
  }

  // The last block of SHA1 input is padded until 448 bits u_int32_t, and then a 64 bit representation of the original message length is appended.
  // Calculate how many characters are in the final block
  int numCharsInFinalBlock = inputChars - ((numBlocks - 1) * 64);
  // Calculate bytes to pad. 56 is used here because the last 8 bytes are used for message length (64 bits),
  int bytesToPad = 56 - numCharsInFinalBlock;

  // Perform padding. Padding adds 1000 0000 (128 in decimal), then 0's.
  if(bytesToPad > 0)
  {
    blocks[numBlocks - 1][numCharsInFinalBlock] = -128;
    bytesToPad--;
    for(int i = numCharsInFinalBlock + 1; i < bytesToPad; i++)
    {
      blocks[numBlocks - 1][i] = 0;
    }
  }

  // Finally, append the 64 bit representation of message length. 
  // Convert the input length into big endian byte order before appending. 
  // Then split the inputChars into 8 bytes and append one by one. 
  u_int64_t inputCharsBigEndian = htobe64(inputChars * 8);
  char* inputCharsBytes = (char *)&inputCharsBigEndian;
  for(int i = 0; i < 8; i++)
  {
    blocks[numBlocks - 1][56 + i] = inputCharsBytes[i];
  }
  
  // Define SHA 1 constants.
  u_int32_t K0 = 0x5A827999;
  u_int32_t K1 = 0x6ED9EBA1;
  u_int32_t K2 = 0x8F1BBCDC;
  u_int32_t K3 = 0xCA62C1D6;
  u_int32_t kArray[80];

  // Initialize buffers and starting values are defined in the spec. 
  u_int32_t buffer1[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0  };
  u_int32_t* A = &(buffer1[0]);
  u_int32_t* B = &(buffer1[1]);
  u_int32_t* C = &(buffer1[2]);
  u_int32_t* D = &(buffer1[3]);
  u_int32_t* E = &(buffer1[4]);

  u_int32_t buffer2[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0  };
  u_int32_t* H0 = &(buffer2[0]);
  u_int32_t* H1 = &(buffer2[1]);
  u_int32_t* H2 = &(buffer2[2]);
  u_int32_t* H3 = &(buffer2[3]);
  u_int32_t* H4 = &(buffer2[4]);

  u_int32_t sequence[80] = { 0 };
  u_int32_t TEMP = 0;

  // Create an array of function pointers and constants we can easily access later.
  u_int32_t (*sha1functions[80]) (u_int32_t, u_int32_t, u_int32_t);
  for(int i = 0; i <= 19; i++) {
    sha1functions[i] = sha1_f0;
    kArray[i] = K0;
  }  
  for(int i = 20; i <= 39; i++) {
    sha1functions[i] = sha1_f1;
    kArray[i] = K1;
  }
  for(int i = 40; i <= 59; i++) {
    sha1functions[i] = sha1_f2;
    kArray[i] = K2;
  }
   for(int i = 60; i <= 79; i++) {
    sha1functions[i] = sha1_f1;
    kArray[i] = K3;
  } 

  // Loop over message blocks
  for(int i = 0; i < numBlocks; i++)
  {
    // Split block into 16 32-bit words as per the spec

    u_int32_t* block32 = (u_int32_t*)blocks[i];
    
    int t = 0;
    for(t = 0; t < 16; t++ ) {
      sequence[t] = htobe32(block32[t]);
      if(showWords) { printf("Word %d: %lX\n", t, sequence[t]); }
    }

    for(t = 16; t <= 79; t++ ) {
      sequence[t] = circularShift((sequence[t-3] ^ sequence[t-8] ^ sequence[t-14] ^ sequence[t-16]), 1);   
    }

    (*A) = (*H0);
    (*B) = (*H1);
    (*C) = (*H2);
    (*D) = (*H3);
    (*E) = (*H4);
    //printf("%lX\n", *B);

    for(t = 0; t <= 79; t++) {
      TEMP = circularShift(*A, 5) + ((*sha1functions[t]) (*B, *C, *D)) + (*E) + sequence[t] + kArray[t];
      u_int32_t test = sha1_f1(*B, *C, *D);
      (*E) = (*D);
      (*D) = (*C);
      (*C) = circularShift((*B), 30);
      (*B) = (*A);
      (*A) = TEMP;
      if(showProcess) { printf("t: %d - A:%lX B:%lX C:%lX D:%lX E:%lX \n", t, *A, *B, *C, *D, *E); }
    }

    (*H0) += (*A);
    (*H1) += (*B);
    (*H2) += (*C);
    (*H3) += (*D);
    (*H4) += (*E);
  }
  printf("%lX%lX%lX%lX%lX\n", *H0, *H1, *H2, *H3, *H4);
  return 0;
}
