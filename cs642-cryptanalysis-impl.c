////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.c
//  Description    : This is the development program for the cs642 first project
//  that
//                   performs cryptanalysis on ciphertext of different ciphers.
//                   See associated documentation for more information.
//
//   Author        : *** INSERT YOUR NAME ***
//   Last Modified : *** DATE ***
//

// Include Files
#include "compsci642_log.h"

// Project Include Files
#include "cs642-cryptanalysis-support.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


//
// Functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentInit
// Description  : This is a function that is called before any cryptanalysis
//                occurs. Use it if you need to initialize some datastructures
//                you may be reusing across ciphers.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentInit(void) {

  // ADD CODE HERE IF NEEDED

  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformROTXCryptanalysis
// Description  : This is the function to cryptanalyze the ROT X cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformROTXCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, uint8_t *key) {

  int i;
  uint8_t k;
  char *cipherdup = strdup(ciphertext);
  int dictSize = cs642GetDictSize();

  for (i = 0; i < dictSize; i++) {
      struct DictWord word = cs642GetWordfromDict(i);
      printf("%s --> %d\n", word.word, word.count);
  }

  for (k = 1; k < 26; k++) {
      for (i = 0; i < clen; i++) {
          if (ciphertext[i] == ' ')
              continue;

          int rotChr = (int)ciphertext[i] - k;
          cipherdup[i] = rotChr < (int)'A' ? (int)'Z' - ((int)'A' - rotChr) + 1: (char)rotChr;
      }
      printf("[ROT %d] Possible Plaintext: %s\n", k, cipherdup);
  }
  /*int result = cs642Decrypt(CIPHER_ROTX, (char*)key, 11, plaintext, plen, ciphertext, clen);*/

  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformVIGECryptanalysis
// Description  : This is the function to cryptanalyze the Vigenere cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformVIGECryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {

  // ADD CODE HERE

  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642PerformSUBSCryptanalysis
// Description  : This is the function to cryptanalyze the substitution cipher
//
// Inputs       : ciphertext - the ciphertext to analyze
//                clen - the length of the ciphertext
//                plaintext - the place to put the plaintext in
//                plen - the length of the plaintext
//                key - the place to put the key in
// Outputs      : 0 if successful, -1 if failure

int cs642PerformSUBSCryptanalysis(char *ciphertext, int clen, char *plaintext,
                                  int plen, char *key) {

  // ADD CODE HERE

  // Return successfully
  return (0);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : cs642StudentCleanUp
// Description  : This is a clean up function called at the end of the
//                cryptanalysis of the different ciphers. Use it if you need to
//                release memory you allocated in cs642StudentInit() for
//                instance.
//
// Inputs       : void
// Outputs      : 0 if successful, -1 if failure

int cs642StudentCleanUp(void) {

  // ADD CODE HERE IF NEEDED

  // Return successfully
  return (0);
}
