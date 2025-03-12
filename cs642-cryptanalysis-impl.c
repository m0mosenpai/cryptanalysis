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
#include <ctype.h>
#include <math.h>

#define MIN_KEYSIZE 6
#define MAX_KEYSIZE 12
#define NALPHABETS 26
#define Kp 0.067
#define Kr 0.0385

const float E[NALPHABETS] = {
    0.08167,
    0.01492,
    0.02782,
    0.04253,
    0.12702,
    0.02228,
    0.02015,
    0.06094,
    0.06966,
    0.00153,
    0.00772,
    0.04025,
    0.02406,
    0.06749,
    0.07507,
    0.01929,
    0.00095,
    0.05987,
    0.06327,
    0.09056,
    0.02758,
    0.00978,
    0.02360,
    0.00150,
    0.01974,
    0.00074
};

void freev(void **ptr, int len, int free_seg) {
    if (len < 0) while (*ptr) { free(*ptr); *ptr++ = NULL; }
    else { for (int i = 0; i < len; i++) free(ptr[i]); }
    if (free_seg) free(ptr);
}

void printMatrix(char **matrix, int rows, int cols) {
  printf("[LOG] Matrix:\n");
  for (int i = 0; i < rows; i++) {
    /*printf("%s\n", matrix[i]);*/
    for (int j = 0; j < cols; j++) {
      printf("%c", matrix[i][j]);
    }
    printf("\n");
  }
}

char rotByX(char chr, int x) {
  int rotChr = (int)chr - x;
  return rotChr < (int)'A' ? (int)'Z' - ((int)'A' - rotChr) + 1: (char)rotChr;
}

void checkDictionary(char *inputWord, int *dictMatches) {
  int j;
  int dictSize = cs642GetDictSize();

  for (j = 0; j < dictSize; j++) {
    struct DictWord dictWord = cs642GetWordfromDict(j);
    if (strcmp(inputWord, dictWord.word) == 0) {
      *dictMatches = *dictMatches + 1;
    }
  }
}

void getLetterFreqs(char *ciphertext, int clen, int *counts) {
  for (int i = 0; i < clen; i++) {
    char chr = ciphertext[i];
    if (isupper(chr)) {
      int idx = (int)chr - (int)'A';
      counts[idx]++;
    }
  }
}

void createCipherMatrix(char *ciphertext, int clen, int rows, int cols, char **matrix) {
  int i, j, c_i = 0;

  for (j = 0; j < cols; j++) {
    for (i = 0; i < rows; i++) {
      /*printf("[LOG] ciphertext chr: %c, idx: %d\n", ciphertext[c_i], c_i);*/
      if (j == 0) matrix[i] = malloc(cols * sizeof(char));
      if (c_i >= clen) {matrix[i][j] = '\0'; return;}
      matrix[i][j] = ciphertext[c_i++];
      /*printf("[LOG] matrix chr: %c\n", matrix[i][j]);*/
    }
  }
}

float friedmanTotal(char **cipherMatrix, int clen, int rows, int cols) {
  int i, j, N;
  float freqSum;
  float Ko, friedmanTotal = 0;

  for (i = 0; i < rows; i++) {
    // take each row value as a separate rotx cipher
    char subcipher[cols];
    for (j = 0; j < cols && cipherMatrix[i][j]; j++) {
      char chr = cipherMatrix[i][j];
      if (isupper(chr) || chr == ' ') {
        subcipher[j] = chr;
      }
    }

    // get letter frequencies in row
    N = strlen(subcipher);
    int freqs[NALPHABETS] = {0};
    getLetterFreqs(subcipher, N, freqs);

    // do Friedman's Test
    freqSum = 0;
    for (j = 0; j < NALPHABETS; j++) {
      if (freqs[j] > 0)
        freqSum += (freqs[j] * (freqs[j] - 1));
    }
    Ko = freqSum / (N * (N - 1));
    /*friedman = (Kp - Kr) / (Ko - Kr);*/
    /*friedmanTotal += friedman;*/
    friedmanTotal += Ko;

    /*printf("[LOG] freqSum: %f\n", freqSum);*/
    /*printf("[LOG] friedman: %f\n", friedman);*/
    /*printf("[LOG] friedmanTotal: %f\n", friedmanTotal);*/
    /*printf("[LOG] colMatrix row %s\n", subcipher);*/
  }
  return friedmanTotal;
}

double chiSquared(char *cipher, int n) {
  int i, idx;
  double Oi, Ei, total = 0;
  int O[NALPHABETS] = {0};
  getLetterFreqs(cipher, n, O);

  for (i = 0; i < n; i++) {
    if (isupper(cipher[i])) {
      idx = (int)cipher[i] - (int)'A';
      Oi = O[idx];
      Ei = E[idx] * n;
      total += (pow(Oi - Ei, 2) / Ei);
    }
  }
  return total;
}


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
  char *decryption = strdup(ciphertext);
  int maxMatches = 0;

  for (k = 1; k < NALPHABETS; k++) {
    for (i = 0; i < clen; i++) {
      if (ciphertext[i] == ' ')
        continue;
      decryption[i] = rotByX(ciphertext[i], k);
    }
    char *decryptionDup = strdup(decryption);
    char *delim = " ";
    char *tok = strtok(decryptionDup, delim);
    int dictMatches = 0;
    while (tok != NULL) {
      checkDictionary(tok, &dictMatches);
      if (dictMatches > maxMatches) {
        maxMatches = dictMatches;
        *key = k;
        strcpy(plaintext, decryption);
      }
      tok = strtok(NULL, delim);
    }
  }
  return 0;
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

  int i, j, k;
  int rows, cols;
  char **cipherMatrix, **maxFriedmanMatrix;
  int keysize, maxFriedmanKeysize = 0;
  double friedman, friedmanAvg;
  double maxFriedmanAvg = 0;
  double chiScore, minChiScore = INFINITY;

  // test all possible key sizes
  for (keysize = MIN_KEYSIZE; keysize < MAX_KEYSIZE; keysize++) {
    rows = keysize;
    cols = (clen % keysize) == 0 ? (clen / keysize): (clen / keysize + 1);
    // transposed matrix - each row is a rotx cipher
    cipherMatrix = malloc(rows * sizeof(char*));
    createCipherMatrix(ciphertext, clen, rows, cols, cipherMatrix);
    friedman = friedmanTotal(cipherMatrix, clen, rows, cols);
    friedmanAvg = friedman / keysize;
    printf("[LOG] [Keysize: %d] Friedman Total: %f, FriedmanAvg: %f\n", keysize, friedman, friedmanAvg);
    if (friedmanAvg > maxFriedmanAvg) {
      maxFriedmanAvg = friedmanAvg;
      maxFriedmanKeysize = keysize;
    }
    freev((void*)cipherMatrix, rows, 1);
  }

  rows = maxFriedmanKeysize;
  cols = (clen % keysize) == 0 ? (clen / keysize): (clen / keysize + 1);
  maxFriedmanMatrix = malloc(rows * sizeof(char*));
  createCipherMatrix(ciphertext, clen, rows, cols, maxFriedmanMatrix);
  printf("[LOG] maxFriedmanKeysize: %d\n", maxFriedmanKeysize);

  // brute-force the key with most-probable keysize
  char *finalKey = malloc(maxFriedmanKeysize * sizeof(char));
  for (i = 0; i < maxFriedmanKeysize; i++) {
    int N = strlen(maxFriedmanMatrix[i]);
    char *subcipher = strdup(maxFriedmanMatrix[i]);
    for (k = 1; k < NALPHABETS; k++) {
      for (j = 0; j < N; j++) {
        char chr = maxFriedmanMatrix[i][j];
        if (isupper(chr)) {
          subcipher[j] = rotByX(chr, k);
        }
      }
      chiScore = chiSquared(subcipher, N);
      if (chiScore < minChiScore) {
        minChiScore = chiScore;
        finalKey[i] = (char)((int)'A' + k);
      }
    }
  }
  strcpy(key, finalKey);
  printf("[LOG] output key: %s\n", key);
  cs642Decrypt(CIPHER_VIGE, key, maxFriedmanKeysize, plaintext, plen, ciphertext, clen);

  free(finalKey);
  freev((void*)maxFriedmanMatrix, rows, 1);
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
