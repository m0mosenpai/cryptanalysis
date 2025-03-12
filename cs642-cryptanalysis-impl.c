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
  int i, idx;
  char chr;

  for (i = 0; i < clen; i++) {
    chr = ciphertext[i];
    if (isupper(chr)) {
      idx = (int)chr - (int)'A';
      counts[idx]++;
    }
  }
}

int getDictLetterFreqs(int *counts) {
  int i, n;
  int dictSize = cs642GetDictSize();
  int total = 0;

  for (i = 0; i < dictSize; i++) {
    struct DictWord dictword = cs642GetWordfromDict(i);
    n = strlen(dictword.word);
    getLetterFreqs(dictword.word, n, counts);
  }

  for (i = 0; i < NALPHABETS; i++) {
    total += counts[i];
  }
  return total;
}

void createCipherMatrix(char *ciphertext, int clen, int rows, int cols, char **matrix, int spaces) {
  int i, j, c_i = 0;
  char chr;

  for (j = 0; j < cols; j++) {
    for (i = 0; i < rows; i++) {
      /*printf("[LOG] ciphertext chr: %c, idx: %d\n", ciphertext[c_i], c_i);*/
      if (j == 0) matrix[i] = malloc(cols * sizeof(char));
      // to include/ not-include spaces in the matrix
      while (!spaces && c_i < clen && ((chr = ciphertext[c_i]) == ' ')) { c_i++; }
      if (c_i >= clen) { matrix[i][j] = '\0'; return; }
      matrix[i][j] = ciphertext[c_i++];
      /*printf("[LOG] matrix chr: %c\n", matrix[i][j]);*/
    }
  }
}

float friedmanTotal(char **cipherMatrix, int clen, int rows, int cols) {
  int i, j, N = 0;
  float freqSum,friedman;
  float Ko, friedmanTotal = 0;

  for (i = 0; i < rows; i++) {
    // take each row value as a separate rotx cipher
    char subcipher[cols];
    for (j = 0; j < cols && cipherMatrix[i][j]; j++) {
      char chr = cipherMatrix[i][j];
      if (isupper(chr) || chr == ' ') {
        if (isupper(chr)) N++;
        subcipher[j] = chr;
      }
    }

    // get letter frequencies in row
    int freqs[NALPHABETS] = {0};
    getLetterFreqs(subcipher, strlen(subcipher), freqs);

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

double chiSquared(char *cipher, int cn, int *E, int en) {
  int i;
  double Ci, Ei, total = 0;
  int C[NALPHABETS] = {0};
  getLetterFreqs(cipher, strlen(cipher), C);

  for (i = 0; i < NALPHABETS; i++) {
      Ci = (double)C[i] / cn;
      Ei = (double)E[i] / en;
      total += (pow(Ci - Ei, 2) / Ei);
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
  /*enableLogLevels(LOG_INFO_LEVEL);*/
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

  int i, j, k, N;
  int rows, cols, dictLetters;
  int dictFreqs[NALPHABETS] = {0};
  char **cipherMatrix, **maxFriedmanMatrix;
  int keysize, maxFriedmanKeysize = 0;
  double friedman, friedmanAvg;
  double maxFriedmanAvg = 0;
  double chiScore, minChiScore;
  int chiKey;

  /*char *test = "THIS IS A RANDOM STRING";*/
  /*int tlen = strlen(test);*/

  // test all possible key sizes
  for (keysize = MIN_KEYSIZE; keysize < MAX_KEYSIZE; keysize++) {
    rows = keysize;
    cols = (clen % rows) == 0 ? (clen / rows): (clen / rows + 1);
    /*cols = (tlen % rows) == 0 ? (tlen / rows): (tlen / rows + 1);*/
    // transposed matrix - each row is a rotx cipher
    cipherMatrix = malloc(rows * sizeof(char*));
    createCipherMatrix(ciphertext, clen, rows, cols, cipherMatrix, 1);
    /*createCipherMatrix(test, tlen, rows, cols, cipherMatrix, 1);*/
    /*printMatrix(cipherMatrix, rows, cols);*/
    friedman = friedmanTotal(cipherMatrix, clen, rows, cols);
    /*friedman = friedmanTotal(cipherMatrix, tlen, rows, cols);*/
    friedmanAvg = friedman / keysize;
    /*printf("[LOG] [Keysize: %d] Friedman Total: %f, FriedmanAvg: %f\n", keysize, friedman, friedmanAvg);*/
    if (friedmanAvg > maxFriedmanAvg) {
      maxFriedmanAvg = friedmanAvg;
      maxFriedmanKeysize = keysize;
    }
    freev((void*)cipherMatrix, rows, 1);
  }


  rows = maxFriedmanKeysize;
  cols = (clen % rows) == 0 ? (clen / rows): (clen / rows + 1);
  /*cols = (tlen % rows) == 0 ? (tlen / rows): (tlen / rows + 1);*/
  maxFriedmanMatrix = malloc(rows * sizeof(char*));
  createCipherMatrix(ciphertext, clen, rows, cols, maxFriedmanMatrix, 1);
  /*createCipherMatrix(test, tlen, rows, cols, maxFriedmanMatrix, 0);*/
  /*printMatrix(maxFriedmanMatrix, rows, cols);*/
  /*exit(0);*/
  printf("[LOG] maxFriedmanKeysize: %d\n", maxFriedmanKeysize);

  // brute-force the key with most-probable keysize
  dictLetters = getDictLetterFreqs(dictFreqs);
  /*printf("[LOG] dictLetters: %d\n", dictLetters);*/
  /*for (i = 0; i < NALPHABETS; i++) {*/
  /*    printf("%c -> %d, ", (char)((int)'A' + i), dictFreqs[i]);*/
  /*}*/
  char *finalKey = malloc(rows * sizeof(char));
  for (i = 0; i < rows; i++) {
    N = 0;
    char *subcipher = strdup(maxFriedmanMatrix[i]);
    minChiScore = INFINITY;
    for (k = 1; k < NALPHABETS; k++) {
      /*printf("[LOG] trying ROT-%d\n", k);*/
      for (j = 0; j < strlen(subcipher); j++) {
        char chr = maxFriedmanMatrix[i][j];
        if (isupper(chr)) {
          subcipher[j] = rotByX(chr, k);
          N++;
        }
      }
      chiScore = chiSquared(subcipher, N, dictFreqs, dictLetters);
      /*printf("[LOG] chi score: %f\n", chiScore);*/
      if (chiScore < minChiScore) {
        minChiScore = chiScore;
        chiKey = k;
        /*printf("[LOG] min chi score: %f, key: %d\n", chiScore, k);*/
        finalKey[i] = (char)((int)'A' + k);
      }
    }
    printf("[LOG] row: %d -> key: %d\n", i, chiKey);
  }
  finalKey[i] = '\0';
  strcpy(key, finalKey);
  printf("[LOG] output key: %s, length: %zu\n", key, strlen(finalKey));
  cs642Decrypt(CIPHER_VIGE, key, maxFriedmanKeysize, plaintext, plen, ciphertext, clen);
  printf("[LOG] ciphertext: %s, length: %d\n", ciphertext, clen);

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
