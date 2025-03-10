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
    printf("%s\n", matrix[i]);
    /*for (int j = 0; j < cols; j++) {*/
    /*  printf("%c", matrix[i][j]);*/
    /*}*/
    /*printf("\n");*/
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

void createRowCipherMatrix(char *ciphertext, int clen, char **matrix, int rows, int cols) {
  int i, j;
  int cnt = 0;
  for (i = 0; i < rows - 1; i++) {
    matrix[i] = malloc(cols * sizeof(char));
    for (j = 0; j < cols - 1; j++) {
      if (cnt >= clen) break;
      matrix[i][j] = ciphertext[cnt];
      cnt++;
    }
    matrix[i][j] = '\0';
  }
  printMatrix(matrix, rows - 1, cols - 1);
}

void createColCipherMatrix(char **rowMatrix, int rows, int cols, char **colMatrix) {
    int i, j;
    int n, csize;
    char *column;

    for (j = 0; j < cols - 1; j++) {
      n = 0;
      csize = 2;
      column = malloc(csize * sizeof(char));
      for (i = 0; i < rows; i++) {
        char chr = rowMatrix[i][j];
        if ((!isupper(chr) && chr != ' ') || chr == '\0')
            break;

        if (n >= csize) {
            csize *= 2;
            column = realloc(column, csize);
        }
        printf("[LOG] cipherMatrix cell: %c\n", chr);
        column[i] = chr;
        n++;
      }
      column[i] = '\0';
      colMatrix[j] = malloc(strlen(column) + 1);
      strcpy(colMatrix[j], column);
      free(column);
    }
    printMatrix(colMatrix, rows - 1, cols - 1);
}

float friedmanTotal(char **cipherMatrix, int rows, int cols) {
  int i, j;
  float freqSum;
  float Ko, friedman, friedmanTotal = 0;

  for (i = 0; i < rows - 1; i++) {
    char *subcipher = cipherMatrix[i];
    int N = strlen(subcipher);
    int freqs[NALPHABETS] = {0};
    getLetterFreqs(subcipher, N, freqs);

    freqSum = 0;
    for (j = 0; j < NALPHABETS; j++) {
      if (freqs[j] > 0)
        freqSum += (freqs[j] * (freqs[j] - 1));
    }
    Ko = freqSum / (N * (N + 1));
    friedman = (Kp - Kr) / (Ko - Kr);
    friedmanTotal += friedman;

    printf("[LOG] freqSum: %f\n", freqSum);
    printf("[LOG] friedman: %f\n", friedman);
    printf("[LOG] friedmanTotal: %f\n", friedmanTotal);
    printf("[LOG] colMatrix row %s\n", cipherMatrix[i]);
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

  char *test = "ABC DEFG SOMETHING LMAO AMAZING RANDOM";
  int tlen = strlen(test);
  printf("[LOG] testString: %s, length: %d\n", test, tlen);

  int i, j, k;
  int rows, cols;
  char **rowCipherMatrix, **colCipherMatrix, **maxFriedmanMatrix;
  int keySize, maxFriedmanKeySize = 0;
  float friedmanAvg;
  float maxFriedmanAvg = 0;
  double chiScore, minChiScore = INFINITY;

  // determine key size
  for (keySize = 6; keySize < 12; keySize++) {
    /*rows = (clen % keySize) == 0 ? (clen / keySize) : (clen / keySize + 1);*/
    rows = (tlen % keySize) == 0 ? (tlen / keySize) + 1: (tlen / keySize + 2);
    cols = keySize + 1;
    // TO-DO: don't need row matrix - directly create column matrix ?
    rowCipherMatrix = malloc(rows * sizeof(char*));
    // TO-DO: seg fault
    colCipherMatrix = malloc(cols * sizeof(char*));
    maxFriedmanMatrix = malloc(cols * sizeof(char*));
    /*createCipherMatrix(ciphertext, clen, cipherMatrix, rows, cols);*/
    createRowCipherMatrix(test, tlen, rowCipherMatrix, rows, cols);
    createColCipherMatrix(rowCipherMatrix, cols, rows, colCipherMatrix);
    friedmanAvg = friedmanTotal(colCipherMatrix, cols, rows) / keySize;
    if (friedmanAvg > maxFriedmanAvg) {
      maxFriedmanAvg = friedmanAvg;
      maxFriedmanKeySize = keySize;
      memcpy(&maxFriedmanMatrix, &colCipherMatrix, sizeof(colCipherMatrix));
    }
    freev((void*)colCipherMatrix, cols, 1);
    freev((void*)rowCipherMatrix, rows, 1);
  }
  printf("[LOG] maxFriedmanKeySize: %d\n", maxFriedmanKeySize);

  // brute-force the key
  char *finalKey = malloc(maxFriedmanKeySize * sizeof(char));
  for (i = 0; i < maxFriedmanKeySize; i++) {
    int N = strlen(maxFriedmanMatrix[i]);
    char *subcipher = strdup(maxFriedmanMatrix[i]);
    for (k = 1; k < NALPHABETS; k++) {
      for (j = 0; j < N; j++) {
        char chr = maxFriedmanMatrix[i][j];
        if (chr == ' ') continue;
         subcipher[j] = rotByX(chr, k);
      }
      chiScore = chiSquared(subcipher, N);
      if (chiScore < minChiScore) {
        minChiScore = chiScore;
        finalKey[i] = (char)((int)'A' + k);
      }
    }
  }
  strcpy(key, finalKey);
  cs642Decrypt(CIPHER_VIGE, key, maxFriedmanKeySize, plaintext, plen, ciphertext, clen);

  free(finalKey);
  freev((void*)maxFriedmanMatrix, maxFriedmanKeySize, 1);
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
