////////////////////////////////////////////////////////////////////////////////
//
//  File           : cs642-cryptanalysis-impl.c
//  Description    : This is the development program for the cs642 first project
//  that
//                   performs cryptanalysis on ciphertext of different ciphers.
//                   See associated documentation for more information.
//
//   Author        : *** SARTHAK KHATTAR ***
//   Last Modified : *** 03-12-2025 ***
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
#include <time.h>

#define MIN_KEYSIZE 6
#define MAX_KEYSIZE 12
#define NALPHABETS 26
#define Kp 0.067
#define Kr 0.0385
#define NGRAMSIZE 4
#define MAX_NGRAMS 456976
#define SUBS_ITERS 10
#define SUBS_SUBITERS 5000

typedef struct lf {
  char letter;
  int freq;
} LF;

void freev(void **ptr, int len, int free_seg) {
  if (len < 0) while (*ptr) { free(*ptr); *ptr++ = NULL; }
  else { for (int i = 0; i < len; i++) free(ptr[i]); }
  if (free_seg) free(ptr);
}

int comparator(const void *a, const void *b) {
    LF *A = (LF *)a;
    LF *B = (LF *)b;
    return (B->freq - A->freq);
}

void printMatrix(char **matrix, int rows, int cols) {
  for (int i = 0; i < rows; i++) {
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
      if (j == 0) matrix[i] = malloc(cols * sizeof(char));
      // to include/ not-include spaces in the matrix
      while (!spaces && c_i < clen && ((chr = ciphertext[c_i]) == ' ')) { c_i++; }
      if (c_i >= clen) { matrix[i][j] = '\0'; return; }
      matrix[i][j] = ciphertext[c_i++];
    }
  }
}

double friedmanTotal(char **cipherMatrix, int clen, int rows, int cols) {
  int i, j, N;
  double freqSum;
  double Ko, friedmanTotal = 0;

  for (i = 0; i < rows; i++) {
    // take each row value as a separate rotx cipher
    N = 0;
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
    friedmanTotal += Ko;
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
    Ei = ((double)E[i] / en) * cn;
    total += (pow(Ci - Ei, 2) / Ei);
  }
  return total;
}

int getDictNGrams(char ngrams[][NGRAMSIZE]) {
  int i, j, k, n, cnt = 0;
  char ngram[NGRAMSIZE];
  int dictSize = cs642GetDictSize();

  for (i = 0; i < dictSize; i++) {
    struct DictWord dictword = cs642GetWordfromDict(i);
    n = strlen(dictword.word);
    for (j = 0; j < n - NGRAMSIZE + 1; j++) {
      for (k = 0; k < NGRAMSIZE; k++) {
        ngram[k] = dictword.word[j + k];
      }
      strcpy(ngrams[cnt++], ngram);
    }
  }
  return cnt;
}

double getDictNGramProb(char *ngram, char dictNGrams[][NGRAMSIZE], double dictNGramProbs[], int dngcnt) {
  int i = 0;
  for (i = 0; i < dngcnt; i++) {
    if (strncmp(ngram, dictNGrams[i], NGRAMSIZE) == 0) {
      return dictNGramProbs[i];
    }
  }
  // very-low probability if ngram doesn't exist in dictionary
  return log(1.0 / dngcnt);
}

double getNGramProb(char *ngram, char ngrams[][NGRAMSIZE], int n) {
  int i, cnt = 0;
  for (i = 0; i < n; i++) {
    if (strncmp(ngram, ngrams[i], NGRAMSIZE) == 0) {
      cnt++;
    }
  }
  return log((double)cnt / n);
}

double cipherNGPSum(char *ciphertext, char dictNGrams[][NGRAMSIZE], double dictNGramProbs[], int dngcnt) {
  int i, j, n;
  char *cipherdup;
  char ngram[NGRAMSIZE];
  double ngpsum = 0;

  cipherdup = strdup(ciphertext);
  char *delim = " ";
  char *word = strtok(cipherdup, delim);
  while (word != NULL) {
    n = strlen(word);
    // break word into n-grams
    for (i = 0; i < n - NGRAMSIZE + 1; i++) {
      for (j = 0; j < NGRAMSIZE; j++) {
        ngram[j] = word[i + j];
      }
      // sum together log probs of all n-grams in the text
      ngpsum += getDictNGramProb(ngram, dictNGrams, dictNGramProbs, dngcnt);
    }
    word = strtok(NULL, delim);
  }
  return ngpsum;
}

void generateRandomKey(char key[NALPHABETS + 1]) {
  int i, j;
  char tmp;

  for (i = 0; i < NALPHABETS; i++) {
    key[i] = 'A' + i;
  }

  for (i = NALPHABETS - 1; i > 0; i--) {
    j = rand() % (i + 1);
    tmp = key[i];
    key[i] = key[j];
    key[j] = tmp;
  }
  key[NALPHABETS] = '\0';
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
  double maxFriedmanAvg = -INFINITY;
  double chiScore, minChiScore;

  // test all possible key sizes
  for (keysize = MIN_KEYSIZE; keysize < MAX_KEYSIZE; keysize++) {
    rows = keysize;
    cols = (clen % rows) == 0 ? (clen / rows): (clen / rows + 1);
    // transposed matrix - each row is a rotx cipher
    cipherMatrix = malloc(rows * sizeof(char*));
    createCipherMatrix(ciphertext, clen, rows, cols, cipherMatrix, 1);
    friedman = friedmanTotal(cipherMatrix, clen, rows, cols);
    friedmanAvg = friedman / rows;
    if (friedmanAvg > maxFriedmanAvg) {
      maxFriedmanAvg = friedmanAvg;
      maxFriedmanKeysize = keysize;
    }
    freev((void*)cipherMatrix, rows, 1);
  }

  // reconstruct matrix with found key size
  rows = maxFriedmanKeysize;
  cols = (clen % rows) == 0 ? (clen / rows): (clen / rows + 1);
  maxFriedmanMatrix = malloc(rows * sizeof(char*));
  createCipherMatrix(ciphertext, clen, rows, cols, maxFriedmanMatrix, 1);

  // fetch dictionary frequencies
  dictLetters = getDictLetterFreqs(dictFreqs);
  // brute-force the key with most-probable keysize
  char *finalKey = malloc(rows * sizeof(char));
  for (i = 0; i < rows; i++) {
    char *subcipher = strdup(maxFriedmanMatrix[i]);
    minChiScore = INFINITY;
    for (k = 0; k < NALPHABETS; k++) {
      N = 0;
      // each row is rotx cipher in transposed matrix
      for (j = 0; j < strlen(subcipher); j++) {
        char chr = maxFriedmanMatrix[i][j];
        if (isupper(chr)) {
          subcipher[j] = rotByX(chr, k);
          N++;
        }
      }
      // compute Chi Squared value & reconstruct key
      chiScore = chiSquared(subcipher, N, dictFreqs, dictLetters);
      if (chiScore < minChiScore) {
        minChiScore = chiScore;
        finalKey[i] = (char)((int)'A' + k);
      }
    }
  }
  finalKey[i] = '\0';
  strcpy(key, finalKey);
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

  int i, j, dngcnt;
  char dictNGrams[MAX_NGRAMS][NGRAMSIZE];
  double dictNGramProbs[MAX_NGRAMS];
  LF dictFreqMap[NALPHABETS], cipherFreqMap[NALPHABETS];
  double score, bestScore = -INFINITY;
  char subsKey[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", bestKey[NALPHABETS];

  // pre-compute dictionary ngrams and their probabilities
  dngcnt = getDictNGrams(dictNGrams);
  /*printf("[LOG] total dict ngrams: %d\n", dngcnt);*/
  for (i = 0; i < dngcnt; i++) {
    /*printf("%.4s\n", dictNGrams[i]);*/
    dictNGramProbs[i] = getNGramProb(dictNGrams[i], dictNGrams, dngcnt);
  }

  // map dict letters to freqs
  int dictFreqs[NALPHABETS] = {0};
  getDictLetterFreqs(dictFreqs);
  for (i = 0; i < NALPHABETS; i++) {
      LF lfMap = { (char)((int)'A' + i), dictFreqs[i] };
      dictFreqMap[i] = lfMap;
  }
  // map cipher letters to freqs
  int cipherFreqs[NALPHABETS] = {0};
  getLetterFreqs(ciphertext, clen, cipherFreqs);
  for (i = 0; i < NALPHABETS; i++) {
      LF lfMap = { (char)((int)'A' + i), cipherFreqs[i] };
      cipherFreqMap[i] = lfMap;
  }
  // sort both in descending order of freq
  qsort(dictFreqMap, NALPHABETS, sizeof(LF), comparator);
  qsort(cipherFreqMap, NALPHABETS, sizeof(LF), comparator);

  // construct initial freq derived key
  for (i = 0; i < strlen(subsKey); i++) {
    char curr = subsKey[i];
    for (j = 0; j < NALPHABETS; j++) {
      if (dictFreqMap[j].letter == curr) {
        subsKey[i] = cipherFreqMap[j].letter;
        break;
      }
    }
  }

  // try different keys
  srand(time(NULL));
  for (i = 0; i < SUBS_ITERS; i++) {
    if (i > 0) { generateRandomKey(subsKey); }
    for (j = 0; j < SUBS_SUBITERS; j++) {
      // choose random indices to swap
      int i1 = rand() % NALPHABETS;
      int i2 = rand() % NALPHABETS;
      while (i1 == i2)
        i2 = rand() % NALPHABETS;

      // swap
      char tmp = subsKey[i1];
      subsKey[i1] = subsKey[i2];
      subsKey[i2] = tmp;

      // decrypt and get score
      cs642Decrypt(CIPHER_SUBS, subsKey, NALPHABETS, plaintext, plen, ciphertext, clen);
      score = cipherNGPSum(plaintext, dictNGrams, dictNGramProbs, dngcnt);
      if (score > bestScore) {
        bestScore = score;
        strcpy(bestKey, subsKey);
      } else {
        // revert swap
        tmp = subsKey[i1];
        subsKey[i1] = subsKey[i2];
        subsKey[i2] = tmp;
      }
    }
  }

  // decrypt using the best key
  cs642Decrypt(CIPHER_SUBS, bestKey, NALPHABETS, plaintext, plen, ciphertext, clen);

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
