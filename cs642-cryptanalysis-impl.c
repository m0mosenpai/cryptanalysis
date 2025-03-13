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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

#define MIN_KEYSIZE 6
#define MAX_KEYSIZE 12
#define NALPHA 26
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

// free 2D arrays
void freev(void **ptr, int len, int free_seg) {
  if (len < 0) while (*ptr) { free(*ptr); *ptr++ = NULL; }
  else { for (int i = 0; i < len; i++) free(ptr[i]); }
  if (free_seg) free(ptr);
}

// swap two indices
void swap(int a, int b, char *array) {
  char tmp = array[a];
  array[a] = array[b];
  array[b] = tmp;
}

// sorting in descending order of freq
int comparator(const void *a, const void *b) {
    LF *A = (LF *)a;
    LF *B = (LF *)b;
    return (B->freq - A->freq);
}

// display cipher matrix
void printMatrix(char **matrix, int rows, int cols) {
  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      printf("%c", matrix[i][j]);
    }
    printf("\n");
  }
}

// shift a char left by x
char rotByX(char chr, int x) {
  int rotChr = (int)chr - x;
  return rotChr < (int)'A' ? (int)'Z' - ((int)'A' - rotChr) + 1: (char)rotChr;
}

// get num of occurrences of a word in the given dict
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

// get letter frequencies in a given ciphertext
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

// get letter frequencies in the given dict
int getDictLetterFreqs(int *counts) {
  int i, n;
  int dictSize = cs642GetDictSize();
  int total = 0;

  for (i = 0; i < dictSize; i++) {
    struct DictWord dictword = cs642GetWordfromDict(i);
    n = strlen(dictword.word);
    getLetterFreqs(dictword.word, n, counts);
  }

  for (i = 0; i < NALPHA; i++) {
    total += counts[i];
  }
  return total;
}

// create transposed ciphermatrix for vigenere, where rows = keysize
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

// compute the Friedman's Test on a given cipher matrix
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
    int freqs[NALPHA] = {0};
    getLetterFreqs(subcipher, strlen(subcipher), freqs);

    // do Friedman's Test
    freqSum = 0;
    for (j = 0; j < NALPHA; j++) {
      if (freqs[j] > 0)
        freqSum += (freqs[j] * (freqs[j] - 1));
    }
    Ko = freqSum / (N * (N - 1));
    friedmanTotal += Ko;
  }
  return friedmanTotal;
}

// compute the Chi-Squared Test for a given ciphertext
double chiSquared(char *cipher, int cn, int *E, int en) {
  int i;
  double Ci, Ei, total = 0;
  int C[NALPHA] = {0};
  getLetterFreqs(cipher, strlen(cipher), C);

  for (i = 0; i < NALPHA; i++) {
    Ci = (double)C[i] / cn;
    Ei = ((double)E[i] / en) * cn;
    total += (pow(Ci - Ei, 2) / Ei);
  }
  return total;
}

// get all 4-grams in the given dicionary for substition cipher
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

// get all 4-gram probabilities in a dict 4-gram list
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

// get log probability of a 4-gram
double getNGramProb(char *ngram, char ngrams[][NGRAMSIZE], int n) {
  int i, cnt = 0;
  for (i = 0; i < n; i++) {
    if (strncmp(ngram, ngrams[i], NGRAMSIZE) == 0) {
      cnt++;
    }
  }
  return log((double)cnt / n);
}

// get log prob sum of all 4-grams in a given ciphertext, compared to 4-grams in a dict
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

void getInitFreqDerivedKey(char *ciphertext, int clen, char key[NALPHA + 1]) {
  int i, j;
  LF dictFreqMap[NALPHA], cipherFreqMap[NALPHA];

  // map dict letters to freqs
  int dictFreqs[NALPHA] = {0};
  int cipherFreqs[NALPHA] = {0};
  getDictLetterFreqs(dictFreqs);
  getLetterFreqs(ciphertext, clen, cipherFreqs);
  for (i = 0; i < NALPHA; i++) {
      LF lfMap1 = { (char)((int)'A' + i), dictFreqs[i] };
      dictFreqMap[i] = lfMap1;

      LF lfMap2 = { (char)((int)'A' + i), cipherFreqs[i] };
      cipherFreqMap[i] = lfMap2;
  }

  // sort both in descending order of freq
  qsort(dictFreqMap, NALPHA, sizeof(LF), comparator);
  qsort(cipherFreqMap, NALPHA, sizeof(LF), comparator);

  // construct initial freq derived key
  for (i = 0; i < NALPHA; i++) {
    char curr = key[i];
    for (j = 0; j < NALPHA; j++) {
      if (dictFreqMap[j].letter == curr) {
        key[i] = cipherFreqMap[j].letter;
        break;
      }
    }
  }
  key[NALPHA] = '\0';
}

// generate a random substition cipher key (Fisher-Yates shuffling)
void generateRandomKey(char key[NALPHA + 1]) {
  int i, j;
  char tmp;

  for (i = 0; i < NALPHA; i++) {
    key[i] = 'A' + i;
  }

  for (i = NALPHA - 1; i > 0; i--) {
    j = rand() % (i + 1);
    tmp = key[i];
    key[i] = key[j];
    key[j] = tmp;
  }
  key[NALPHA] = '\0';
}

int checkBestKey(char *plaintext) {
  int dictMatches;
  char *word, *ptextdup, *delim = " ";

  ptextdup = strdup(plaintext);
  word = strtok(ptextdup, delim);
  while (word != NULL) {
    dictMatches = 0;
    checkDictionary(word, &dictMatches);
    if (dictMatches == 0) return -1;
      word = strtok(NULL, delim);
  }
  // if all words in plaintext exist in the dictionary
  return 0;
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

  int i, dictMatches, r;
  uint8_t k;
  char *decryption = strdup(ciphertext);
  char *decryptionDup, *tok, *delim = " ";
  int maxMatches = 0;

  // test all possible rotations
  for (k = 1; k < NALPHA; k++) {
    for (i = 0; i < clen; i++) {
      if (ciphertext[i] == ' ')
        continue;
      decryption[i] = rotByX(ciphertext[i], k);
    }
    decryptionDup = strdup(decryption);
    tok = strtok(decryptionDup, delim);
    dictMatches = 0;
    while (tok != NULL) {
      // select rotation with highest dict word matches
      checkDictionary(tok, &dictMatches);
      if (dictMatches > maxMatches) {
        maxMatches = dictMatches;
        *key = k;
        strcpy(plaintext, decryption);
      }
      tok = strtok(NULL, delim);
    }
  }
  if ((r = cs642Decrypt(CIPHER_ROTX, (char*)key, strlen((char*)key), plaintext, plen, ciphertext, clen)) == 0)
    return 0;

  return -1;
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

  int i, j, k, N, r;
  int rows, cols, dictLetters;
  int dictFreqs[NALPHA] = {0};
  char chr;
  char *subcipher, *finalKey;
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
  finalKey = malloc(rows * sizeof(char));
  for (i = 0; i < rows; i++) {
    subcipher = strdup(maxFriedmanMatrix[i]);
    minChiScore = INFINITY;
    for (k = 0; k < NALPHA; k++) {
      N = 0;
      // each row is rotx cipher in transposed matrix
      for (j = 0; j < strlen(subcipher); j++) {
        chr = maxFriedmanMatrix[i][j];
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
  free(finalKey);
  freev((void*)maxFriedmanMatrix, rows, 1);

  if ((r = cs642Decrypt(CIPHER_VIGE, key, maxFriedmanKeysize, plaintext, plen, ciphertext, clen) == 0))
    return 0;

  return -1;
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

  int i, j, dngcnt, i1, i2, r;
  char dictNGrams[MAX_NGRAMS][NGRAMSIZE];
  double dictNGramProbs[MAX_NGRAMS];
  double score, bestScore = -INFINITY;
  char freqKey[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", bestKey[NALPHA];
  char subsKey[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  clock_t start, end;

  // pre-compute dictionary ngrams and their probabilities
  dngcnt = getDictNGrams(dictNGrams);
  for (i = 0; i < dngcnt; i++) {
    dictNGramProbs[i] = getNGramProb(dictNGrams[i], dictNGrams, dngcnt);
  }

  // start with a frequency derived key
  getInitFreqDerivedKey(ciphertext, clen, freqKey);

  srand(time(NULL));
  start = clock();
  for (i = 0; i < SUBS_ITERS; i++) {
    /*if (i > 0) generateRandomKey(subsKey);*/
    strcpy(subsKey, freqKey);
    bestScore = -INFINITY;
    // try permutations of the current key for some time
    for (j = 0; j < SUBS_SUBITERS; j++) {
      // choose random indices to swap
      i1 = rand() % NALPHA;
      i2 = rand() % NALPHA;
      while (i1 == i2)
        i2 = rand() % NALPHA;

      // swap
      swap(i1, i2, subsKey);

      // decrypt and get score, and save it if better than best score
      cs642Decrypt(CIPHER_SUBS, subsKey, NALPHA, plaintext, plen, ciphertext, clen);
      score = cipherNGPSum(plaintext, dictNGrams, dictNGramProbs, dngcnt);
      printf("[LOG] round-%d (iter: %d of %d) - key: %s, score: %f\n", i, j, SUBS_SUBITERS, subsKey, score);
      if (score > bestScore) {
        bestScore = score;
        strcpy(bestKey, subsKey);
        printf("[LOG] bestKey: %s, bestScore: %f\n", bestKey, bestScore);
      } else {
        // revert the swap
        swap(i1, i2, subsKey);
      }
    }
    printf("[LOG] [round #%d complete] bestKey: %s, bestScore: %f\n", i, bestKey, bestScore);

    // decrypt using the best key & check if the plaintext contains words in the dict
    cs642Decrypt(CIPHER_SUBS, bestKey, NALPHA, plaintext, plen, ciphertext, clen);
    if (checkBestKey(plaintext) == 0) {
      strcpy(key, bestKey);
      end = clock();
      printf("[LOG] key successfully recovered! (took: %0.5f sec)\n", ((double)(end - start) / CLOCKS_PER_SEC));
      return 0;
    }
  }

  // decrypt using the best key
  strcpy(key, bestKey);
  if ((r = cs642Decrypt(CIPHER_SUBS, key, NALPHA, plaintext, plen, ciphertext, clen) == 0))
    return 0;

  return -1;
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
