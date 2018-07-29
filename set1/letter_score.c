#include "type.h"

// Scores each letter based on its use % in English text. Non-letters get 0
int score_letter(byte_t ch) {
    switch (ch) {
        case 'e':
        case 'E':
            return 13;
        case 't':
        case 'T':
            return 9;
        case 'a':
        case 'A':
        case 'o':
        case 'O':
            return 8;
        case 'n':
        case 'N':
        case 'i':
        case 'I':
            return 7;
        case 's':
        case 'S':
        case 'h':
        case 'H':
        case 'r':
        case 'R':
            return 6;
        case 'd':
        case 'D':
        case 'l':
        case 'L':
            return 4;
        case 'u':
        case 'U':
        case 'c':
        case 'C':
            return 3;
        // The other letters are not significant enough to be scored
        default: return 0;
    }
}

int score_text(const byte_t * buf, const size_t len) {
    int score = 0;
    for (size_t i = 0; i < len; i++) {
        score += score_letter(buf[i]);
    }
    return score;
}
