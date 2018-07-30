#pragma once

#include "type.h"

#define MINIMUM_TEXT_SCORE 0

int score_letter(byte_t ch);
int score_text(const byte_t * buf, const size_t len);
