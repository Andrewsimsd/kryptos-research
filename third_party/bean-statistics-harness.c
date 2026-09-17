/* SPDX-License-Identifier: GPL-3.0-only
 * Test adapter for the pinned GPL-3.0 source; not linked into the Rust library.
 * Its original time-seeded main is renamed and never invoked.
 */
#define main bean_original_main
#include "bean-k4testing/k4-testy.c"
#undef main

int main(void) {
    char line[100];
    while (fgets(line, sizeof line, stdin)) {
        size_t i;
        if (strlen(line) != 98 || line[97] != '\n') return 2;
        line[97] = '\0';
        for (i = 0; i < 97; ++i) if (line[i] < 'A' || line[i] > 'Z') return 2;
        if (printf("%d %d %d %d %d\n", count21(line), materna(line), bean1(line),
                   bean2(line), double_letter_bigrams(line)) < 0) return 3;
    }
    return ferror(stdin) || fflush(stdout) == EOF ? 3 : 0;
}
