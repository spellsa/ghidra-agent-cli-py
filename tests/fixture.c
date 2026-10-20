#include <stdio.h>
#include <stddef.h>

volatile int fixture_value = 7;
const char fixture_message[] = "Ghidra inline smoke fixture";

__attribute__((noinline)) int fixture_add(int a, int b) {
    if (a > b) return a + b + fixture_value;
    return b - a;
}

__attribute__((noinline)) int fixture_total(const char *s) {
    int total = 0;
    for (size_t i = 0; s[i]; ++i) total += s[i];
    return fixture_add(total, 10);
}

int main(void) {
    puts(fixture_message);
    return fixture_total(fixture_message) == 0;
}
