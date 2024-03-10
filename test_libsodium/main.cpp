#define SODIUM_STATIC
#include <iostream>

#include <sodium.h>

#include "ED25519.h"
#include "simplest_OT.h"
#include "test_simplest_OT.h"

int main() {
    test_simplest_OT();
    return 0;
}