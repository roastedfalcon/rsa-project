.global cpubexp

# Function: cpubexp
# Author: Mark Schlining
# Description: Validates the public key exponent 'e'.
#              Checks if 1 < e < phi_n AND gcd(e, phi_n) == 1.
# Input: r0 = e, r1 = phi_n
# Output: r0 = 1 if e is valid, 0 if e is invalid
cpubexp:
    PUSH    {r4, lr}        @ Save registers

    MOV     r4, r0          @ r4 = e

    # Rule 1: Check if e > 1
    CMP     r4, #1
    MOVLE   r0, #0          @ If e <= 1, it's invalid. Set return to 0.
    BLE     cpubexp_done    @ Exit if invalid.

    # Rule 2: Check if e < phi_n
    CMP     r4, r1          @ Compare e with phi_n
    MOVGE   r0, #0          @ If e >= phi_n, it's invalid. Set return to 0.
    BGE     cpubexp_done    @ Exit if invalid.

    # Rule 3: Check if gcd(e, phi_n) == 1
    # r0 (e) and r1 (phi_n) are already set correctly for the gcd call.
    BL      gcd
    CMP     r0, #1          @ Check if the gcd is 1
    MOVEQ   r0, #1          @ If gcd is 1, e is valid. Set return to 1.
    MOVNE   r0, #0          @ If gcd is not 1, e is invalid. Set return to 0.

cpubexp_done:
    POP     {r4, pc}        @ Restore registers and return