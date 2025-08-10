# File: math_util.s
# Authors: [Team]
# Description: Provides basic math functions for RSA operations.
#              Contains functions: gcd, mod, isPrime, totient.

.text

.global gcd
# Function: gcd
# Description: Computes the greatest common divisor of two integers using the Euclidean algorithm
# Input: r0 = first integer, r1 = second integer
# Output: r0 = greatest common divisor
gcd:
    SUB sp, sp, #4         @ save link register
    STR lr, [sp]

gcd_loop:
    CMP r0, r1             @ compare numbers in r0 and r1
    BEQ gcd_done           @ if equal, we're done
    BLT gcd_subtract_r0    @ if r0 < r1, subtract r0 from r1
    SUB r0, r0, r1         @ subtract r1 from r0
    B gcd_continue

gcd_subtract_r0:
    SUB r1, r1, r0         @ subtract r0 from r1

gcd_continue:
    B gcd_loop             @ repeat loop

gcd_done:
    LDR lr, [sp]           @ restore link register
    ADD sp, sp, #4
    MOV pc, lr             @ return





.global mod
# Function: mod
# Description: Calculates the remainder when r0 is divided by r1
# Input: r0 = dividend, r1 = divisor
# Output: r0 = remainder (modulo result)
mod:
    SUB sp, sp, #4         @ save link register
    STR lr, [sp]
    SUB sp, sp, #4         @ save r4
    STR r4, [sp]
    SUB sp, sp, #4         @ save r5
    STR r5, [sp]

    MOV r4, r0             @ Save dividend in r4
    MOV r5, r1             @ Save divisor in r5
    BL __aeabi_idiv        @ Divide r4 by r5 (quotient in r0)
    
    MUL r3, r0, r5         @ use a temporary register (r3) for multiplication
    MOV r0, r3             @ move result back to r0
    
    SUB r0, r4, r0         @ compute remainder: dividend - (quotient * divisor)

    LDR r5, [sp]          @ restore r5
    ADD sp, sp, #4
    LDR r4, [sp]          @ restore r4
    ADD sp, sp, #4
    LDR lr, [sp]          @ restore link register
    ADD sp, sp, #4
    MOV pc, lr            @ return







.global isPrime
# Function: isPrime
# Description: Determines if a given integer is a prime number
# Input: r0 = integer to test
# Output: r0 = 1 if prime, 0 if composite, and -1 for invalid values (n ≤ 1)
isPrime:
    SUB sp, sp, #4         @ save link register
    STR lr, [sp]
    SUB sp, sp, #4         @ save r4
    STR r4, [sp]
    SUB sp, sp, #4         @ save r5
    STR r5, [sp]

    CMP r0, #1            @ check if number <= 1
    MOVLE r0, #-1         @ return -1 if invalid
    BLE prime_end

    MOV r4, r0            @ store original number in r4
    MOV r5, #2            @ start counter at 2
prime_loop:
    MUL r0, r5, r5        @ compute counter^2
    CMP r0, r4            @ if counter^2 > number, exit loop
    MOVGT r0, #1
    BGT prime_end
    MOV r0, r4            @ test divisibility: number mod counter
    MOV r1, r5
    BL mod
    CMP r0, #0            @ if divisible, number is not prime
    BEQ prime_end
    ADD r5, r5, #1        @ increment counter
    B prime_loop

prime_end:
    LDR r5, [sp]         @ restore r5
    ADD sp, sp, #4
    LDR r4, [sp]         @ restore r4
    ADD sp, sp, #4
    LDR lr, [sp]         @ restore link register
    ADD sp, sp, #4
    MOV pc, lr           @ return




.global totient
# Function: totient
# Description: Computes the totient value Φ(n) = (p-1)*(q-1) for two prime numbers
# Input: r0 = prime p, r1 = prime q
# Output: r0 = totient value if both are prime; returns -1 if either p or q is not prime
totient:
    PUSH {r4, r5, lr}     @ save r4, r5 and link register

    MOV r4, r0            @ r4 = p
    MOV r5, r1            @ r5 = q

    MOV r0, r4            @ check if p is prime
    BL isPrime
    CMP r0, #1
    BLT totient_error

    MOV r0, r5            @ check if q is prime
    BL isPrime
    CMP r0, #1
    BLT totient_error

    MOV r1, r4
    MOV r2, r5
    SUB r1, r1, #1        @ r1 = p - 1
    SUB r2, r2, #1        @ r2 = q - 1
    MUL r0, r1, r2        @ r0 = (p - 1) * (q - 1)
    B totient_done

totient_error:
    MVN r0, #1           @ set r0 to -1
    ADD r0, #1

totient_done:
    POP {r4, r5, pc}      @ restore r4, r5 and return

.section  .note.GNU-stack,"",%progbits
