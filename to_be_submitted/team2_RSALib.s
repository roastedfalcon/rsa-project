# File: math_util.s
# Authors: Team2
# Description: Provides math library for RSA operations.
#              Contains functions: gcd, mod, isPrime, totient, etc.

.text
@ Function: gcd
@ Author: Kendra Mosley
@ Purpose:  Computes the greatest common divisor of two integers.
@ Method:   Uses the Euclidean algorithm.
@
@ Args:     r0 = a (first integer), r1 = b (second integer)
@ Returns:  r0 = gcd(a, b)
gcd:
    @ Save registers we need to preserve.
    PUSH    {r4, lr}

mod_loop:
    @ Loop as long as b (r1) is not zero.
    CMP     r1, #0
    BEQ     mod_done

    @ Calculate remainder: r0 = r0 % r1
    @ Save the original 'a' before the division call.
    MOV     r4, r0          @ r4 = a (the dividend)

    BL      __aeabi_idiv    @ Returns quotient in r0.

    @ Finish the modulo calculation: remainder = a - (quotient * b)
    MUL     r0, r0, r1      @ r0 = quotient * b
    SUB     r0, r4, r0      @ r0 = a - (quotient * b) -> this is the remainder

    @ Setup for next loop iteration
    MOV     r3, r0          @ r3 holds the new remainder
    MOV     r0, r1          @ The new 'a' is the old 'b'
    MOV     r1, r3          @ The new 'b' is the remainder

    B       mod_loop

mod_done:
    @ The GCD is whatever is left in r0.
    @ Restore saved registers and return.
    POP     {r4, pc}



.global mod
# Function: mod
# Author: Kassem Arif
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

.global cprivexp
@ Function: cprivexp
@ Author: Kendra Mosley
@ Purpose:  Calculates the private key 'd'.
@ Method:   Uses the Extended Euclidean Algorithm to find the modular
@           multiplicative inverse of e (mod phi_n).
@
@ Args:     r0 = e (public exponent), r1 = phi_n (totient)
@ Returns:  r0 = d (private exponent)
cprivexp:
    @ Save all the registers we're about to use, plus the return address.
    PUSH    {r4-r9, lr}

    @ Setup 
    @ This algorithm finds 's' in the equation: s*e + t*phi_n = gcd(e, phi_n).
    @ That 's' value is our private key 'd'. We don't need 't'.
    MOV     R4, R0          @ r4 is old_r, starts as e
    MOV     R5, R1          @ r5 is r, starts as phi_n
    MOV     R6, #1          @ r6 is old_s, starts at 1
    MOV     R7, #0          @ r7 is s, starts at 0
    MOV     R8, R1          @ r8 holds the original phi_n for the final check

cprivexp_loop:
    @ Keep looping as long as r (r5) is not zero.
    CMP     R5, #0
    BEQ     cprivexp_done

    @ Main Algorithm
    @ 1. Get the quotient: q = old_r / r
    MOV     R0, R4          @ Set args for the C division function
    MOV     R1, R5
    BL      __aeabi_idiv    @ C helper returns quotient in R0
    MOV     R9, R0          @ Store quotient in r9

    @ 2. Update r: new_r = old_r - q * r
    MUL     R0, R9, R5      @ r0 = q * r
    SUB     R0, R4, R0      @ r0 = old_r - (q * r)

    @ "Slide" the r values down for the next loop
    MOV     R4, R5          @ old_r becomes the old r
    MOV     R5, R0          @ r becomes the new_r we just calculated

    @ 3. Update s: new_s = old_s - q * s
    MUL     R0, R9, R7      @ r0 = q * s
    SUB     R0, R6, R0      @ r0 = old_s - (q * s)

    @ "Slide" the s values down for the next loop
    MOV     R6, R7          @ old_s becomes the old s
    MOV     R7, R0          @ s becomes the new_s we just calculated

    B       cprivexp_loop   @ And again...
cprivexp_done:
    @ The result 'd' is whatever is left in old_s (r6).

    @ The raw result from the algorithm can be negative. If so,
    @ add phi_n to it to get the correct positive modular inverse.
    CMP     R6, #0          @ Is d negative?
    ADDLT   R6, R6, R8      @ If so, d = d + phi_n

    @ Put the final result in the return register.
    MOV     R0, R6

    @ Restore the registers and get out of here.
    POP     {r4-r9, pc}
.data
# END cprivexp

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
.data
# END cpubexp

.global process
# Function: process
# Author: Kassem Arif
# Purpose:  Computes a^b mod n
# Input:    r0 = base (a), r1 = exponent (b), r2 = modulus (n)
# Output:   r0 = a^b mod n
.text
process:
     SUB sp, sp, #20         @ allocate stack space
     STR lr, [sp, #0]        @ save return address
     STR r4, [sp, #4]        @ save r4
     STR r5, [sp, #8]        @ save r5
     STR r6, [sp, #12]       @ save r6
     STR r7, [sp, #16]       @ save r7
     MOV r4, r0              @ store base in r4
     MOV r5, r1              @ store exponent in r5
     MOV r6, r2              @ store modulus in r6
     MOV r7, #0              @ initialize loop counter
     MOV r0, #1              @ initialize result to 1
     processLoop:
         CMP r7, r5          @ check if counter >= exponent
         BGE processLoopEnd  @ if yes, exit loop
         MUL r3, r0, r4      @ use r3 as a temporary register
         MOV r0, r3          @ move result back to r0         
         MOV r1, r6          @ move modulus to r1 for mod
         BL mod              @ call mod function
         ADD r7, r7, #1      @ increment counter
         B processLoop       @ repeat loop
     processLoopEnd:
     LDR lr, [sp, #0]        @ restore return address
     LDR r4, [sp, #4]        @ restore r4
     LDR r5, [sp, #8]        @ restore r5
     LDR r6, [sp, #12]       @ restore r6
     LDR r7, [sp, #16]       @ restore r7
     ADD sp, sp, #20         @ free stack space
     MOV pc, lr              @ return to caller
.data
# END process

.global processArray
# Function: processArray
# Author: Kassem Arif
# Purpose:  Processes an array for RSA encryption/decryption
# Input:    r0 = array pointer, r1 = array size, r2 = exponent, r3 = modulus
# Output:   r0 = processed array pointer, r1 = array size
.text
processArray:
     SUB sp, sp, #24         @ allocate stack space
     STR lr, [sp, #0]        @ save return address
     STR r4, [sp, #4]        @ save r4
     STR r5, [sp, #8]        @ save r5
     STR r6, [sp, #12]       @ save r6
     STR r7, [sp, #16]       @ save r7
     STR r8, [sp, #20]       @ save r8
     MOV r4, r0              @ store array pointer in r4
     MOV r5, r1              @ store array size in r5
     MOV r6, r2              @ store exponent in r6
     MOV r7, r3              @ store modulus in r7
     MOV r8, #0              @ initialize loop counter
     processArrayLoop:
         CMP r8, r5          @ check if counter >= array size
         BGE processArrayLoopEnd  @ if yes, exit loop
         LSL r1, r8, #2      @ calculate array offset (i * 4)
         LDR r0, [r4, r1]    @ load array element into r0
         MOV r1, r6          @ move exponent to r1
         MOV r2, r7          @ move modulus to r2
         BL process          @ call process function
         LSL r1, r8, #2      @ calculate array offset (i * 4)
         STR r0, [r4, r1]    @ store result back in array
         ADD r8, r8, #1      @ increment counter
         B processArrayLoop  @ repeat loop
     processArrayLoopEnd:
     MOV r0, r4              @ return array pointer
     MOV r1, r5              @ return array size
     LDR lr, [sp, #0]        @ restore return address
     LDR r4, [sp, #4]        @ restore r4
     LDR r5, [sp, #8]        @ restore r5
     LDR r6, [sp, #12]       @ restore r6
     LDR r7, [sp, #16]       @ restore r7
     LDR r8, [sp, #20]       @ restore r8
     ADD sp, sp, #24         @ free stack space
     MOV pc, lr              @ return to caller
.data
# END processArray


.section  .note.GNU-stack,"",%progbits
