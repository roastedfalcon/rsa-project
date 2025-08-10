# File: rsa_core.s
# Authors: [Team]
# Description: Contains RSA functions for key generation, encryption, and decryption.


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

.global generateKeys
# Function: generateKeys
# Author: Mark Schlining
# Description: Handles the entire user flow for generating RSA keys.
.text
generateKeys:
    PUSH    {lr}            @ Save link register for this function

    # 1. Get p from user
    LDR     r0, =p_prompt
    BL      printf
    LDR     r0, =scan_format_d
    LDR     r1, =p_val
    BL      scanf

    # 2. Get q from user
    LDR     r0, =q_prompt
    BL      printf
    LDR     r0, =scan_format_d
    LDR     r1, =q_val
    BL      scanf

    # 3. Calculate totient (which also validates if p and q are prime)
    LDR     r0, =p_val
    LDR     r0, [r0]
    LDR     r1, =q_val
    LDR     r1, [r1]
    BL      totient
    CMP     r0, #-1         @ totient returns -1 on error
    BEQ     prime_error

    # Store phi_n if successful
    LDR     r1, =phi_n_val
    STR     r0, [r1]

    # 4. Calculate n = p * q
    LDR     r0, =p_val
    LDR     r0, [r0]
    LDR     r1, =q_val
    LDR     r1, [r1]
    MUL     r2, r0, r1
    LDR     r3, =n_val
    STR     r2, [r3]

get_e_loop:
    # 5. Get e from user
    LDR     r0, =e_prompt
    BL      printf
    LDR     r0, =scan_format_d
    LDR     r1, =e_val
    BL      scanf

    # 6. Validate e by calling cpubexp
    LDR     r0, =e_val
    LDR     r0, [r0]        @ r0 = e
    LDR     r1, =phi_n_val
    LDR     r1, [r1]        @ r1 = phi_n
    BL      cpubexp
    CMP     r0, #0          @ cpubexp returns 0 on error
    BEQ     e_error         @ If invalid, print error and loop

    # 7. Calculate d by calling cprivexp
    LDR     r0, =e_val
    LDR     r0, [r0]        @ r0 = e
    LDR     r1, =phi_n_val
    LDR     r1, [r1]        @ r1 = phi_n
    BL      cprivexp
    LDR     r1, =d_val
    STR     r0, [r1]        @ Store d

    # 8. Print the final keys
    LDR     r0, =keys_header
    BL      printf
    LDR     r1, =n_val      @ Public Key (n, e)
    LDR     r1, [r1]
    LDR     r2, =e_val
    LDR     r2, [r2]
    LDR     r0, =pub_key_format
    BL      printf
    LDR     r1, =n_val      @ Private Key (n, d)
    LDR     r1, [r1]
    LDR     r2, =d_val
    LDR     r2, [r2]
    LDR     r0, =priv_key_format
    BL      printf

    B       generate_done   @ Skip error messages

prime_error:
    LDR     r0, =prime_error_msg
    BL      printf
    B       generate_done

e_error:
    LDR     r0, =e_error_msg
    BL      printf
    B       get_e_loop      @ Loop back to ask for e again

generate_done:
    POP     {pc}            @ Return from this function

.data
# Key Generation Data
p_prompt:         .asciz  "Enter the first prime number (p): "
q_prompt:         .asciz  "Enter the second prime number (q): "
e_prompt:         .asciz  "Enter a public key exponent (e): "
prime_error_msg:  .asciz  "Error: One or both numbers are not prime. Please try again.\n"
e_error_msg:      .asciz  "Error: Invalid public exponent 'e'. It must be 1 < e < phi(n) and coprime to phi(n).\n"
keys_header:      .asciz  "\n--- Keys Generated Successfully ---\n"
pub_key_format:   .asciz  "Public Key (n, e):  (%d, %d)\n"
priv_key_format:  .asciz  "Private Key (n, d): (%d, %d)\n"

# Formats and Storage
scan_format_d:    .asciz  "%d"
p_val:            .word   0
q_val:            .word   0
e_val:            .word   0
n_val:            .word   0
phi_n_val:        .word   0
d_val:            .word   0

# END generateKeys

.global encrypt
# Function: encrypt
# Author: Joyonna Gamble-George
# Purpose:  Encrypts a message using public key and modulus
.text
encrypt:
     PUSH {r4, r5, lr}       @ save registers
     LDR r0, =promptPubKey   @ load prompt for public key
     BL printf               @ print prompt
     LDR r0, =scan_format_d  @ load integer format
     LDR r1, =publicKey      @ load address for public key
     BL scanf                @ read public key from user
     LDR r0, =promptModulus  @ load prompt for modulus
     BL printf               @ print prompt
     LDR r0, =scan_format_d  @ load integer format
     LDR r1, =modulus        @ load address for modulus
     BL scanf                @ read modulus from user
     clearStdin:
         BL getchar          @ clear stdin buffer
         CMP r0, #'\n'       @ check if newline
         BEQ cont            @ if yes, continue
         CMP r0, #-1         @ check if end of input
         BEQ cont            @ if yes, continue
         B clearStdin        @ repeat loop
     cont:
     LDR r0, =promptText     @ load prompt for text
     BL printf               @ print prompt
     MOV r0, #255            @ allocate 255 bytes for input
     BL malloc               @ call malloc
     MOV r1, #255            @ set buffer size
     LDR r2, =stdin          @ load stdin
     LDR r2, [r2]            @ dereference stdin
     BL fgets                @ read input from user
     MOV r4, r0              @ store input pointer in r4
     BL strlen               @ Get input length
     SUB r5, r0, #1          @ subtract 1 to remove newline
     MOV r0, r4              @ move input pointer to r0
     MOV r1, r5              @ move length to r1
     BL str_to_array        @ convert string to array
     LDR r2, =publicKey      @ load public key
     LDR r2, [r2]            @ dereference public key
     LDR r3, =modulus        @ load modulus
     LDR r3, [r3]            @ dereference modulus
     BL processArray         @ process array for encryption
     MOV r2, r1              @ move array size to r2
     MOV r1, r0              @ move array pointer to r1
     LDR r0, =fileName       @ load output file name
     BL write_array           @ Write array to file
     LDR r0, =encryptionDone @ load encryption done message
     BL printf               @ print message
     POP {r4, r5, pc}        @ restore registers and return
     
.data
    promptPubKey:   .asciz "\nEnter the public key (e): "
    publicKey:      .word 0

    promptModulus:  .asciz "Enter the modulus (n): "
    modulus:        .word 0

    promptText:     .asciz "Enter the text to encrypt: "
    fileName:       .asciz "encrypted.txt"

    encryptionDone: .asciz "\n[Success] Encryption complete.\n
Encrypted message saved in 'encrypted.txt'.\n"

# END encrypt

.global decrypt
# Function: decrypt
# Author: Joyonna Gamble-George
# Purpose:  Decrypts a message using private key and modulus
.text
decrypt:
     PUSH {r4, r5, lr}       @ save registers
     LDR r0, =promptPrivKey  @ load prompt for private key
     BL printf               @ print prompt
     LDR r0, =scan_format_d  @ load integer format
     LDR r1, =privateKey     @ load address for private key
     BL scanf                @ read private key from user
     LDR r0, =promptModulus  @ load prompt for modulus
     BL printf               @ print prompt
     LDR r0, =scan_format_d  @ load integer format
     LDR r1, =modulus        @ load address for modulus
     BL scanf                @ read modulus from user
     LDR r0, =fileName       @ load input file name
     BL read_array            @ read array from file
     LDR r2, =privateKey     @ load private key
     LDR r2, [r2]            @ dereference private key
     LDR r3, =modulus        @ load modulus
     LDR r3, [r3]            @ dereference modulus
     BL processArray         @ process array for decryption
     BL array_to_str        @ convert array to string
     MOV r1, r0              @ move string pointer to r1
     LDR r0, =plaintextFileName  @ load output file name
     BL write_file            @ Write string to file
     LDR r0, =decryptionDone @ load decryption done message
     BL printf               @ print message
     POP {r4, r5, pc}        @ restore registers and return
     
.data
    promptPrivKey:     .asciz "\nEnter the private key (d): "
    privateKey:        .word 0
    plaintextFileName: .asciz "decrypted.txt"
    decryptionDone:    .asciz "\n[Success] Decryption complete.\n
Decrypted message saved in 'decrypted.txt'.\n"

.section  .note.GNU-stack,"",%progbits     
# END decrypt
