# File: rsa_core.s
# Authors: [Team]
# Description: Contains RSA functions for key generation, encryption, and decryption.


.global cprivexp
# Function: cprivexp
# Purpose:  Calculates the private exponent
# Input:    r0 - public exponent (e), r1 - phi(n)
# Output:   r0 - private exponent
# Errors:   returns -1 if gcd(r0,r1) != 1
.text
cprivexp:
     SUB sp, sp, #4          @ allocate stack space for return address
     STR lr, [sp]            @ save return address
     SUB sp, sp, #4          @ allocate stack space for r4
     STR r4, [sp]
     SUB sp, sp, #4
     STR r4, [sp]            @ save r4
     SUB sp, sp, #4          @ allocate stack space for r5
     STR r5, [sp]            @ save r5
     MOV r4, r0              @ store public exponent in r4
     MOV r5, r1              @ store phi(n) in r5
     BL gcd                  @ call gcd function
     CMP r0, #1              @ check if gcd is 1
     MOVNE r0, #-1           @ if not, return -1 (error)
     BNE PrivExpEnd          @ jump to end if error
     MOV r6, #1              @ initialize x to 1
     PrivExpLoop:
         MUL r0, r5, r6      @ calculate x * phi(n)
         ADD r0, r0, #1      @ add 1 to get (1 + x * phi(n))
         MOV r1, r4          @ move public exponent to r1 for mod
         BL mod              @ call mod function
         CMP r0, #0          @ check if result is 0
         BEQ PrivExpEndLoop  @ if yes, exit loop
         ADD r6, r6, #1      @ increment x
         B PrivExpLoop       @ repeat loop
     PrivExpEndLoop:
         MUL r0, r5, r6      @ calculate x * phi(n)
         ADD r0, r0, #1      @ add 1 to get (1 + x * phi(n))
         MOV r1, r4          @ move public exponent to r1 for division
         BL __aeabi_idiv     @ divide to get private exponent
         B PrivExpEnd        @ jump to end
     PrivExpEnd:
     LDR r6, [sp]            @ restore r6
     ADD sp, sp, #4          @ free stack space
     LDR r5, [sp]            @ restore r5
     ADD sp, sp, #4          @ free stack space
     LDR r4, [sp]            @ restore r4
     ADD sp, sp, #4          @ free stack space
     LDR lr, [sp]            @ restore return address
     ADD sp, sp, #4          @ free stack space
     MOV pc, lr              @ return to caller
.data
# END cprivexp

.global cpubexp
# Function: cpubexp
# Purpose:  Validates the public exponent
# Input:    r0 = p, r1 = q, r2 = e
# Output:   r0 = pub exponent or -1 (error)
.text
cpubexp:
    PUSH {r4, r5, r6, lr}    @ save registers
    MOV r4, r0               @ store p in r4
    MOV r5, r1               @ store q in r5
    MOV r6, r2               @ store e in r6
    MOV r0, r2               @ move e to r0 for comparison
    CMP r0, #1               @ check if e < 1
    BLT pubError             @ if yes, jump to error
    MOV r0, r4               @ move p to r0 for totient
    MOV r1, r5               @ move q to r1 for totient
    BL totient               @ call totient function
    CMP r0, #-1              @ check if totient returned -1 (error)
    BEQ pubError             @ if yes, jump to error
    MOV r4, r0               @ store totient result in r4
    CMP r6, r4               @ check if e > totient
    BGT pubError             @ if yes, jump to error
    MOV r0, r6               @ move e to r0 for gcd
    MOV r1, r4               @ move totient to r1 for gcd
    BL gcd                   @ call gcd function
    CMP r0, #1               @ check if gcd is 1
    BEQ pubValid             @ if yes, jump to valid
    B pubError               @ Else, jump to error
    pubError:
        MOV r0, #-1          @ return -1 (error)
        B end                @ jump to end
    pubValid:
        MOV r0, r6           @ return e (valid public exponent)
        B end                @ jump to end
    end:
    POP {r4, r5, r6, pc}     @ restore registers and return
.data
# END cpubexp

.global process
# Function: process
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
# Purpose:  Prompts user for primes and public exponent, generates private key
.text
generateKeys:
    PUSH {r4, r5, lr}        @ save registers
    LDR r0, =introPrompt     @ load intro message
    BL printf                @ print intro message
    promptPrimesLoop:
       LDR r0, =promptP      @ load prompt for p
       BL printf             @ print prompt
       LDR r0, =intFmt       @ load integer format
       LDR r1, =pVal         @ load address for p
       BL scanf              @ read p from user
       LDR r0, =promptQ      @ load prompt for q
       BL printf             @ print prompt
       LDR r0, =intFmt       @ load integer format
       LDR r1, =qVal         @ load address for q
       BL scanf              @ read q from user
       LDR r0, =pVal         @ load p value
       LDR r0, [r0]          @ dereference p
       LDR r1, =qVal         @ load q value
       LDR r1, [r1]          @ dereference q
       BL totient            @ call totient function
       CMP r0, #-1           @ check if totient returned -1 (error)
       BNE primesValidated   @ if valid, continue
           LDR r0, =primeError  @ load error message
           BL printf            @ print error
           B promptPrimesLoop   @ repeat loop
       primesValidated:
       MOV r4, r0            @ store totient result in r4
    promptPubKeyLoop:
        LDR r0, =promptE     @ load prompt for e
        BL printf            @ print prompt
        LDR r0, =intFmt      @ load integer format
        LDR r1, =pubKey      @ load address for e
        BL scanf             @ read e from user
        LDR r0, =pVal        @ load p value
        LDR r0, [r0]         @ dereference p
        LDR r1, =qVal        @ load q value
        LDR r1, [r1]         @ dereference q
        LDR r2, =pubKey      @ load e value
        LDR r2, [r2]         @ dereference e
        BL cpubexp           @ call cpubexp function
        CMP r0, #-1          @ check if cpubexp returned -1 (error)
        BNE pubKeyValidated  @ if valid, continue
            LDR r0, =pubKeyError  @ load error message
            MOV r1, r4            @ move totient to r1
            MOV r2, r4            @ move totient to r2
            BL printf             @ print error
            B promptPubKeyLoop    @ repeat loop
        pubKeyValidated:
    LDR r0, =pubKey          @ load e value
    LDR r0, [r0]             @ dereference e
    MOV r1, r4               @ move totient to r1
    BL cprivexp              @ call cprivexp function
    MOV r5, r0               @ store private key in r5
    LDR r0, =pVal            @ load p value
    LDR r0, [r0]             @ dereference p
    LDR r1, =qVal            @ load q value
    LDR r1, [r1]             @ dereference q
    MUL r1, r0, r1           @ calculate modulus (n = p * q)
    LDR r0, =displayMod      @ load modulus display message
    BL printf                @ print modulus
    LDR r0, =displayPubKey   @ load public key display message
    LDR r1, =pubKey          @ load e value
    LDR r1, [r1]             @ dereference e
    BL printf                @ print public key
    LDR r0, =displayPrivKey  @ load private key display message
    MOV r1, r5               @ move private key to r1
    BL printf                @ print private key
    POP {r4, r5, pc}         @ restore registers and return
.data
    introPrompt: .asciz "\n=====================================\n
         RSA Key Generation           \n
=====================================\n
 To generate RSA keys, provide:\n
 - Two prime numbers (P and Q), both prime.\n
 - A public key value (e) such that:\n
    - 1 < e < Φ(n)\n
    - e is co-prime to Φ(n) [ gcd(e, Φ(n)) = 1 ]\n\n"

    intFmt: .asciz "%d"
    pVal: .word 0
    qVal: .word 0

    promptP: .asciz "Enter the first prime number (P): "
    promptQ: .asciz "Enter the second prime number (Q): "
    primeError: .asciz "\n[Error] One or both of the given integers are not prime.\n"

    pubKey: .word 0
    promptE: .asciz "Enter the desired public exponent (e): "
    
    pubKeyError: .asciz "\n[Error] Invalid public key.\n
     Conditions:\n
     - e must be between 1 and %d\n
     - e must be coprime to Φ(n) (gcd(e, Φ(n)) = 1)\n"

    displayMod:      .asciz "\n[Key Pair Generated]\nModulus (n): %d\n"
    displayPubKey:   .asciz "Public Key (e): %d\n"
    displayPrivKey:  .asciz "Private Key (d): %d\n"

# END generateKeys

.global encrypt
# Function: encrypt
# Purpose:  Encrypts a message using public key and modulus
.text
encrypt:
     PUSH {r4, r5, lr}       @ save registers
     LDR r0, =promptPubKey   @ load prompt for public key
     BL printf               @ print prompt
     LDR r0, =intFmt         @ load integer format
     LDR r1, =publicKey      @ load address for public key
     BL scanf                @ read public key from user
     LDR r0, =promptModulus  @ load prompt for modulus
     BL printf               @ print prompt
     LDR r0, =intFmt         @ load integer format
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
# Purpose:  Decrypts a message using private key and modulus
.text
decrypt:
     PUSH {r4, r5, lr}       @ save registers
     LDR r0, =promptPrivKey  @ load prompt for private key
     BL printf               @ print prompt
     LDR r0, =intFmt         @ load integer format
     LDR r1, =privateKey     @ load address for private key
     BL scanf                @ read private key from user
     LDR r0, =promptModulus  @ load prompt for modulus
     BL printf               @ print prompt
     LDR r0, =intFmt         @ load integer format
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
