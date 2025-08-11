# File: rsa_main.s
# Authors: [Team]
# Description: Main driver for RSA encryption/decryption.
#              Handles key generation, encryption, and decryption.

.global main
.text
main:
    PUSH {r4, r5, r6, lr}     @ save registers

    LDR r0, =msg_prompt       @ load the prompt message
    BL printf               @ print the prompt

    LDR r0, =fmt_int        @ load integer input format
    LDR r1, =user_choice    @ get address for user input
    BL scanf                @ read the user input

    LDR r0, =user_choice    @ load the user choice value
    LDR r0, [r0]            @ get the value from memory
    CMP r0, #1              @ compare if choice equals 1
    BNE choiceElse1
        BL generateKeys     @ generate keys if choice is 1
        B choiceEnd

choiceElse1:
    CMP r0, #2              @ check if choice equals 2
    BNE choiceElse2
        BL encrypt          @ encrypt message if choice is 2
        B choiceEnd

choiceElse2:
    CMP r0, #3              @ check if choice equals 3
    BNE choiceElse3
        BL decrypt          @ decrypt message if choice is 3
        B choiceEnd

choiceElse3:
    B invalidChoice         @ Jump to error if choice is invalid

choiceEnd:
    B finish                @ end of choice handling

invalidChoice:
    LDR r0, =msg_error      @ load error message
    BL printf               @ print the error message
    B finish

finish:
    POP {r4, r5, r6, pc}     @ restore registers and exit

.data
    msg_prompt: .asciz "\n===== RSA Encryption System =====\n
     Select an option:\n
     1 - Generate RSA Key Pair\n
     2 - Encrypt a Message\n
     3 - Decrypt a Message\n
     Selection: "
    fmt_int:     .asciz "%d"
    msg_error:   .asciz "\n[Error] Invalid selection. Please enter 1, 2, or 3.\n"
    user_choice: .word 0



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


.global str_to_array
.text
# Function: str_to_array
# Author: Kassem Arif
# Converts a string into an array of 32-bit integers.
# Input:    
#   r0 - Pointer to the string
#   r1 - Length of the string
# Output:   
#   r0 - Pointer to the integer array
#   r1 - Size of the array
str_to_array:
    SUB sp, sp, #20
    STR lr, [sp, #0]
    STR r4, [sp, #4]
    STR r5, [sp, #8]
    STR r6, [sp, #12]
    STR r7, [sp, #16]

    MOV r4, r0               @ Pointer to input string
    MOV r5, r1               @ String length
    LSL r0, r5, #2           @ Allocate memory (4 bytes per char)
    BL malloc
    MOV r6, r0               @ Pointer to new integer array
    MOV r7, #0               @ Loop counter

str_to_array_loop:
    CMP r7, r5
    BGE str_to_array_done
    LDRB r0, [r4, r7]        @ Load character
    LSL r1, r7, #2
    STR r0, [r6, r1]         @ Store as integer
    ADD r7, r7, #1
    B str_to_array_loop

str_to_array_done:
    MOV r0, r6               @ Return array pointer
    MOV r1, r5               @ Return size
    LDR lr, [sp, #0]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    LDR r6, [sp, #12]
    LDR r7, [sp, #16]
    ADD sp, sp, #20
    MOV pc, lr


.global array_to_str
.text
# Function: array_to_str
# Author: Kassem Arif
# Converts an integer array into a string with a null terminator.
# Input:    
#   r0 - Pointer to the integer array
#   r1 - Number of elements in the array
# Output:   
#   r0 - Pointer to the converted string
#   r1 - Length of the string
array_to_str:
    SUB sp, sp, #20
    STR lr, [sp, #0]
    STR r4, [sp, #4]
    STR r5, [sp, #8]
    STR r6, [sp, #12]
    STR r7, [sp, #16]

    MOV r4, r0               @ Pointer to integer array
    MOV r5, r1               @ Array size
    ADD r0, r5, #1           @ Allocate space (extra for null terminator)
    BL malloc
    MOV r6, r0               @ Pointer to new string
    MOV r7, #0               @ Loop counter

array_to_str_loop:
    CMP r7, r5
    BGE array_to_str_done
    LSL r1, r7, #2
    LDR r0, [r4, r1]         @ Load integer
    STRB r0, [r6, r7]        @ Store as byte
    ADD r7, r7, #1
    B array_to_str_loop

array_to_str_done:
    MOV r0, #0
    STRB r0, [r6, r7]        @ Add null terminator
    MOV r0, r6               @ Return pointer to string
    MOV r1, r5               @ Return size
    LDR lr, [sp, #0]
    LDR r4, [sp, #4]
    LDR r5, [sp, #8]
    LDR r6, [sp, #12]
    LDR r7, [sp, #16]
    ADD sp, sp, #20
    MOV pc, lr




.global write_file
.text
# Function: write_file
# Author: Kassem Arif
# Saves a string to a file.
# Input:    
#   r0 - File name
#   r1 - Pointer to the string to write
write_file:
    PUSH {r4, r5, lr}

    MOV r5, r1               @ Store message pointer
    LDR r1, =file_write_mode
    BL fopen
    MOV r4, r0               @ Store file pointer
    CMP r4, #0
    BEQ write_error

    MOV r0, r4
    MOV r1, r5
    BL fprintf

    MOV r0, r4
    BL fclose
    B write_done

write_error:
    LDR r0, =error_write_msg
    BL printf

write_done:
    POP {r4, r5, pc}

.data
file_write_mode: .asciz "w"
error_write_msg: .asciz "\nERROR: COULDN'T WRITE TO FILE\n"





.global write_array
.text
# Function: write_array
# Author: Kassem Arif
# Saves an integer array to a file.
# Input:    
#   r0 - File name
#   r1 - Pointer to the array
#   r2 - Number of elements in the array
write_array:
    PUSH {r4, r5, r6, r7, lr}

    MOV r5, r1               @ Pointer to array
    MOV r6, r2               @ Array size
    LDR r1, =file_write_mode
    BL fopen
    MOV r4, r0
    CMP r4, #0
    BEQ write_array_error

    MOV r7, #0
write_array_loop:
    CMP r7, r6
    BGE write_array_done
    LSL r3, r7, #2
    LDR r2, [r5, r3]
    MOV r0, r4
    LDR r1, =write_format
    BL fprintf
    ADD r7, r7, #1
    B write_array_loop

write_array_done:
    MOV r0, r4
    BL fclose
    B write_array_exit

write_array_error:
    LDR r0, =error_write_msg
    BL printf

write_array_exit:
    POP {r4, r5, r6, r7, pc}

.data
write_format: .asciz "%d "




.global read_array
.text
# Function: read_array
# Author: Kassem Arif
# Reads integers from a file into an array.
# Input:    
#   r0 - File name
# Output:   
#   r0 - Pointer to the integer array
#   r1 - Number of elements in the array
read_array:
    PUSH {r4, r5, r6, r7, lr}

    LDR r1, =file_read_mode
    BL fopen
    MOV r4, r0
    CMP r4, #0
    BEQ read_error

    MOV r6, #0
    MOV r0, r4
    BL feof
    CMP r0, #0
    BNE read_done

read_loop:
    MOV r0, r4
    LDR r1, =read_format
    LDR r2, =num_buffer
    BL fscanf

    MOV r0, r4
    BL feof
    CMP r0, #0
    BNE read_done

    LDR r0, =num_buffer
    LDR r0, [r0]
    PUSH {r0}
    ADD r6, r6, #1
    B read_loop

read_done:
    LSL r0, r6, #2
    BL malloc
    MOV r5, r0

    MOV r7, #1
store_loop:
    CMP r7, r6
    BGT store_done
    SUB r1, r6, r7
    LSL r1, r1, #2
    POP {r0}
    STR r0, [r5, r1]
    ADD r7, r7, #1
    B store_loop

store_done:
    MOV r0, r4
    BL fclose
    B read_exit

read_error:
    LDR r0, =error_read_msg
    BL printf

read_exit:
    MOV r0, r5               @ Return array pointer
    MOV r1, r6               @ Return array size
    POP {r4, r5, r6, r7, pc}

.data
read_format: .asciz "%d"
num_buffer: .word 0
file_read_mode: .asciz "r+"
error_read_msg: .asciz "ERROR: NULL FILE\n"