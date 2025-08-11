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

.section  .note.GNU-stack,"",%progbits
