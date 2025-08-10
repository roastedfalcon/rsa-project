@ generate_keys.s - Contains the high-level logic for each menu option.

.text
@ External functions from RSALib that we will call
.extern totient
.extern cpubexp
.extern cprivexp

@ External C library functions
.extern printf
.extern scanf

@ We need to know the addresses of the data in RSA.s
.extern p_prompt, q_prompt, e_prompt, scan_format, p_val, q_val, e_val
.extern n_val, phi_n_val, d_val, prime_error_msg, e_error_msg
.extern keys_header, pub_key_format, priv_key_format

.global generate_keys
@ ---
@ Function: generate_keys
@ Description: Handles the entire user flow for generating RSA keys.
@ ---
generate_keys:
    PUSH    {lr}            @ Save link register for this function

    @ 1. Get p from user
    LDR     r0, =p_prompt
    BL      printf
    LDR     r0, =scan_format
    LDR     r1, =p_val
    BL      scanf

    @ 2. Get q from user
    LDR     r0, =q_prompt
    BL      printf
    LDR     r0, =scan_format
    LDR     r1, =q_val
    BL      scanf

    @ 3. Calculate totient (which also validates if p and q are prime)
    LDR     r0, =p_val
    LDR     r0, [r0]
    LDR     r1, =q_val
    LDR     r1, [r1]
    BL      totient
    CMP     r0, #-1         @ totient returns -1 on error
    BEQ     prime_error

    @ Store phi_n if successful
    LDR     r1, =phi_n_val
    STR     r0, [r1]

    @ 4. Calculate n = p * q
    LDR     r0, =p_val
    LDR     r0, [r0]
    LDR     r1, =q_val
    LDR     r1, [r1]
    MUL     r2, r0, r1
    LDR     r3, =n_val
    STR     r2, [r3]

get_e_loop:
    @ 5. Get e from user
    LDR     r0, =e_prompt
    BL      printf
    LDR     r0, =scan_format
    LDR     r1, =e_val
    BL      scanf

    @ 6. Validate e by calling cpubexp
    LDR     r0, =e_val
    LDR     r0, [r0]        @ r0 = e
    LDR     r1, =phi_n_val
    LDR     r1, [r1]        @ r1 = phi_n
    BL      cpubexp
    CMP     r0, #0          @ cpubexp returns 0 on error
    BEQ     e_error         @ If invalid, print error and loop

    @ 7. Calculate d by calling cprivexp
    LDR     r0, =e_val
    LDR     r0, [r0]        @ r0 = e
    LDR     r1, =phi_n_val
    LDR     r1, [r1]        @ r1 = phi_n
    BL      cprivexp
    LDR     r1, =d_val
    STR     r0, [r1]        @ Store d

    @ 8. Print the final keys
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
    @ --- Key Generation Data ---
p_prompt:         .asciz  "Enter the first prime number (p): "
q_prompt:         .asciz  "Enter the second prime number (q): "
e_prompt:         .asciz  "Enter a public key exponent (e): "
prime_error_msg:  .asciz  "Error: One or both numbers are not prime. Please try again.\n"
e_error_msg:      .asciz  "Error: Invalid public exponent 'e'. It must be 1 < e < phi(n) and coprime to phi(n).\n"
keys_header:      .asciz  "\n--- Keys Generated Successfully ---\n"
pub_key_format:   .asciz  "Public Key (n, e):  (%d, %d)\n"
priv_key_format:  .asciz  "Private Key (n, d): (%d, %d)\n"
