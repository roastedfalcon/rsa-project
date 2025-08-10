# File: rsa_io.s
# Authors: [Team]
# Description: Handles input/output operations for RSA encryption.


.global str_to_array
.text
# Function: str_to_array
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

.section  .note.GNU-stack,"",%progbits

