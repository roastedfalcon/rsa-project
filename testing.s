@ testing.s - A test harness for the 'mod' function

.text
.extern mod @ Tell the assembler that 'mod' exists in another file

.global main
main:
    push    {lr}            @ Save link register for a clean exit

    @ --- Test Case 1: 10 % 3 ---
    ldr     r0, =12         @ Set dividend
    ldr     r1, =3          @ Set divisor
    bl      mod             @ Call the function. Result will be in r0.

    @ --- Print the result ---
    mov     r1, r0          @ Move the result into r1 (the 2nd argument for printf)
    ldr     r0, =format_str @ Load the address of our format string into r0
    bl      printf          @ Call the C library printf function

    @ --- Clean Exit ---
    mov     r0, #0          @ Return 0 to the OS
    pop     {pc}            @ Return from main

.data
format_str:
    .asciz  "The result of 11 %% 3 is: %d\n"