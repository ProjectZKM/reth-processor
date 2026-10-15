// reth_jumpdest_scan(code: *const u8, len: usize, table: *mut u8)
//
// The JUMPDEST bitmap of `code[..len]` for the zkVM guest: bit `i & 7` of
// `table[i >> 3]` is set when byte `i` starts an instruction and is 0x5b.
// `table` holds ceil(len / 8) zeroed bytes, and `code` must be readable up to
// `len + 32`: the RawCode padding, which the walk reads ahead into.
//
// The compiled walk spends nine instructions per opcode, two of them nops in
// branch delay slots.  Here the slots carry work: the cursor advance sits in
// the JUMPDEST test's slot and the next opcode's load in the loop branch's,
// six instructions per opcode.  The load ahead reads at most 32 bytes past
// `len` (a PUSH32 at `len - 1`), inside the padding.
	.section .rodata.reth_jumpdest_span,"a",@progbits
	.p2align	2
.Lreth_jumpdest_span:
	# bytes an opcode spans: n + 1 for PUSHn (0x60..0x7f), else 1
	.fill	96, 1, 1
	.byte	2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
	.byte	18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33
	.fill	128, 1, 1

	.text
	.globl	reth_jumpdest_scan
	.p2align	2
	.type	reth_jumpdest_scan,@function
	.set	nomicromips
	.set	nomips16
	.ent	reth_jumpdest_scan
reth_jumpdest_scan:
	.frame	$sp,0,$ra
	.set	noreorder
	.set	nomacro
	.set	noat
	beqz	$5, .Lreth_jumpdest_done
	addu	$9, $4, $5
	lui	$10, %hi(.Lreth_jumpdest_span)
	addiu	$10, $10, %lo(.Lreth_jumpdest_span)
	addiu	$11, $zero, 0x5b
	move	$12, $4
	lbu	$13, 0($12)
.Lreth_jumpdest_loop:
	# $12 cursor, $13 the opcode under it, $9 end
	addu	$14, $10, $13
	lbu	$14, 0($14)
	beq	$13, $11, .Lreth_jumpdest_mark
	addu	$12, $12, $14
.Lreth_jumpdest_next:
	sltu	$1, $12, $9
	bnez	$1, .Lreth_jumpdest_loop
	lbu	$13, 0($12)
.Lreth_jumpdest_done:
	jr	$ra
	nop
.Lreth_jumpdest_mark:
	# the cursor is one past the JUMPDEST: its index is $12 - 1 - code
	subu	$14, $12, $4
	addiu	$14, $14, -1
	srl	$15, $14, 3
	addu	$15, $6, $15
	lbu	$24, 0($15)
	andi	$14, $14, 7
	addiu	$25, $zero, 1
	sllv	$25, $25, $14
	or	$24, $24, $25
	b	.Lreth_jumpdest_next
	sb	$24, 0($15)
	.set	at
	.set	macro
	.set	reorder
	.end	reth_jumpdest_scan
	.size	reth_jumpdest_scan, .-reth_jumpdest_scan
