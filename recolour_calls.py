import idaapi
import idc

COLOR_CALL = 0xffffd0


if __name__ == "__main__":
	next_instr = 0
	while next_instr != idaapi.BADADDR:

		next_instr = idc.next_head(next_instr)

		insn = idaapi.insn_t()
		idaapi.decode_insn(insn, next_instr)
		if idaapi.is_call_insn(insn):
			idaapi.set_item_color(next_instr, COLOR_CALL)

	idaapi.refresh_idaview_anyway()
