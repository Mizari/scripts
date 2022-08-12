import idaapi
import idc
from collections import defaultdict

# COLOR_CALL = 0xffffd0
# BGR
DEFAULT_COLOR_CALL = 0x505000

def iterate_all_instructions():
	next_instr = 0
	next_instr = idc.next_head(next_instr)
	while next_instr != idaapi.BADADDR:
		yield next_instr
		next_instr = idc.next_head(next_instr)

def iterate_all_calls():
	for instr_ea in iterate_all_instructions():
		insn = idaapi.insn_t()
		idaapi.decode_insn(insn, instr_ea)
		if idaapi.is_call_insn(insn):
			yield instr_ea

def iterate_all_noncalls():
	for instr_ea in iterate_all_instructions():
		insn = idaapi.insn_t()
		idaapi.decode_insn(insn, instr_ea)
		if not idaapi.is_call_insn(insn):
			yield instr_ea

def recolour_calls(item_color=DEFAULT_COLOR_CALL):
	for call_ea in iterate_all_calls():
		idaapi.set_item_color(call_ea, item_color)

	idaapi.refresh_idaview_anyway()

def undo_recolour_calls():
	colors = defaultdict(int)
	for instr_ea in iterate_all_noncalls():
		color = idaapi.get_item_color(instr_ea)
		colors[color] += 1

	max_color = max((k for k in colors), key=colors.__getitem__)
	recolour_calls(max_color)


if __name__ == "__main__":
	recolour_calls()