import idaapi
import idc
import idautils

def get_pointer_size() -> int:
	if idaapi.get_inf_structure().is_64bit():
		return 8
	elif idaapi.get_inf_structure().is_32bit():
		return 4
	else:
		return 2


def get_offsets(start, end):
	iterator = start
	ints_set = 0
	ptr_size = get_pointer_size()
	while iterator < end - 4:
		dw = idaapi.get_dword(iterator)
		if not idaapi.is_loaded(dw):
			iterator += 1
			continue

		cur_type = idc.get_type(dw)
		if cur_type is not None and cur_type != "char[4]":
			iterator += ptr_size
			continue

		idc.SetType(iterator, "void*")
		ints_set += 1
		iterator += ptr_size
	print('Found', ints_set, "int pointers")

def get_offsets_everywhere():
	for segea in idautils.Segments():
		segname = idc.get_segm_name(segea)
		if segname not in (".data", ".data.rel.ro"):
			continue

		segstart = idc.get_segm_start(segea)
		segend = idc.get_segm_end(segea)
		get_offsets(segstart, segend)

if __name__ == "__main__":
	get_offsets_everywhere()