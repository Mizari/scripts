import idaapi
import idc
import idautils


def get_offsets(start, end):
	iterator = start
	ints_set = 0
	while iterator < end - 4:
		dw = idaapi.get_dword(iterator)
		if not idaapi.is_loaded(dw):
			iterator += 1
			continue

		cur_type = idc.get_type(dw)
		if cur_type is not None and cur_type != "char[4]":
			iterator += 4
			continue

		idc.SetType(iterator, "void*")
		ints_set += 1
		iterator += 4
	print('ints sets', ints_set)

for segea in idautils.Segments():
	segname = idc.get_segm_name(segea)
	if segname != ".data":
		continue

	segstart = idc.get_segm_start(segea)
	segend = idc.get_segm_end(segea)
	get_offsets(segstart, segend)
