import idaapi, idc, idautils
import re

def is_good_string(ea, sz):
	for i in range(sz-1):
		if not idaapi.is_loaded(ea):
			return False

		b = idaapi.get_byte(ea + i)
		if b == 0 or b == 0xff:
			return False
	return True

r = re.compile("char\[([0-9]+)\]")
tif = idaapi.tinfo_t()
for segea in idautils.Segments():
	segname = idc.get_segm_name(segea)
	if segname != ".data":
		print("skipping segment", segname)
		continue

	segstart = idc.get_segm_start(segea)
	segend   = idc.get_segm_end(segea)
	for ea in range(segstart, segend):
		# I dont know what third arg is supposed to be, 3 just works :)))
		if not idaapi.get_type(ea, tif, 3):
			continue

		if not r.match(str(tif)):
			continue


		n = str(tif)[5:-1]
		n = int(n)

		if not is_good_string(ea, n):
			continue
		print("found at", hex(ea), tif, n)

		new_const_type = "const " + str(tif)
		idc.SetType(ea, new_const_type)