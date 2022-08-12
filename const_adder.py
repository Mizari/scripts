import idaapi, idc, idautils
import re


def get_c_string(ea):
	s = ""
	while True:
		if not idaapi.is_loaded(ea):
			break

		c = idaapi.get_byte(ea)
		if c == 0 or c == 0xff:
			break
		s += chr(c)
		ea += 1
	return s


def add_consts():
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

			if idaapi.get_name(ea) == '':
				continue

			type_string = str(tif)
			if type_string != "char []" and r.match(type_string):
				continue

			cstr = get_c_string(ea)
			if len(cstr) < 3:
				continue

			print("found at", hex(ea), tif, cstr)

			new_const_type = "const " + str(tif)
			idc.SetType(ea, new_const_type)

if __name__ == "__main__":
	add_consts()