import ida_struct


def remove_spaces_from_name(sname):

	sname = sname.replace(",const ", ',')
	sname = sname.replace(" const,", ',')
	sname = sname.replace(" const*,", ',')
	sname = sname.replace("<const ", '<')
	sname = sname.replace(" const>", '>')
	sname = sname.replace(" const*>", '>')

	# order matters
	inttypes_map = (
		("long unsigned int", "__uint64_t"),
		("long int", "__int64_t"),
		("short unsigned int", "__uint16_t"),
		("unsigned int", "__uint32_t"),
		("signed int", "__int32_t"),
		("short int", "__int16_t"),
		("unsigned char", "__uint8_t"),
		("signed char", "__int8_t"),
		("__int128 unsigned", "__uint128_t"),
	)

	wrappers = (
		('<', '>'),
		('<', ','),
		(',', '>'),
		(',', ','),
	)

	for inttype, new_inttype in inttypes_map:
		# for prefix, suffix in wrappers:
		#	sname = sname.replace(prefix + inttype + suffix, prefix + new_inttype + suffix)
		sname = sname.replace(inttype, new_inttype)

	while "> >" in sname:
		sname = sname.replace("> >", ">>")

	sname = sname.replace(", ", ',')

	return sname


for i in range(ida_struct.get_struc_qty()):
	tid = ida_struct.get_struc_by_idx(i)
	struct_name = ida_struct.get_struc_name(tid)
	if ' ' not in struct_name:
		continue

	new_struct_name = remove_spaces_from_name(struct_name)
	if new_struct_name == struct_name:
		print("Failed to remove spaces from", struct_name)
		continue

	if ' ' in new_struct_name:
		print("Not all spaces are removed from", struct_name, '\n', "Still trying to rename")

	rv = ida_struct.set_struc_name(tid, new_struct_name)
	if not rv:
		print("Failed to rename", struct_name, '\n', "TO", '\n', new_struct_name, '\n')
		continue
