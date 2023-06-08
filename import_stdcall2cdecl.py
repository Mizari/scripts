import idaapi
import idc
import idautils

# changes prototypes of some functions, that were incorrectly assigned stdcall instead of cdecl

changed_func_names = set()

def stdcall_to_cdecl(func_addr, name, _ord):
	func_type = idc.get_type(func_addr)
	if func_type is None:
		return True

	if "__stdcall" not in func_type:
		return True

	changed_func_names.add(name)
	new_type = func_type.replace("__stdcall", "__cdecl") + ';'
	rv = idc.SetType(func_addr, new_type)
	if rv:
		print("changing", hex(func_addr), name, idc.get_type(func_addr), "to", new_type, "succeeded")
	else:
		print("changing", hex(func_addr), name, idc.get_type(func_addr), "to", new_type, "failed")
	return True

def module_sdtcall_to_cdecl(module_strs):
	changed_func_names.clear()
	nimps = idaapi.get_import_module_qty()
	for i in range(0, nimps):
		name = idaapi.get_import_module_name(i)
		if not name:
			print("Failed to get import module name for #%d" % i)
			continue

		if name not in module_strs:
			continue

		idaapi.enum_import_names(i, stdcall_to_cdecl)

module_names = ["COREDLL", "WINSOCK", "OLEAUT32", "atlce400", "ole32", "CEDDK"]
module_sdtcall_to_cdecl(module_names)


for segea in idautils.Segments():
	for func_addr in idautils.Functions(segea, idc.get_segm_end(segea)):
		fname = idc.get_func_name(func_addr)
		if fname == "" or fname is None:
			continue

		if "__imp__" + fname not in changed_func_names:
			continue

		func_type = idc.get_type(func_addr)
		if func_type is None:
			continue

		if "__stdcall" not in func_type:
			continue

		idc.SetType(func_addr, func_type.replace("__stdcall", "__cdecl foo") + ';')