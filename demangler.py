import idautils
import idaapi
import idc
import re


def iterate_all_functions():
	for segea in idautils.Segments():
		for funcea in idautils.Functions(segea, idc.get_segm_end(segea)):
			yield funcea
	# TODO demangle imports?


def idc_demangle_function(func_name:str) -> str:
	return idaapi.demangle_name(func_name, idaapi.MNG_NODEFINIT | idaapi.MNG_NORETTYPE)


class Demangler:
	# regular expression to replace some illegal c++ mangle chars for IDA names
	ILLEGAL_CHARS = "`',()<>*+-/.&={}#!"
	ILLEGAL_CHARS = re.compile("[" + ILLEGAL_CHARS + "]")

	# regular expression to rempve c++ templates
	DETEMPLATER = r"[<][^<>]*[>]"
	DETEMPLATER = re.compile(DETEMPLATER)

	# if demangled function starts with this prefix, then skip demangling it
	PREFIX_SKIP_LIST = [
		"fmt::v7",
		"spdlog::",
		"__gnu_cxx::",
		"boost::",
		"nlohmann::",
		"eka::",
		"operator delete",
		"operator new",
		"__gnu_internal::",
		"__cxxabiv1::",
	]

	# remove this substrings from demangled name
	REMOVE_LIST = [
		"`anonymous namespace'::",
		"`virtual thunk to'",
		"`non-virtual thunk to'",
		"[abi:cxx11]",
	]

	def __init__(self, skipoptions=()):
		self.skip_options = skipoptions

	def demangle_string(self, string_to_demangle: str):
		# global constructors
		if string_to_demangle.startswith("_GLOBAL__sub_I_"):
			string_to_demangle = string_to_demangle[15:]

		dfname = idc_demangle_function(string_to_demangle)
		if dfname is None:
			return None
		return self.post_demangle(dfname)

	@classmethod
	def apply_removes(cls, func_name):
		for remover in cls.REMOVE_LIST:
			func_name = func_name.replace(remover, '')
		return func_name

	@classmethod
	def apply_prefixes(cls, func_name):
		for prefix in cls.PREFIX_SKIP_LIST:
			if func_name.startswith(prefix):
				return None
		return func_name

	@classmethod
	def apply_detemplater(cls, func_name):
		new_name = re.sub(cls.DETEMPLATER, '', func_name)
		while func_name != new_name:
			func_name = new_name
			new_name = re.sub(cls.DETEMPLATER, '', func_name)

		return func_name

	@classmethod
	def apply_illegals(cls, func_name):
		return re.sub(cls.ILLEGAL_CHARS, '_', func_name)
	
	@classmethod
	def apply_detilder(cls, func_name):
		if '~' in func_name:
			func_name = func_name.replace('~', '')
			func_name = func_name + "_destructor"
		return func_name

	def post_demangle(self, func_name):
		def apply_func(func, skip_option):
			nonlocal func_name
			if func_name is None: return None
			if skip_option in self.skip_options:
				return func_name
			func_name = func(func_name)

		apply_func(self.apply_removes,     "noremoves")
		apply_func(self.apply_prefixes,    "noprefixes")
		apply_func(self.apply_detemplater, "nodetemplater")
		apply_func(self.apply_illegals,    "noillegals")
		apply_func(self.apply_detilder,    "nodetilder")

		if func_name is not None and ' ' in func_name:
			return None

		return func_name


class Renamer:
	def __init__(self):
		self.functions_to_rename = {}
		self.conflicting_names = {}
		self.renames_applied = {}
		self.renames_failed = {}

	def add_conflict(self, funcea, new_name):
		conflicts = self.conflicting_names.setdefault(new_name, [])
		conflicts.append(funcea)

	def add_rename(self, funcea, new_name):
		conflicts = self.conflicting_names.get(new_name, None)
		if conflicts is not None:
			conflicts.append(funcea)
			return

		added_funcea = self.functions_to_rename.pop(new_name, None)
		if added_funcea is not None:
			self.add_conflict(funcea, new_name)
			self.add_conflict(added_funcea, new_name)
			return

		existing_ea = idc.get_name_ea_simple(new_name)
		if existing_ea != idaapi.BADADDR:
			self.add_conflict(funcea, new_name)
			return

		self.functions_to_rename[new_name] = funcea

	def resolve_conflicts(self):
		def name_conflicts(func_name):
			if idc.get_name_ea_simple(func_name) != idaapi.BADADDR:
				return True
			return func_name in self.functions_to_rename

		for new_name, funcs in self.conflicting_names.items():
			idx = 0
			for funcea in funcs:
				resolved_name = new_name
				while name_conflicts(resolved_name):
					idx += 1
					resolved_name = new_name + str(idx)
				self.functions_to_rename[resolved_name] = funcea

		self.conflicting_names.clear()

	def count_conflicts(self):
		return sum(len(x) for x in self.conflicting_names.values())

	def print_info(self):
		self.print_renamed()
		self.print_fails()
		self.print_conflits()

	def print_conflits(self, print_full=False):
		print("conflicting_functions", self.count_conflicts())
		for new_name, objects in self.conflicting_names.items():
			print("conflicted dfname" + '(' + str(len(objects)) + ')', new_name)
			if print_full == False: continue

			for obj_ea in objects:
				name = idaapi.get_name(obj_ea)
				print('\t', hex(obj_ea), name)

	def print_fails(self):
		print("failed renames", len(self.renames_failed))
		for obj_ea, new_name in self.renames_failed.items():
			obj_name = idaapi.get_name(obj_ea)
			print("failed to rename", obj_name, "to", new_name)

	def print_renamed(self):
		print("total renamed:", len(self.renames_applied))
		for obj_ea, new_name in self.renames_applied.items():
			obj_name = idaapi.get_name(obj_ea)
			print("successfully renamed", obj_name, "at", hex(obj_ea), "to", new_name)

	def apply_renames(self):
		for new_name, funcea in self.functions_to_rename.items():
			setnamerv = idc.set_name(funcea, new_name)
			if setnamerv == 1:
				self.renames_applied[funcea] = new_name
			else:
				self.renames_failed[funcea] = new_name
		self.functions_to_rename.clear()


def demangle_selected_objects(*addresses, skipoptions=()):
	renamer = Renamer()
	demangler = Demangler(skipoptions=skipoptions)

	for obj_ea in addresses:
		name = idaapi.get_name(obj_ea)
		if name == '': continue

		demangled_name = demangler.demangle_string(name)
		if demangled_name is None: continue

		renamer.add_rename(obj_ea, demangled_name)

	renamer.resolve_conflicts()
	renamer.apply_renames()
	return renamer

def demangle_all_objects(skipoptions=()):
	addresses = []
	for segea in idautils.Segments():
		segname = idc.get_segm_name(segea)
		if segname not in (".data", ".idata"):
			continue

		segstart = idc.get_segm_start(segea)
		segend = idc.get_segm_end(segea)
		for i in range(segstart, segend):
			if idaapi.get_name(i) != '':
				addresses.append(i)
	return demangle_selected_objects(*addresses, skipoptions=skipoptions)


def demangle_all_functions(skipoptions=()):
	func_names = [idaapi.get_func_name(fea) for fea in iterate_all_functions()]
	return demangle_selected_objects(*func_names, skipoptions=skipoptions)