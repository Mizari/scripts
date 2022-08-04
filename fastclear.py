import idaapi

class MyHandler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		idaapi.msg_clear()
		return 0

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

if idaapi.get_action_shortcut("Quit") == "Alt-X":
	idaapi.update_action_shortcut("Quit", None)

action_desc = idaapi.action_desc_t(
	'fast:clear',   # The action name. This acts like an ID and must be unique
	'Quickly clears output window',  # The action text.
	MyHandler(),   # The action handler.
	'Alt+X',      # Optional: the action shortcut
	'Clear output window',  # Optional: the action tooltip (available in menus/toolbar)
	199)           # Optional: the action icon (shows when in menus/toolbars)

idaapi.register_action(action_desc)

class FastclearPlugin(idaapi.plugin_t):
	flags = 0
	wanted_name = "fastclear"

	def init(self):
		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		return

	def term(self):
		return

def PLUGIN_ENTRY():
	return FastclearPlugin()