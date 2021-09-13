import idaapi

class MyHandler(idaapi.action_handler_t):
	def __init__(self):
		idaapi.action_handler_t.__init__(self)

	def activate(self, ctx):
		curr = idaapi.get_current_widget()

		form = idaapi.find_widget("Output window")
		w = idaapi.PluginForm.FormToPyQtWidget(form)
		w.activateWindow()
		w.setFocus()
		idaapi.process_ui_action("msglist:Clear")

		form = idaapi.find_widget("Output")
		w = idaapi.PluginForm.FormToPyQtWidget(form)
		w.activateWindow()
		w.setFocus()
		idaapi.process_ui_action("msglist:Clear")

		w = idaapi.PluginForm.FormToPyQtWidget(curr)
		w.activateWindow()
		w.setFocus()
		return 1

	def update(self, ctx):
		return idaapi.AST_ENABLE_ALWAYS

action_desc = idaapi.action_desc_t(
	'fast:clear',   # The action name. This acts like an ID and must be unique
	'Quickly clears output window',  # The action text.
	MyHandler(),   # The action handler.
	'Alt+X',      # Optional: the action shortcut
	'Clear output window',  # Optional: the action tooltip (available in menus/toolbar)
	199)           # Optional: the action icon (shows when in menus/toolbars)

idaapi.register_action(action_desc)