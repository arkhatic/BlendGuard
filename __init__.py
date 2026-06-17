# SPDX-License-Identifier: GPL-3.0-or-later
# BlendGuard - transparency before trust for .blend files (inspection-only).
#
# Reports two things, kept separate on purpose:
#   * "What will run on open" - a neutral inventory (scripts, drivers, OSL nodes).
#   * "Security concerns" - only genuinely meaningful capabilities, each with a
#     plain-English explanation of when it is dangerous and when it is normal.
# A clean file shows the inventory and "no specific security concerns".
#
# Static analysis only, no network. Detection lives in scanner.py.

import os
import bpy
from bpy.app.handlers import persistent
from bpy.props import StringProperty, BoolProperty

from . import scanner

LAST = {"severity": None, "inventory": None, "concerns": [], "autorun": None, "items": 0}
DISK = {"name": None, "severity": None, "note": "", "concerns": []}

_VERDICT_ICON = {
    scanner.CLEAN: "CHECKMARK", scanner.INFO: "INFO",
    scanner.SUSPICIOUS: "ERROR", scanner.DANGEROUS: "CANCEL",
    scanner.INCOMPLETE: "QUESTION",
}
_SEV_ICON = {"critical": "CANCEL", "high": "ERROR", "review": "INFO"}

_INCOMPLETE_HELP = [
    "This .blend is compressed (normal for Blender 3.0+), so it cannot be",
    "fully read from disk without opening it. This is NOT an error and NOT",
    "a sign of malware. To inspect it safely:",
    "1. Keep 'Auto-Run Python Scripts' OFF (Preferences > Save & Load).",
    "2. Open the file - with Auto-Run off, embedded scripts will NOT run.",
    "3. Press 'Inspect This File' in this panel.",
]


def _clip(s, n=70):
    s = (s or "").replace("\n", " ")
    return s if len(s) <= n else s[:n - 1] + "…"


class BlendGuardPrefs(bpy.types.AddonPreferences):
    bl_idname = __package__

    inspect_on_open: BoolProperty(
        name="Inspect automatically when a file opens",
        description="Off by default. The recommended flow is to scan a file before opening it, "
                    "or press Inspect manually. Enable this only if you want an automatic check on every open.",
        default=False,
    )

    def draw(self, context):
        col = self.layout.column()
        col.prop(self, "inspect_on_open")
        col.label(text="Recommended: keep Auto-Run Python Scripts off, and scan files before opening them.")
        col.label(text="Static analysis only. No code is executed and no network access is used.")


def _prefs():
    try:
        return bpy.context.preferences.addons[__package__].preferences
    except Exception:
        return None


def _autorun_enabled():
    try:
        return bool(bpy.context.preferences.filepaths.use_scripts_auto_execute)
    except Exception:
        return None


_DRIVER_COLLECTIONS = ("objects", "materials", "node_groups", "scenes", "worlds",
                       "meshes", "lights", "cameras", "armatures", "curves", "shape_keys")
_NODE_COLLECTIONS = ("materials", "node_groups", "worlds", "scenes", "lights", "linestyles", "textures")


def _iter_driver_expressions():
    for cname in _DRIVER_COLLECTIONS:
        coll = getattr(bpy.data, cname, None)
        if not coll:
            continue
        for idblock in coll:
            ad = getattr(idblock, "animation_data", None)
            if not ad:
                continue
            for fc in getattr(ad, "drivers", []) or []:
                expr = getattr(getattr(fc, "driver", None), "expression", "") or ""
                if expr.strip():
                    yield ("%s:%s" % (cname, getattr(idblock, "name", "?")), expr)


def _iter_osl_scripts():
    for cname in _NODE_COLLECTIONS:
        coll = getattr(bpy.data, cname, None)
        if not coll:
            continue
        for idblock in coll:
            nt = getattr(idblock, "node_tree", None)
            nodes = getattr(nt, "nodes", None) if nt else None
            if not nodes:
                continue
            for node in nodes:
                if getattr(node, "type", "") == "SCRIPT":
                    try:
                        if getattr(node, "mode", "") == "INTERNAL" and getattr(node, "script", None):
                            yield ("osl:%s" % getattr(idblock, "name", "?"), node.script.as_string())
                        else:
                            yield ("osl:%s" % getattr(idblock, "name", "?"), "ShaderNodeScript external " + (getattr(node, "filepath", "") or ""))
                    except Exception:
                        continue


def _collect_items():
    items = []
    for t in getattr(bpy.data, "texts", []) or []:
        try:
            body = t.as_string()
        except Exception:
            body = ""
        items.append({"name": getattr(t, "name", "text"), "kind": "text", "body": body,
                      "registered": bool(getattr(t, "use_module", False))})
    for name, expr in _iter_driver_expressions():
        items.append({"name": name, "kind": "driver", "body": expr, "registered": True})
    for name, body in _iter_osl_scripts():
        items.append({"name": name, "kind": "osl", "body": body, "registered": True})
    return items


def run_inspection(source="manual"):
    items = _collect_items()
    result = scanner.scan_items(items)
    LAST.update({
        "severity": result["severity"],
        "inventory": scanner.will_run(items),
        "concerns": scanner.concerns(result),
        "autorun": _autorun_enabled(),
        "items": len(items),
    })
    _redraw()
    return result


def _redraw():
    try:
        for win in bpy.context.window_manager.windows:
            for area in win.screen.areas:
                if area.type == 'VIEW_3D':
                    area.tag_redraw()
    except Exception:
        pass


def _inventory_text():
    inv = LAST.get("inventory") or {}
    return "Will run on open: %d script(s), %d driver(s), %d OSL node(s)" % (
        inv.get("scripts", 0), inv.get("drivers", 0), inv.get("osl", 0))


def _clean_summary():
    if LAST.get("items", 0) == 0:
        return "No embedded scripts, drivers, or OSL nodes. Nothing will auto-run."
    return "Inspected %d datablock(s). None execute code, reach the network, or write scripts." % LAST["items"]


def _draw_concerns(layout, concerns):
    for c in concerns[:10]:
        layout.label(text=c["label"], icon=_SEV_ICON.get(c["severity"], "INFO"))
        if c.get("danger"):
            layout.label(text="    when it matters: " + _clip(c["danger"]), icon='NONE')
        if c.get("legit"):
            layout.label(text="    usually fine: " + _clip(c["legit"]), icon='NONE')


def _popup_in_session(title):
    sev = LAST["severity"] or scanner.CLEAN
    concerns = LAST["concerns"]

    def draw(self, context):
        layout = self.layout
        if LAST["autorun"]:
            layout.label(text="Auto-Run is ON - scripts run on open", icon='ERROR')
        else:
            layout.label(text="Auto-Run is OFF - nothing was executed", icon='CHECKMARK')
        layout.label(text=_inventory_text(), icon='TEXT')
        layout.separator()
        if not concerns:
            layout.label(text=_clean_summary(), icon='CHECKMARK')
        else:
            layout.label(text="Security concerns (%d):" % len(concerns), icon=_VERDICT_ICON.get(sev, "INFO"))
            _draw_concerns(layout, concerns)
        layout.separator()
        layout.operator("blendguard.report_to_text", icon='TEXT')
    try:
        bpy.context.window_manager.popup_menu(draw, title="%s:  %s" % (title, sev), icon=_VERDICT_ICON.get(sev, "INFO"))
    except Exception:
        pass


def _full_report_text():
    out = ["BlendGuard report", "=" * 40, ""]
    out.append("IN-SESSION (current file)")
    if LAST["severity"] is None:
        out.append("  (not inspected yet - press 'Inspect This File')")
    else:
        out.append("  Verdict: %s" % LAST["severity"])
        out.append("  Auto-Run Python Scripts: %s" % ("ON" if LAST["autorun"] else "OFF"))
        out.append("  " + _inventory_text())
        if not LAST["concerns"]:
            out.append("  " + _clean_summary())
        else:
            out.append("  Security concerns (%d):" % len(LAST["concerns"]))
            for c in LAST["concerns"]:
                out.append("    - [%s] %s" % (c["severity"].upper(), c["label"]))
                if c.get("what"):
                    out.append("        what:   %s" % c["what"])
                if c.get("danger"):
                    out.append("        danger: %s" % c["danger"])
                if c.get("legit"):
                    out.append("        normal: %s" % c["legit"])
    if DISK["name"]:
        out += ["", "ON-DISK SCAN: %s" % DISK["name"], "  Verdict: %s" % DISK["severity"]]
        if DISK["note"]:
            out.append("  Note: %s" % DISK["note"])
        for c in DISK["concerns"]:
            out.append("    - [%s] %s : %s" % (c["severity"].upper(), c["label"], c.get("danger", "")))
    out += ["", "Rule reference: docs/RULES.md", "Static analysis only. No code was executed; no network access."]
    return "\n".join(out)


class BLENDGUARD_OT_inspect_current(bpy.types.Operator):
    bl_idname = "blendguard.inspect_current"
    bl_label = "Inspect This File"
    bl_description = "Show what would auto-run and any security concerns, without executing anything"

    def execute(self, context):
        run_inspection("manual")
        _popup_in_session("BlendGuard")
        sev = LAST["severity"] or scanner.CLEAN
        self.report({'INFO'} if sev in (scanner.CLEAN, scanner.INFO) else {'WARNING'}, "BlendGuard: %s" % sev)
        return {'FINISHED'}


class BLENDGUARD_OT_scan_file(bpy.types.Operator):
    bl_idname = "blendguard.scan_file"
    bl_label = "Scan a .blend on Disk"
    bl_description = "Quick pre-check of a .blend on disk WITHOUT opening it. Compressed files cannot be fully read; for those, open with Auto-Run off and use Inspect"

    filepath: StringProperty(subtype='FILE_PATH')
    filter_glob: StringProperty(default="*.blend", options={'HIDDEN'})

    def invoke(self, context, event):
        context.window_manager.fileselect_add(self)
        return {'RUNNING_MODAL'}

    def execute(self, context):
        res = scanner.scan_blend_file(self.filepath)
        cons = scanner.concerns({"items": [{"name": os.path.basename(self.filepath),
                                            "findings": res.get("findings", [])}]})
        DISK.update({"name": os.path.basename(self.filepath), "severity": res["severity"],
                     "note": res.get("note", ""), "concerns": cons})
        sev = res["severity"]

        def draw(self, context):
            layout = self.layout
            layout.label(text=DISK["name"], icon='FILE_BLEND')
            if sev == scanner.INCOMPLETE:
                for line in _INCOMPLETE_HELP:
                    layout.label(text=line, icon='NONE')
            elif not cons:
                layout.label(text="No specific security concerns", icon='CHECKMARK')
            else:
                layout.label(text="Security concerns (%d):" % len(cons), icon=_VERDICT_ICON.get(sev, "INFO"))
                _draw_concerns(layout, cons)
        try:
            context.window_manager.popup_menu(draw, title="BlendGuard (disk):  " + sev, icon=_VERDICT_ICON.get(sev, "INFO"))
        except Exception:
            pass
        _redraw()
        self.report({'INFO'} if sev in (scanner.CLEAN, scanner.INFO) else {'WARNING'}, "BlendGuard (disk): %s" % sev)
        return {'FINISHED'}


class BLENDGUARD_OT_disable_autorun(bpy.types.Operator):
    bl_idname = "blendguard.disable_autorun"
    bl_label = "Disable Auto-Run Python Scripts"

    def execute(self, context):
        try:
            context.preferences.filepaths.use_scripts_auto_execute = False
            self.report({'INFO'}, "Auto-Run disabled")
        except Exception as exc:
            self.report({'ERROR'}, str(exc)); return {'CANCELLED'}
        _redraw(); return {'FINISHED'}


class BLENDGUARD_OT_report_to_text(bpy.types.Operator):
    bl_idname = "blendguard.report_to_text"
    bl_label = "Write Full Report to Text"
    bl_description = "Write the complete report (with every explanation) to a Text datablock you can read in the Text Editor"

    def execute(self, context):
        name = "BlendGuard Report"
        try:
            txt = bpy.data.texts.get(name) or bpy.data.texts.new(name)
            txt.clear()
            txt.write(_full_report_text())
        except Exception as exc:
            self.report({'ERROR'}, str(exc)); return {'CANCELLED'}
        self.report({'INFO'}, "Wrote '%s' - open it in the Text Editor" % name)
        return {'FINISHED'}


class VIEW3D_PT_blendguard(bpy.types.Panel):
    bl_label = "BlendGuard"
    bl_idname = "VIEW3D_PT_blendguard"
    bl_space_type = 'VIEW_3D'
    bl_region_type = 'UI'
    bl_category = "BlendGuard"

    def draw(self, context):
        layout = self.layout
        autorun = _autorun_enabled()
        b = layout.box()
        if autorun:
            b.label(text="Auto-Run Python Scripts: ON", icon='ERROR')
            b.operator("blendguard.disable_autorun", icon='CANCEL')
        elif autorun is False:
            b.label(text="Auto-Run Python Scripts: OFF", icon='CHECKMARK')

        col = layout.column(align=True)
        col.operator("blendguard.inspect_current", icon='VIEWZOOM')
        col.operator("blendguard.scan_file", icon='FILE_FOLDER')

        if LAST["severity"] is not None:
            box = layout.box()
            box.label(text="This file: %s" % LAST["severity"], icon=_VERDICT_ICON.get(LAST["severity"], "INFO"))
            box.label(text=_inventory_text(), icon='TEXT')
            if not LAST["concerns"]:
                box.label(text=_clean_summary(), icon='CHECKMARK')
            else:
                _draw_concerns(box, LAST["concerns"])
            box.operator("blendguard.report_to_text", icon='TEXT')

        if DISK["name"]:
            box = layout.box()
            box.label(text="Disk: %s  (%s)" % (DISK["name"], DISK["severity"]), icon=_VERDICT_ICON.get(DISK["severity"], "INFO"))
            if DISK["severity"] == scanner.INCOMPLETE:
                for line in _INCOMPLETE_HELP:
                    box.label(text=line, icon='NONE')
            elif not DISK["concerns"]:
                box.label(text="No specific security concerns", icon='CHECKMARK')
            else:
                _draw_concerns(box, DISK["concerns"])


@persistent
def _on_load_post(_dummy):
    prefs = _prefs()
    if prefs is None or not prefs.inspect_on_open:
        return
    try:
        run_inspection("load")
        sev = LAST["severity"]
        if sev in (scanner.SUSPICIOUS, scanner.DANGEROUS) or (LAST["autorun"] and LAST["concerns"]):
            _popup_in_session("BlendGuard")
        print("[BlendGuard] load: severity=%s concerns=%d autorun=%s" % (sev, len(LAST["concerns"]), LAST["autorun"]))
    except Exception as exc:
        print("[BlendGuard] inspection error (ignored):", exc)


_classes = (
    BlendGuardPrefs,
    BLENDGUARD_OT_inspect_current,
    BLENDGUARD_OT_scan_file,
    BLENDGUARD_OT_disable_autorun,
    BLENDGUARD_OT_report_to_text,
    VIEW3D_PT_blendguard,
)


def register():
    for cls in _classes:
        bpy.utils.register_class(cls)
    if _on_load_post not in bpy.app.handlers.load_post:
        bpy.app.handlers.load_post.append(_on_load_post)


def unregister():
    if _on_load_post in bpy.app.handlers.load_post:
        bpy.app.handlers.load_post.remove(_on_load_post)
    for cls in reversed(_classes):
        try:
            bpy.utils.unregister_class(cls)
        except Exception:
            pass


if __name__ == "__main__":
    register()
