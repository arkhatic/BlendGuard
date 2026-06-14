# SPDX-License-Identifier: GPL-3.0-or-later
# BlendGuard - transparency before trust for .blend files (inspection-only).
#
# Shows what a .blend would auto-run (text scripts, Python drivers, OSL script
# nodes, handlers) without executing it, and scores the risk. Static analysis
# only, no network access. Detection logic lives in scanner.py.

import os
import bpy
from bpy.app.handlers import persistent
from bpy.props import StringProperty, BoolProperty

from . import scanner

LAST = {"severity": None, "count": 0, "items": [], "autorun": None}

_ICON = {
    scanner.CLEAN: "CHECKMARK", scanner.INFO: "INFO",
    scanner.SUSPICIOUS: "ERROR", scanner.DANGEROUS: "CANCEL",
    scanner.INCOMPLETE: "QUESTION",
}


class BlendGuardPrefs(bpy.types.AddonPreferences):
    bl_idname = __package__

    auto_inspect: BoolProperty(name="Inspect files automatically on open", default=True)
    warn_autorun: BoolProperty(name="Warn when Auto-Run Python Scripts is enabled", default=True)

    def draw(self, context):
        col = self.layout.column()
        col.prop(self, "auto_inspect")
        col.prop(self, "warn_autorun")
        col.separator()
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
    data = bpy.data
    for cname in _DRIVER_COLLECTIONS:
        coll = getattr(data, cname, None)
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
    data = bpy.data
    for cname in _NODE_COLLECTIONS:
        coll = getattr(data, cname, None)
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
    result = scanner.scan_items(_collect_items())
    flagged = [it for it in result["items"] if it["severity"] != scanner.CLEAN]
    LAST.update({"severity": result["severity"], "count": len(flagged),
                 "items": flagged[:25], "autorun": _autorun_enabled()})
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


def _popup(title, severity, lines):
    def draw(self, context):
        for text, icon in lines:
            self.layout.label(text=text, icon=icon)
    try:
        bpy.context.window_manager.popup_menu(draw, title=title, icon=_ICON.get(severity, "INFO"))
    except Exception:
        pass


class BLENDGUARD_OT_inspect_current(bpy.types.Operator):
    bl_idname = "blendguard.inspect_current"
    bl_label = "Inspect This File"
    bl_description = "List embedded scripts, drivers, OSL nodes and handlers without executing them"

    def execute(self, context):
        run_inspection("manual")
        sev = LAST["severity"] or scanner.CLEAN
        lines = [("Auto-Run is %s" % ("ON" if LAST["autorun"] else "OFF"),
                  "ERROR" if LAST["autorun"] else "CHECKMARK"),
                 ("%d flagged item(s) - %s" % (LAST["count"], sev), _ICON.get(sev, "INFO"))]
        _popup("BlendGuard", sev, lines)
        self.report({'INFO'} if sev in (scanner.CLEAN, scanner.INFO) else {'WARNING'}, "BlendGuard: %s" % sev)
        return {'FINISHED'}


class BLENDGUARD_OT_scan_file(bpy.types.Operator):
    bl_idname = "blendguard.scan_file"
    bl_label = "Scan a .blend on Disk"
    bl_description = "Triage a .blend on disk for embedded scripts WITHOUT opening it"

    filepath: StringProperty(subtype='FILE_PATH')
    filter_glob: StringProperty(default="*.blend", options={'HIDDEN'})

    def invoke(self, context, event):
        context.window_manager.fileselect_add(self)
        return {'RUNNING_MODAL'}

    def execute(self, context):
        res = scanner.scan_blend_file(self.filepath)
        sev = res["severity"]
        lines = [(os.path.basename(self.filepath), "FILE")]
        if res.get("note"):
            lines.append((res["note"][:90], "INFO"))
        for f in res.get("findings", [])[:6]:
            lines.append((f["desc"], "DOT"))
        _popup("BlendGuard (disk)", sev, lines)
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

        sev = LAST["severity"]
        if sev is not None:
            r = layout.box()
            r.label(text="Last result: %s" % sev, icon=_ICON.get(sev, "INFO"))
            if LAST["count"]:
                r.label(text="%d flagged item(s)" % LAST["count"])
                for it in LAST["items"][:8]:
                    r.label(text="%s [%s]" % (it["name"], it["severity"]), icon='DOT')


@persistent
def _on_load_post(_dummy):
    prefs = _prefs()
    if prefs is not None and not prefs.auto_inspect:
        return
    try:
        result = run_inspection("load")
        sev = result["severity"]
        autorun = LAST["autorun"]
        warn = (prefs is None) or prefs.warn_autorun
        if sev in (scanner.SUSPICIOUS, scanner.DANGEROUS) or (autorun and warn and sev != scanner.CLEAN):
            _popup("BlendGuard", sev, [("%d flagged item(s) - %s" % (LAST["count"], sev), _ICON.get(sev, "INFO"))])
        print("[BlendGuard] load: severity=%s flagged=%d autorun=%s" % (sev, LAST["count"], autorun))
    except Exception as exc:
        print("[BlendGuard] inspection error (ignored):", exc)


_classes = (
    BlendGuardPrefs,
    BLENDGUARD_OT_inspect_current,
    BLENDGUARD_OT_scan_file,
    BLENDGUARD_OT_disable_autorun,
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
