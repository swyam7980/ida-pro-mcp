import os
import sys
import ast
import json
import shutil
import argparse
import http.client
from urllib.parse import urlparse
from glob import glob

# Optional local disassembly using Capstone for nicer fallbacks
try:
    import capstone as _capstone
except Exception:
    _capstone = None

from mcp.server.fastmcp import FastMCP

# The log_level is necessary for Cline to work: https://github.com/jlowin/fastmcp/issues/81
mcp = FastMCP("ida-pro-mcp", log_level="ERROR")

jsonrpc_request_id = 1
ida_host = "127.0.0.1"
ida_port = 13337

def make_jsonrpc_request(method: str, *params):
    """Make a JSON-RPC request to the IDA plugin"""
    global jsonrpc_request_id, ida_host, ida_port
    conn = http.client.HTTPConnection(ida_host, ida_port)
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": list(params),
        "id": jsonrpc_request_id,
    }
    jsonrpc_request_id += 1

    try:
        conn.request("POST", "/mcp", json.dumps(request), {
            "Content-Type": "application/json"
        })
        response = conn.getresponse()
        data = json.loads(response.read().decode())
        # Normalize error handling and provide richer exception types for callers
        if "error" in data:
            error = data["error"]
            code = error.get("code")
            message = error.get("message", "<no message>")
            detail = error.get("data")
            pretty = f"JSON-RPC error {code}: {message}"
            if detail:
                pretty += "\n" + str(detail)
            # Detect some plugin-side internal errors and raise a typed exception
            # Note: func.name AttributeError has been fixed in the plugin file
            if isinstance(detail, str) and "func_t' object has no attribute 'name'" in detail:
                raise PluginInternalError("disassemble_function_bug", pretty)
            # Generic remote error
            raise RemoteJSONRPCError(code, message, detail)

        result = data.get("result")
        # NOTE: LLMs do not respond well to empty responses
        if result is None:
            result = "success"
        return result
    except Exception:
        # Re-raise so callers can catch typed exceptions introduced above
        raise
    finally:
        conn.close()


class RemoteJSONRPCError(Exception):
    """Generic JSON-RPC error returned by the IDA plugin."""
    def __init__(self, code, message, data=None):
        super().__init__(f"JSON-RPC error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class PluginInternalError(Exception):
    """Specific marker for plugin internal errors that need special handling."""
    def __init__(self, kind: str, message: str = ""):
        super().__init__(message)
        self.kind = kind


def disassemble_with_fallback(ea: str):
    """Try to disassemble using the plugin; on known plugin bug, fall back to a bytes-based disassembly.

    Returns plugin result or a dict {"fallback": True, "asm": "..."} when fallback used.
    """
    try:
        return make_jsonrpc_request("disassemble_function", ea)
    except PluginInternalError as pie:
        # Known disassemble plugin bug. Try to gather function bounds and raw bytes and return them.
        try:
            func = make_jsonrpc_request("get_function_by_address", ea)
            # func is expected to contain 'address' and 'size'
            size = func.get("size")
            # size may be hex string — try to coerce
            if isinstance(size, str):
                try:
                    size_int = int(size, 0)
                except Exception:
                    size_int = None
            else:
                size_int = int(size) if size is not None else None

            if not size_int:
                raise

            # The MCP plugin exposes a read_memory_bytes helper; use it when get_bytes isn't available
            try:
                bytes_blob = make_jsonrpc_request("read_memory_bytes", ea, size_int)
            except Exception:
                # fall back to the older/get_bytes name if present elsewhere
                bytes_blob = make_jsonrpc_request("get_bytes", ea, size_int)

            # If capstone is available, attempt to disassemble locally for a nicer fallback
            asm_text = None
            try:
                raw = None
                # bytes_blob might already be a hex string or list of ints
                if isinstance(bytes_blob, str):
                    s = bytes_blob.strip()
                    # common format: "0x55 0x8b 0xec ..." (space-separated 0xNN)
                    if s.startswith("0x") or " 0x" in s or ",0x" in s:
                        parts = [p.strip().lstrip("0x") for p in s.replace(',', ' ').split() if p.strip()]
                        # Normalize tokens to two hex digits (pad single-digit nibbles)
                        norm = []
                        for p in parts:
                            tok = p.strip()
                            if len(tok) == 0:
                                continue
                            # remove any stray non-hex chars
                            tok = ''.join([c for c in tok if c in '0123456789abcdefABCDEF'])
                            if len(tok) == 0:
                                continue
                            if len(tok) % 2 == 1:
                                tok = tok.zfill(2)
                            norm.append(tok)
                        try:
                            raw = bytes.fromhex(''.join(norm))
                        except Exception:
                            raw = None
                    else:
                        # maybe a plain hex string without 0x and possibly spaces
                        compact = ''.join([c for c in s if c in '0123456789abcdefABCDEF'])
                        try:
                            if len(compact) % 2 == 1:
                                compact = '0' + compact
                            raw = bytes.fromhex(compact)
                        except Exception:
                            raw = None
                elif isinstance(bytes_blob, list):
                    raw = bytes(bytes_blob)
                elif isinstance(bytes_blob, (bytes, bytearray)):
                    raw = bytes(bytes_blob)

                if raw is not None and _capstone is not None:
                    # Attempt to autodetect architecture from bytes heuristics
                    arch = _capstone.CS_ARCH_X86
                    # Heuristic: common 32-bit prologue is 0x55 0x8b 0xec
                    mode = _capstone.CS_MODE_64
                    try:
                        if len(raw) >= 3 and raw[0] == 0x55 and raw[1] == 0x8b and raw[2] == 0xec:
                            mode = _capstone.CS_MODE_32
                    except Exception:
                        mode = _capstone.CS_MODE_64
                    cs = _capstone.Cs(arch, mode)
                    cs.detail = False
                    lines = []
                    for i in cs.disasm(raw, int(func.get("address", "0"), 0)):
                        lines.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
                    asm_text = "\n".join(lines)
            except Exception:
                asm_text = None

            result = {"fallback": True, "func": func, "bytes": bytes_blob}
            if asm_text:
                result["asm"] = asm_text
            return result
        except Exception as e:
            raise


def rename_local_variable_with_promote(function_address: str, old_name: str, new_name: str):
    """Attempt to rename a local variable, with fallbacks if IDA refuses a direct rename.

    Strategy:
      1. Try simple rename_local_variable.
      2. If that fails, inspect stack frame variables. If the target is a struct/array member, attempt to set the stack frame variable type/name.
      3. If all else fails, set a function comment recording the desired name.
    """
    try:
        return make_jsonrpc_request("rename_local_variable", function_address, old_name, new_name)
    except Exception:
        # gather frame variables and attempt a safer edit
        try:
            vars_list = make_jsonrpc_request("get_stack_frame_variables", function_address)
            # vars_list could be a dict or list of entries; try to find matching old_name
            found = None
            if isinstance(vars_list, dict):
                # some endpoints return streaming dicts; normalize
                for k, v in vars_list.items():
                    if isinstance(v, dict) and v.get("name") == old_name:
                        found = v
                        break
            elif isinstance(vars_list, list):
                for v in vars_list:
                    if v.get("name") == old_name:
                        found = v
                        break

            if found:
                # Try a non-invasive type update if API available
                try:
                    # Prefer set_local_variable_type if exposed
                    return make_jsonrpc_request("set_local_variable_type", function_address, old_name, new_name)
                except Exception:
                    # As a last resort, write a comment on the function documenting the intended name
                    comment = f"renamed_local:{old_name}->{new_name}"
                    try:
                        make_jsonrpc_request("set_comment", function_address, comment)
                        return {"commented": True}
                    except Exception:
                        raise
            else:
                # Not found: write a general function comment
                comment = f"desired_local_rename:{old_name}->{new_name}"
                make_jsonrpc_request("set_comment", function_address, comment)
                return {"commented": True}
        except Exception:
            raise


def repro_disassemble_error(ea: str, outpath: str = None):
    """Attempt to reproduce disassemble failure and collect diagnostics: function bounds, platform info, and traceback.

    If outpath is provided, write a JSON dump to that file.
    """
    import traceback
    diag = {"ea": ea, "sys_version": sys.version, "platform": sys.platform}
    try:
        make_jsonrpc_request("disassemble_function", ea)
        diag["status"] = "success"
    except Exception as e:
        diag["status"] = "failed"
        diag["error"] = str(e)
        diag["traceback"] = traceback.format_exc()
        try:
            func = make_jsonrpc_request("get_function_by_address", ea)
            diag["function"] = func
        except Exception:
            diag["function"] = None

    if outpath:
        try:
            with open(outpath, "w", encoding="utf-8") as f:
                json.dump(diag, f, indent=2)
        except Exception:
            pass
    return diag

@mcp.tool()
def check_connection() -> str:
    """Check if the IDA plugin is running"""
    try:
        metadata = make_jsonrpc_request("get_metadata")
        return f"Successfully connected to IDA Pro (open file: {metadata['module']})"
    except Exception as e:
        if sys.platform == "darwin":
            shortcut = "Ctrl+Option+M"
        else:
            shortcut = "Ctrl+Alt+M"
        return f"Failed to connect to IDA Pro! Did you run Edit -> Plugins -> MCP ({shortcut}) to start the server?"

# Code taken from https://github.com/mrexodia/ida-pro-mcp (MIT License)
class MCPVisitor(ast.NodeVisitor):
    def __init__(self):
        self.types: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.descriptions: dict[str, str] = {}
        self.unsafe: list[str] = []

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == "jsonrpc":
                    for i, arg in enumerate(node.args.args):
                        arg_name = arg.arg
                        arg_type = arg.annotation
                        if arg_type is None:
                            raise Exception(f"Missing argument type for {node.name}.{arg_name}")
                        if isinstance(arg_type, ast.Subscript):
                            assert isinstance(arg_type.value, ast.Name)
                            assert arg_type.value.id == "Annotated"
                            assert isinstance(arg_type.slice, ast.Tuple)
                            assert len(arg_type.slice.elts) == 2
                            annot_type = arg_type.slice.elts[0]
                            annot_description = arg_type.slice.elts[1]
                            assert isinstance(annot_description, ast.Constant)
                            node.args.args[i].annotation = ast.Subscript(
                                value=ast.Name(id="Annotated", ctx=ast.Load()),
                                slice=ast.Tuple(
                                    elts=[
                                    annot_type,
                                    ast.Call(
                                        func=ast.Name(id="Field", ctx=ast.Load()),
                                        args=[],
                                        keywords=[
                                        ast.keyword(
                                            arg="description",
                                            value=annot_description)])],
                                    ctx=ast.Load()),
                                ctx=ast.Load())
                        elif isinstance(arg_type, ast.Name):
                            pass
                        else:
                            raise Exception(f"Unexpected type annotation for {node.name}.{arg_name} -> {type(arg_type)}")

                    body_comment = node.body[0]
                    if isinstance(body_comment, ast.Expr) and isinstance(body_comment.value, ast.Constant):
                        new_body = [body_comment]
                        self.descriptions[node.name] = body_comment.value.value
                    else:
                        new_body = []

                    call_args = [ast.Constant(value=node.name)]
                    for arg in node.args.args:
                        call_args.append(ast.Name(id=arg.arg, ctx=ast.Load()))
                    new_body.append(ast.Return(
                        value=ast.Call(
                            func=ast.Name(id="make_jsonrpc_request", ctx=ast.Load()),
                            args=call_args,
                            keywords=[])))
                    decorator_list = [
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id="mcp", ctx=ast.Load()),
                                attr="tool",
                                ctx=ast.Load()),
                            args=[],
                            keywords=[]
                        )
                    ]
                    node_nobody = ast.FunctionDef(node.name, node.args, new_body, decorator_list, node.returns, node.type_comment, lineno=node.lineno, col_offset=node.col_offset)
                    assert node.name not in self.functions, f"Duplicate function: {node.name}"
                    self.functions[node.name] = node_nobody
                elif decorator.id == "unsafe":
                    self.unsafe.append(node.name)

    def visit_ClassDef(self, node):
        for base in node.bases:
            if isinstance(base, ast.Name):
                if base.id == "TypedDict":
                    self.types[node.name] = node


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PY = os.path.join(SCRIPT_DIR, "mcp-plugin.py")
GENERATED_PY = os.path.join(SCRIPT_DIR, "server_generated.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PY):
    raise RuntimeError(f"IDA plugin not found at {IDA_PLUGIN_PY} (did you move it?)")
with open(IDA_PLUGIN_PY, "r", encoding="utf-8") as f:
    code = f.read()
module = ast.parse(code, IDA_PLUGIN_PY)
visitor = MCPVisitor()
visitor.visit(module)
code = """# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
import sys
if sys.version_info >= (3, 12):
    from typing import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
else:
    from typing_extensions import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
from pydantic import Field

T = TypeVar("T")

"""
for type in visitor.types.values():
    code += ast.unparse(type)
    code += "\n\n"
for function in visitor.functions.values():
    code += ast.unparse(function)
    code += "\n\n"

try:
    if os.path.exists(GENERATED_PY):
        with open(GENERATED_PY, "rb") as f:
            existing_code_bytes = f.read()
    else:
        existing_code_bytes = b""
    code_bytes = code.encode("utf-8").replace(b"\r", b"")
    if code_bytes != existing_code_bytes:
        with open(GENERATED_PY, "wb") as f:
            f.write(code_bytes)
except:
    print(f"Failed to generate code: {GENERATED_PY}", file=sys.stderr, flush=True)

exec(compile(code, GENERATED_PY, "exec"))

MCP_FUNCTIONS = ["check_connection"] + list(visitor.functions.keys())
UNSAFE_FUNCTIONS = visitor.unsafe
SAFE_FUNCTIONS = [f for f in MCP_FUNCTIONS if f not in UNSAFE_FUNCTIONS]

def generate_readme():
    print("README:")
    print(f"- `check_connection()`: Check if the IDA plugin is running.")
    def get_description(name: str):
        function = visitor.functions[name]
        signature = function.name + "("
        for i, arg in enumerate(function.args.args):
            if i > 0:
                signature += ", "
            signature += arg.arg
        signature += ")"
        description = visitor.descriptions.get(function.name, "<no description>").strip()
        if description[-1] != ".":
            description += "."
        return f"- `{signature}`: {description}"
    for safe_function in SAFE_FUNCTIONS:
        print(get_description(safe_function))
    print("\nUnsafe functions (`--unsafe` flag required):\n")
    for unsafe_function in UNSAFE_FUNCTIONS:
        print(get_description(unsafe_function))
    print("\nMCP Config:")
    mcp_config = {
        "mcpServers": {
            "github.com/mrexodia/ida-pro-mcp": {
            "command": "uv",
            "args": [
                "--directory",
                "c:\\MCP\\ida-pro-mcp",
                "run",
                "server.py",
                "--install-plugin"
            ],
            "timeout": 1800,
            "disabled": False,
            }
        }
    }
    print(json.dumps(mcp_config, indent=2))

def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable

def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result

def print_mcp_config():
    mcp_config = {
        "command": get_python_executable(),
        "args": [
            __file__,
        ],
        "timeout": 1800,
        "disabled": False,
    }
    env = {}
    if copy_python_env(env):
        print(f"[WARNING] Custom Python environment variables detected")
        mcp_config["env"] = env
    print(json.dumps({
            "mcpServers": {
                mcp.name: mcp_config
            }
        }, indent=2)
    )

def install_mcp_servers(*, uninstall=False, quiet=False, env={}):
    if sys.platform == "win32":
        configs = {
            "Cline": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.getenv("APPDATA"), "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.getenv("APPDATA"), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(config_path, "r", encoding="utf-8") as f:
                data = f.read().strip()
                if len(data) == 0:
                    config = {}
                else:
                    try:
                        config = json.loads(data)
                    except json.decoder.JSONDecodeError:
                        if not quiet:
                            print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                        continue
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        mcp_servers = config["mcpServers"]
        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]
        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[mcp.name]
        else:
            # Copy environment variables from the existing server if present
            if mcp.name in mcp_servers:
                for key, value in mcp_servers[mcp.name].get("env", {}):
                    env[key] = value
            if copy_python_env(env):
                print(f"[WARNING] Custom Python environment variables detected")
            mcp_servers[mcp.name] = {
                "command": get_python_executable(),
                "args": [
                    __file__,
                ],
                "timeout": 1800,
                "disabled": False,
                "autoApprove": SAFE_FUNCTIONS,
                "alwaysAllow": SAFE_FUNCTIONS,
            }
            if env:
                mcp_servers[mcp.name]["env"] = env
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(f"{action} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1
    if not uninstall and installed == 0:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config()

def install_ida_plugin(*, uninstall: bool = False, quiet: bool = False):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    free_licenses = glob(os.path.join(ida_folder, "idafree_*.hexlic"))
    if len(free_licenses) > 0:
        print(f"IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead.")
        sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    plugin_destination = os.path.join(ida_plugin_folder, "mcp-plugin.py")
    if uninstall:
        if not os.path.exists(plugin_destination):
            print(f"Skipping IDA plugin uninstall\n  Path: {plugin_destination} (not found)")
            return
        os.remove(plugin_destination)
        if not quiet:
            print(f"Uninstalled IDA plugin\n  Path: {plugin_destination}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Skip if symlink already up to date
        realpath = os.path.realpath(plugin_destination)
        if realpath == IDA_PLUGIN_PY:
            if not quiet:
                print(f"Skipping IDA plugin installation (symlink up to date)\n  Plugin: {realpath}")
        else:
            # Remove existing plugin
            if os.path.lexists(plugin_destination):
                os.remove(plugin_destination)

            # Symlink or copy the plugin
            try:
                os.symlink(IDA_PLUGIN_PY, plugin_destination)
            except OSError:
                shutil.copy(IDA_PLUGIN_PY, plugin_destination)

            if not quiet:
                print(f"Installed IDA Pro plugin (IDA restart required)\n  Plugin: {plugin_destination}")

def main():
    global ida_host, ida_port
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install the MCP Server and IDA plugin")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the MCP Server and IDA plugin")
    parser.add_argument("--generate-docs", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--install-plugin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    parser.add_argument("--ida-rpc", type=str, default=f"http://{ida_host}:{ida_port}", help=f"IDA RPC server to use (default: http://{ida_host}:{ida_port})")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("--config", action="store_true", help="Generate MCP config JSON")
    args = parser.parse_args()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin()
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True)
        install_mcp_servers(uninstall=True)
        return

    # NOTE: Developers can use this to generate the README
    if args.generate_docs:
        generate_readme()
        return

    # NOTE: This is silent for automated Cline installations
    if args.install_plugin:
        install_ida_plugin(quiet=True)

    if args.config:
        print_mcp_config()
        return

    # Parse IDA RPC server argument
    ida_rpc = urlparse(args.ida_rpc)
    if ida_rpc.hostname is None or ida_rpc.port is None:
        raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
    ida_host = ida_rpc.hostname
    ida_port = ida_rpc.port

    # Remove unsafe tools
    if not args.unsafe:
        mcp_tools = mcp._tool_manager._tools
        for unsafe in UNSAFE_FUNCTIONS:
            if unsafe in mcp_tools:
                del mcp_tools[unsafe]

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            print(f"MCP Server availabile at http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
