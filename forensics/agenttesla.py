#!/usr/bin/env python3
"""
Agent Tesla / GuLoader-style loader decoder (static, nothing is executed).

    Stage 1 - JScript dropper (.js inside .rar/.zip):
              rebuilds the embedded PowerShell (string accumulator + junk-word
              replacements), decodes the char-skip strings (WMI / cmd / powershell
              path) and reports how the PowerShell is launched.
    Stage 2 - PowerShell loader:
              finds the key array, decodes int-array strings (subtraction) and
              hex/base64 strings (XOR), removes junk calls, resolves variables
              and extracts IOCs (URL, registry, User-Agent, stage 3 substring).
    Stage 3 - optional: cuts stage 3 out of the downloaded blob / registry value.

Usage:
    python agenttesla.py sample.rar                    # stage 1 + stage 2
    python agenttesla.py sample.rar --stage 1          # only JS -> PowerShell
    python agenttesla.py stage2.ps1 --stage 2          # only PowerShell
    python agenttesla.py sample.rar --blob Minuting.mix   # + stage 3
"""
import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import time
import zipfile


#######################################################################
# COMMON
#######################################################################

SCRIPT_EXTENSIONS = (".js", ".jse", ".wsf", ".vbs", ".vbe", ".hta", ".ps1", ".txt")


class Timer:
	def __init__(self, message: str = ""):
		self.start_time = None
		self.message = message

	def __enter__(self):
		self.start_time = time.time()

	def __exit__(self, *args, **kwargs):
		print(f"[+] Finished {self.message} in total {round(time.time() - self.start_time, 4)}s")


def info(message: str) -> None:
	print(f"[+] {message}")


def warn(message: str) -> None:
	print(f"[-] {message}")


def read_text(path: str) -> str:
	with open(path, "rb") as in_file:
		data = in_file.read()
	for encoding in ("utf-8-sig", "utf-16"):
		try:
			text = data.decode(encoding)
			if "\x00" not in text:
				return text
		except UnicodeDecodeError:
			continue
	return data.decode("latin-1")


def write_text(path: str, text: str) -> str:
	with open(path, "w", encoding="utf-8", newline="\n") as out_file:
		out_file.write(text)
	return path


def printable_ratio(text: str) -> float:
	if not text:
		return 0.0
	return sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t") / len(text)


def ps_literal(text: str) -> str:
	return "'" + text.replace("'", "''") + "'"


def prettify_ps(code: str) -> str:
	"""One statement / brace per line (same idea as the original prettyfy_code)."""
	return "\n}".join("{\n".join(";\n".join(code.split(";")).split("{")).split("}"))


def unpack_archive(path: str, out_dir: str, password: str = None) -> list:
	"""Extracts .rar / .zip without executing anything and returns script files."""
	with open(path, "rb") as in_file:
		magic = in_file.read(8)
	if not magic.startswith((b"PK", b"Rar!")):
		return [path]

	target = os.path.join(out_dir, os.path.basename(path) + "_extracted")
	os.makedirs(target, exist_ok=True)

	if magic.startswith(b"PK"):
		with zipfile.ZipFile(path) as archive:
			archive.extractall(target, pwd=password.encode() if password else None)
	elif magic.startswith(b"Rar!"):
		commands = [
			["unar", "-q", "-f", "-o", target] + (["-p", password] if password else []) + [path],
			["7z", "x", "-y", f"-o{target}", f"-p{password or ''}", path],
			["unrar", "x", "-o+", f"-p{password or '-'}", path, target + os.sep],
			["bsdtar", "-xf", path, "-C", target],
		]
		for command in commands:
			if shutil.which(command[0]) is None:
				continue
			if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
				break
		else:
			raise RuntimeError("No working RAR extractor found (install unar, 7z, unrar or bsdtar)")

	files = []
	for root, _, names in os.walk(target):
		for name in names:
			files.append(os.path.join(root, name))
	scripts = [f for f in files if f.lower().endswith(SCRIPT_EXTENSIONS)] or files
	info(f"Extracted {len(files)} file(s) from {os.path.basename(path)}: {', '.join(os.path.basename(f) for f in scripts)}")
	return scripts


def detect_type(code: str) -> str:
	js_score = len(re.findall(r"\bvar\s+\w+\s*=|WScript\.|ActiveXObject|GetObject\(", code))
	ps_score = len(re.findall(r"\$\w+\s*=|\bfunction\s+\w+\s*\(\$|\[Convert\]::|\bparam\(", code, re.I))
	return "js" if js_score > ps_score else "ps"


SUSPICIOUS_KEYWORDS = (
	"Invoke-Expression", "IEX", "DownloadString", "DownloadFile", "DownloadData", "Invoke-WebRequest",
	"Invoke-RestMethod", "Start-BitsTransfer", "Net.WebClient", "ServerXMLHTTP", "FromBase64String",
	"Reflection.Assembly", "::Load(", "VirtualAlloc", "GetDelegateForFunctionPointer", "CallWindowProc",
	"Add-MpPreference", "Set-MpPreference", "schtasks", "Register-ScheduledTask", "CurrentVersion\\Run",
	"Start-Process", "-WindowStyle Hidden", "Set-ItemProperty", "New-ItemProperty",
)


def extract_iocs_from_text(texts: list, depth: int = 0) -> dict:
	"""Generic IOC extraction from plain (already decoded) script text."""
	blob = "\n".join(str(t) for t in texts if t)
	urls = sorted({u.rstrip(".,;)'\"") for u in re.findall(r"(?i)\b(?:https?|ftp)://[^\s'\"<>|`)]+", blob)})
	domains = sorted({h for h in (re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0] for u in urls)
					  if not re.fullmatch(r"[\d.]+", h)})
	ips = sorted({ip for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob)
				  if all(int(o) < 256 for o in ip.split(".")) and not ip.startswith(("0.", "127.", "255."))})
	iocs = {
		"urls": urls,
		"domains": domains,
		"ips": ips,
		"registry": sorted(set(re.findall(r"(?i)\b(?:HKCU|HKLM|HKCR|HKU|HKEY_[A-Z_]+)(?::)?\\[^'\"\s|;<>]+", blob))),
		"file_paths": sorted(set(re.findall(r"(?i)(?:\b[a-z]:\\|%\w+%\\|\$env:\w+\\)[^'\"\s|;<>]+", blob))),
		"user_agent": sorted(set(re.findall(r"['\"]([^'\"\n]*(?:Mozilla/|Windows NT \d)[^'\"\n]*)['\"]", blob))),
		"com_objects": sorted(set(re.findall(r"(?i)(?:-Com(?:Object)?\s+['\"]?|ActiveXObject\(\s*['\"])([A-Za-z][\w]*\.[\w.]+)", blob))),
		"suspicious": [k for k in SUSPICIOUS_KEYWORDS if re.search(rf"(?<![\w-]){re.escape(k)}(?![\w-])", blob, re.I)],
	}
	substring = re.search(r"\.substring\(\s*(\d+)\s*,\s*(\d+)\s*\)", blob, re.I)
	if substring:
		iocs["stage3_substring"] = [int(substring.group(1)), int(substring.group(2))]

	# powershell -EncodedCommand <base64 UTF-16LE>
	decoded = []
	for data in re.findall(r"(?i)\s-e(?:nc(?:odedcommand)?)?\s+['\"]?([A-Za-z0-9+/]{20,}={0,2})", blob):
		try:
			command = base64.b64decode(data).decode("utf-16-le")
			if printable_ratio(command) > 0.9 and command not in decoded:
				decoded.append(command)
		except Exception:
			continue
	if decoded and depth < 3:
		iocs["encoded_commands"] = decoded
		for name, values in extract_iocs_from_text(decoded, depth + 1).items():
			if isinstance(values, list) and name in iocs and isinstance(iocs[name], list):
				iocs[name] = sorted(set(iocs[name]) | set(map(str, values)))
	return {k: v for k, v in iocs.items() if v}


def print_iocs(title: str, iocs: dict) -> None:
	info(f"{title}:")
	for name, value in iocs.items():
		if isinstance(value, list) and name in ("encoded_commands",):
			for item in value:
				print(f"\t{name}: {item if len(item) < 200 else item[:200] + '...'}")
		else:
			print(f"\t{name}: {', '.join(map(str, value)) if isinstance(value, list) else value}")


#######################################################################
# STAGE 1 - JScript dropper
#######################################################################

class JsEvaluator:
	"""
	Very small, side-effect free evaluator for the statements the dropper uses:
	string/number literals, +, variables, arrays, .substr/.substring/.slice,
	.replace(/x/g, y) and calls to the dropper's own decoder functions.
	Control flow is ignored - statements are evaluated in file order.
	"""

	TOKEN = re.compile(r"""
		\s*(?:
			(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
			|(?P<regex>(?<![\w)\]])/(?:[^/\\\n]|\\.)+/[gimsuy]*)
			|(?P<num>0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)
			|(?P<name>[A-Za-z_$][\w$]*)
			|(?P<op>\+=|==|!=|<=|>=|&&|\|\||[-+*/%(),.\[\]=;<>!?:{}^|&~])
		)""", re.X | re.S)

	def __init__(self, functions: dict):
		self.vars = {}
		self.functions = functions	# name -> python callable(evaluator, args)

	@staticmethod
	def unescape(literal: str) -> str:
		body = literal[1:-1]
		return re.sub(r"\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)", lambda m: {
			"n": "\n", "r": "\r", "t": "\t", "0": "\0", "b": "\b", "f": "\f", "v": "\v",
		}.get(m.group(1), chr(int(m.group(1)[1:], 16)) if m.group(1)[0] in "xu" and len(m.group(1)) > 1 else m.group(1)), body, flags=re.S)

	def tokenize(self, text: str) -> list:
		tokens, pos = [], 0
		while pos < len(text):
			match = self.TOKEN.match(text, pos)
			if not match or match.end() == pos:
				if text[pos:].strip() == "":
					break
				raise ValueError(f"cannot tokenize near {text[pos:pos + 20]!r}")
			kind = match.lastgroup
			tokens.append((kind, match.group(kind)))
			pos = match.end()
		return tokens

	# --- recursive descent -------------------------------------------------
	def parse_expression(self, tokens: list, i: int):
		value, i = self.parse_term(tokens, i)
		while i < len(tokens) and tokens[i][0] == "op" and tokens[i][1] in ("+", "-"):
			op = tokens[i][1]
			right, i = self.parse_term(tokens, i + 1)
			if op == "+":
				if isinstance(value, (int, float)) and isinstance(right, (int, float)):
					value = value + right
				else:
					value = self.to_str(value) + self.to_str(right)
			else:
				if not isinstance(value, (int, float)) or not isinstance(right, (int, float)):
					raise ValueError("non numeric arithmetic")
				value = value - right
		return value, i

	def parse_term(self, tokens: list, i: int):
		value, i = self.parse_unary(tokens, i)
		while i < len(tokens) and tokens[i][0] == "op" and tokens[i][1] in ("*", "/", "%"):
			op = tokens[i][1]
			right, i = self.parse_unary(tokens, i + 1)
			if not isinstance(value, (int, float)) or not isinstance(right, (int, float)):
				raise ValueError("non numeric arithmetic")
			value = {"*": lambda: value * right, "/": lambda: value / right if right else 0, "%": lambda: value % right if right else 0}[op]()
		return value, i

	def parse_unary(self, tokens: list, i: int):
		if i < len(tokens) and tokens[i] == ("op", "-"):
			value, i = self.parse_unary(tokens, i + 1)
			return -value, i
		return self.parse_postfix(tokens, i)

	def parse_postfix(self, tokens: list, i: int):
		value, i = self.parse_primary(tokens, i)
		while i < len(tokens) and tokens[i] == ("op", "."):
			method = tokens[i + 1][1]
			i += 2
			args = []
			if i < len(tokens) and tokens[i] == ("op", "("):
				args, i = self.parse_args(tokens, i)
			value = self.call_method(value, method, args)
		return value, i

	def parse_args(self, tokens: list, i: int):
		args, i = [], i + 1
		while tokens[i] != ("op", ")"):
			arg, i = self.parse_expression(tokens, i)
			args.append(arg)
			if tokens[i] == ("op", ","):
				i += 1
		return args, i + 1

	def parse_primary(self, tokens: list, i: int):
		kind, value = tokens[i]
		if kind == "str":
			return self.unescape(value), i + 1
		if kind == "num":
			return (int(value, 16) if value.lower().startswith("0x") else (float(value) if "." in value else int(value))), i + 1
		if kind == "regex":
			body, flags = value[1:].rsplit("/", 1)
			return ("__regex__", body, flags), i + 1
		if kind == "op" and value == "(":
			result, i = self.parse_expression(tokens, i + 1)
			return result, i + 1
		if kind == "op" and value == "[":
			items, i = [], i + 1
			while tokens[i] != ("op", "]"):
				item, i = self.parse_expression(tokens, i)
				items.append(item)
				if tokens[i] == ("op", ","):
					i += 1
			return items, i + 1
		if kind == "name":
			if i + 1 < len(tokens) and tokens[i + 1] == ("op", "("):
				args, j = self.parse_args(tokens, i + 1)
				if value in self.functions:
					return self.functions[value](self, args), j
				raise ValueError(f"unknown function {value}")
			if value in self.vars:
				return self.vars[value], i + 1
			raise ValueError(f"unknown variable {value}")
		raise ValueError(f"unexpected token {value!r}")

	@staticmethod
	def to_str(value) -> str:
		if isinstance(value, list):
			return ",".join(JsEvaluator.to_str(v) for v in value)
		if isinstance(value, float) and value.is_integer():
			return str(int(value))
		return str(value)

	def call_method(self, value, method: str, args: list):
		if isinstance(value, str):
			if method == "substr":
				start = int(args[0]) if args else 0
				return value[start:start + int(args[1])] if len(args) > 1 else value[start:]
			if method in ("substring", "slice"):
				return value[int(args[0]):int(args[1])] if len(args) > 1 else value[int(args[0]):]
			if method == "replace" and len(args) == 2:
				pattern = args[0]
				if isinstance(pattern, tuple):
					return re.sub(pattern[1], args[1].replace("$&", r"\g<0>"), value, count=0 if "g" in pattern[2] else 1)
				return value.replace(pattern, args[1], 1)
			if method == "split" and args:
				return value.split(args[0])
			if method in ("toLowerCase", "toUpperCase"):
				return value.lower() if method == "toLowerCase" else value.upper()
		if isinstance(value, list) and method == "join":
			return (args[0] if args else ",").join(self.to_str(v) for v in value)
		raise ValueError(f"unsupported method {method}")

	def execute(self, statement: str):
		"""Evaluates `[var] NAME (=|+=) EXPR`. Returns (name, value) or None."""
		match = re.match(r"^\s*(?:var\s+)?([A-Za-z_$][\w$]*)\s*(\+?=)(?!=)\s*(.+?)\s*;?\s*$", statement, re.S)
		if not match:
			return None
		name, operator, expression = match.groups()
		tokens = self.tokenize(expression)
		value, consumed = self.parse_expression(tokens, 0)
		if consumed != len(tokens):
			raise ValueError("trailing tokens")
		if operator == "+=":
			value = self.to_str(self.vars.get(name, "")) + self.to_str(value)
		self.vars[name] = value
		return name, value


class Stage1Dropper:
	"""JScript dropper -> embedded PowerShell + launch chain."""

	SINK_PATTERNS = {
		"GetObject": r"\bGetObject\(",
		"ActiveXObject": r"new\s+ActiveXObject\(",
		"WMI Get": r"\.Get\(",
		"Create": r"\.Create\(",
		"Run / Exec": r"\.(?:Run|Exec|ShellExecute)\(",
		"EnvironmentVariables": r"\.EnvironmentVariables\s*=\s*",
	}

	def __init__(self, path: str, out_dir: str):
		self.path = path
		self.out_dir = out_dir
		self.code = read_text(path)
		self.functions = {}
		self.notes = []
		self.decoded = []	# every value returned by the dropper's decoder functions

	# --- preprocessing -----------------------------------------------------
	@staticmethod
	def strip_comments(code: str) -> str:
		"""Removes // and /* */ comments but keeps string literals intact."""
		pattern = re.compile(r"""("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|(/\*.*?\*/|//[^\n]*)""", re.S)
		return pattern.sub(lambda m: m.group(1) if m.group(1) else "", code)

	@staticmethod
	def split_statements(code: str) -> list:
		"""Splits on ; and newlines outside of string literals / brackets."""
		statements, buffer, depth, quote, i = [], [], 0, None, 0
		while i < len(code):
			c = code[i]
			if quote:
				buffer.append(c)
				if c == "\\" and i + 1 < len(code):
					buffer.append(code[i + 1])
					i += 1
				elif c == quote:
					quote = None
			elif c in "\"'":
				quote = c
				buffer.append(c)
			elif c in "([":
				depth += 1
				buffer.append(c)
			elif c in ")]":
				depth = max(0, depth - 1)
				buffer.append(c)
			elif c in "{}" and depth == 0:
				statements.append("".join(buffer))
				buffer = []
			elif (c == ";" or c == "\n") and depth == 0:
				statements.append("".join(buffer))
				buffer = []
			else:
				buffer.append(c)
			i += 1
		statements.append("".join(buffer))
		return [s.strip() for s in statements if s.strip()]

	# --- decoder function detection ----------------------------------------
	def function_bodies(self, code: str) -> dict:
		bodies = {}
		for match in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)\s*\{", code):
			depth, i = 1, match.end()
			while i < len(code) and depth:
				depth += {"{": 1, "}": -1}.get(code[i], 0)
				i += 1
			params = [p.strip() for p in match.group(2).split(",") if p.strip()]
			bodies[match.group(1)] = (params, code[match.end():i - 1])
		return bodies

	def build_replace_function(self, name: str, params: list, body: str):
		"""function X(a,b,c){ r = new RegExp(b,'g'); return a.replace(r,c) }"""
		regex = re.search(r"RegExp\(\s*(\w+)", body)
		replace = re.search(r"(\w+)\.replace\(\s*\w+\s*,\s*(\w+)", body)
		if not regex or not replace or len(params) < 3:
			return None
		subject, pattern, replacement = (params.index(replace.group(1)), params.index(regex.group(1)), params.index(replace.group(2)))

		def replace_function(evaluator, args):
			return re.sub(args[pattern], lambda _: args[replacement], args[subject])

		info(f"Stage 1 replace function: {name}({', '.join(params)})")
		return replace_function

	def build_skip_function(self, name: str, params: list, body: str):
		"""function X(s){ for(var i=START; i<s.length; i+=STEP){ r+=s.substr(i,TAKE) } return r }"""
		loop = re.search(r"for\s*\(\s*(?:var\s+)?(\w+)\s*=\s*([^;]+);\s*\1\s*<\s*(\w+)\.length\s*;\s*\1\s*(?:\+=\s*([^)]+)|\+\+)\s*\)", body)
		if not loop or len(params) < 1:
			return None
		take = re.search(rf"\.(substr|charAt)\(\s*{loop.group(1)}\s*(?:,\s*([^)]+))?\)", body)
		if not take:
			return None
		locals_code = body[:loop.start()]
		start_expr, step_expr = loop.group(2), loop.group(4) or "1"
		take_expr = take.group(2) if take.group(1) == "substr" and take.group(2) else "1"

		def skip_function(evaluator, args):
			scope = JsEvaluator(evaluator.functions)
			scope.vars = dict(evaluator.vars)
			scope.vars[params[0]] = args[0]
			for statement in self.split_statements(locals_code):
				try:
					scope.execute(statement)
				except Exception:
					pass
			start = int(scope.parse_expression(scope.tokenize(start_expr), 0)[0])
			step = int(scope.parse_expression(scope.tokenize(step_expr), 0)[0])
			count = int(scope.parse_expression(scope.tokenize(take_expr), 0)[0])
			text = args[0]
			result = "".join(text[i:i + count] for i in range(start, len(text), step))
			self.decoded.append(result)
			return result

		info(f"Stage 1 char-skip decoder: {name}(start={start_expr.strip()}, step={step_expr.strip()}, take={take_expr.strip()})")
		return skip_function

	def detect_functions(self, code: str) -> None:
		for name, (params, body) in self.function_bodies(code).items():
			function = self.build_replace_function(name, params, body) or self.build_skip_function(name, params, body)
			if function:
				self.functions[name] = function
			elif re.search(r"getTime\(\)", body) and "fromCharCode" in body:
				self.notes.append(f"{name}() is an anti-emulation timing check: the payload only runs if its CPU loop takes longer than the threshold (fast emulators/sandboxes get a wrong char)")
				# the dropper only continues when this returns the 'good' value, so emulate the slow branch
				good = re.findall(r"fromCharCode\(\s*(\w+)\s*-\s*(\d+)\s*\)", body)
				self.functions[name] = lambda evaluator, args, good=good, body=body: self.emulate_timing(body, good)

	@staticmethod
	def emulate_timing(body: str, branches: list) -> str:
		"""Returns the 'else' (slow machine) branch of the timing check."""
		counter = re.search(r"var\s+(\w+)\s*=\s*1\s*;[^}]*?\1\+\+", body, re.S)
		limit = re.search(r"while\s*\(\s*\w+\s*<\s*(\w+)\s*\)", body)
		limit_value = re.search(rf"var\s+{limit.group(1)}\s*=\s*(\d+)", body) if limit else None
		if not branches or not limit_value:
			return ""
		final = 1 + int(limit_value.group(1))
		return chr(final - int(branches[-1][1]))

	@staticmethod
	def first_argument(text: str, start: int) -> str:
		"""Returns the first top-level argument after an opening '(' (or the rest of an assignment)."""
		depth, quote, i, buffer = 0, None, start, []
		while i < len(text):
			c = text[i]
			if quote:
				if c == "\\":
					buffer.append(text[i:i + 2])
					i += 2
					continue
				if c == quote:
					quote = None
			elif c in "\"'":
				quote = c
			elif c in "([":
				depth += 1
			elif c in ")]":
				if depth == 0:
					break
				depth -= 1
			elif c == "," and depth == 0:
				break
			buffer.append(c)
			i += 1
		return "".join(buffer).strip().rstrip(";")

	# --- main --------------------------------------------------------------
	def find_accumulator(self, statements: list, evaluated: dict) -> str:
		"""
		The PowerShell is the longest string the dropper builds. Pieces can be
		appended with `X += "..."` or `X = X + "..."`, so the evaluated values are
		used; the literal-size count is only a tie breaker / fallback.
		"""
		sizes = {}
		for statement in statements:
			match = re.match(r'^(?:var\s+)?(\w+)\s*(?:\+=|=\s*(?:\1\s*\+\s*)?)\s*(["\'])', statement)
			if not match:
				match = re.match(r'^(?:var\s+)?(\w+)\s*=\s*(\w+)\s*\+\s*["\']', statement)
				if not match or match.group(1) != match.group(2):
					continue
			sizes[match.group(1)] = sizes.get(match.group(1), 0) + len(statement)

		candidates = {name: value for name, value in evaluated.items() if isinstance(value, str) and len(value) > 64}
		if candidates:
			name = max(candidates, key=lambda n: (len(candidates[n]), sizes.get(n, 0)))
			info(f"Stage 1 payload variable: {name} ({len(candidates[name])} chars, {sizes.get(name, 0)} chars of literals)")
			return name
		if not sizes:
			raise ValueError("No string accumulator found")
		name = max(sizes, key=sizes.get)
		info(f"Stage 1 payload variable: {name} ({sizes[name]} chars of literals)")
		return name

	def run(self) -> dict:
		code = self.strip_comments(self.code)
		self.detect_functions(code)
		statements = self.split_statements(code)

		evaluator = JsEvaluator(self.functions)
		evaluator.vars.update({"WScript": "WScript"})
		sinks = []
		for statement in statements:
			try:
				evaluator.execute(statement)
			except Exception:
				pass
			for sink, pattern in self.SINK_PATTERNS.items():
				match = re.search(pattern, statement)
				if not match:
					continue
				try:
					argument = self.first_argument(statement, match.end())
					value = evaluator.parse_expression(evaluator.tokenize(argument), 0)[0]
				except Exception:
					continue
				if value and not isinstance(value, (int, float)):
					sinks.append((sink, value))

		payload_var = self.find_accumulator(statements, evaluator.vars)
		powershell = evaluator.vars.get(payload_var, "")
		if not isinstance(powershell, str) or not powershell:
			raise ValueError("Payload could not be rebuilt")

		decoded_strings = list(dict.fromkeys(v for v in self.decoded if isinstance(v, str) and 0 < len(v) < 300))
		if any("syswow64" in v.lower() for v in decoded_strings) and any("system32" in v.lower() for v in decoded_strings):
			self.notes.append("PowerShell path depends on Win32_Processor.AddressWidth: 32-bit -> System32, 64-bit -> SysWOW64 (forces 32-bit PowerShell)")

		base = os.path.join(self.out_dir, os.path.splitext(os.path.basename(self.path))[0])
		ps_path = write_text(base + "_stage2.ps1", prettify_ps(powershell))

		report = {
			"file": self.path,
			"payload_variable": payload_var,
			"stage2_file": ps_path,
			"stage2_length": len(powershell),
			"launch_chain": [{"sink": s, "value": v} for s, v in sinks],
			"decoded_strings": decoded_strings,
			"notes": self.notes,
		}

		info(f"Stage 2 PowerShell ({len(powershell)} chars) written to {ps_path}")
		for note in self.notes:
			info(f"Note: {note}")
		info("Stage 1 launch chain:")
		for sink, value in sinks:
			if isinstance(value, list):
				print(f"\t{sink}:")
				for item in map(str, value):
					print(f"\t\t{item if len(item) < 120 else item[:120] + '...'}")
			else:
				print(f"\t{sink}: {value}")
		info("Stage 1 decoded strings:")
		for value in decoded_strings:
			print(f"\t{value}")

		report["powershell"] = powershell
		return report


#######################################################################
# STAGE 2 - PowerShell loader
#######################################################################

class Stage2Loader:
	"""PowerShell loader: int-array subtraction strings + hex/base64 XOR strings."""

	RE_INT_ARRAY_ASSIGN = re.compile(r"\$(\w+)\s*=\s*@\(\s*([\d\s,]+?)\s*\)\s*;")
	RE_KEY_INDEX = re.compile(r"\$(\w+)\[\(?\s*\$\w+\s*%\s*\$(\w+)\s*\)?\]")
	RE_INT_CALL = re.compile(r"(\w+)\s*\(\s*@\(\s*([\d\s,]+?)\s*\)\s*\)")
	RE_STRING_CALL = re.compile(r"\b(\w+)\s+'([0-9A-Za-z+/=]{2,})'((?:\s+-?\d+)*)\s*;?")
	RE_NUM_ASSIGN = re.compile(r"\$(\w+)\s*=\s*(-?\d+)\s*([+-])?\s*(-?\d+)?\s*;")
	RE_TRAILING_PAIRS = re.compile(r'^"?[^"$(){}]*"(?:\s*,\s*"[^"]*")+"?$')

	def __init__(self, path: str, out_dir: str, code: str = None, method: str = None, strip_junk: bool = True):
		self.path = path
		self.out_dir = out_dir
		self.code = code if code is not None else read_text(path)
		self.method = method
		self.strip_junk = strip_junk
		self.key = None
		self.modulus = None

	# --- necessity check ---------------------------------------------------
	@classmethod
	def needs_decoding(cls, code: str) -> tuple:
		"""
		Stage 2 is only needed if the PowerShell still hides strings:
		a key array indexed with %, a function called repeatedly with hex/base64
		literals, or a function called with int arrays.
		"""
		reasons = []
		arrays = {name for name, _ in cls.RE_INT_ARRAY_ASSIGN.findall(code)}
		if any(key in arrays for key, _ in cls.RE_KEY_INDEX.findall(code)):
			reasons.append("key array indexed with modulus")

		calls = {}
		for name, data, _ in cls.RE_STRING_CALL.findall(code):
			is_hex = len(data) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", data)
			is_b64 = len(data) >= 16 and len(data) % 4 == 0 and re.search(r"[A-Z]", data) and re.search(r"[a-z0-9+/]", data)
			if name.lower() not in ("function", "param", "return") and (is_hex or is_b64) and len(data) >= 8:
				calls[name] = calls.get(name, 0) + 1
		encoded = {n: c for n, c in calls.items() if c >= 3}
		if encoded:
			reasons.append("encoded string calls: " + ", ".join(f"{n} x{c}" for n, c in encoded.items()))

		int_calls = len(cls.RE_INT_CALL.findall(code))
		if int_calls >= 2:
			reasons.append(f"{int_calls} int-array decoder calls")

		needed = bool(encoded) or (bool(reasons) and int_calls >= 2)
		return needed, reasons

	# --- preprocessing -----------------------------------------------------
	def prepare(self) -> str:
		code = self.code
		if code.count("\n") < 5:
			code = prettify_ps(code)

		# legacy variant: last line "a","b","c","d" holds replacement pairs
		lines = [l.strip() for l in code.splitlines() if l.strip() and not l.strip().startswith("#")]
		if lines and self.RE_TRAILING_PAIRS.match(lines[-1]):
			items = [x for x in lines[-1].split('"') if x not in ("", ",")]
			pairs = dict(zip(items[0::2], items[1::2]))
			if pairs and all(k != v for k, v in pairs.items()):
				info(f"Stage 2 replacement pairs from last line: {pairs}")
				for old, new in pairs.items():
					code = code.replace(old, new)
			code = "\n".join(code.splitlines()[:-1])
		return code

	def numeric_vars(self, code: str) -> dict:
		values = {}
		for name, a, op, b in self.RE_NUM_ASSIGN.findall(code):
			value = int(a)
			if op and b:
				value = value + int(b) if op == "+" else value - int(b)
			values[name] = value
		return values

	# --- detection ---------------------------------------------------------
	def find_key(self, code: str) -> None:
		arrays = {name: [int(x) for x in values.replace(" ", "").split(",") if x]
				  for name, values in self.RE_INT_ARRAY_ASSIGN.findall(code)}
		numbers = self.numeric_vars(code)

		for key_name, mod_name in self.RE_KEY_INDEX.findall(code):
			if key_name in arrays:
				self.key = bytes(arrays[key_name])
				self.modulus = numbers.get(mod_name, len(self.key))
				info(f"Stage 2 key: ${key_name} = {self.key.decode(errors='replace')!r} (modulus ${mod_name} = {self.modulus})")
				return

		for name, values in arrays.items():
			if values and all(32 <= v < 127 for v in values):
				self.key, self.modulus = bytes(values), len(values)
				info(f"Stage 2 key (fallback): ${name} = {self.key.decode()!r}")
				return
		raise ValueError("Stage 2 key array not found")

	def find_decrypt_method(self, code: str) -> None:
		if self.method:
			return
		counts = {}
		for name, _, _ in self.RE_STRING_CALL.findall(code):
			if name.lower() not in ("function", "param", "return"):
				counts[name] = counts.get(name, 0) + 1
		if not counts:
			raise ValueError("Stage 2 decrypt method not found, pass --method")
		self.method = max(counts, key=counts.get)
		info(f"Stage 2 decrypt method: {self.method} ({counts[self.method]} calls)")

	def find_junk_functions(self, code: str) -> set:
		defined = set(re.findall(r"(?im)^\s*function\s+(\w+)", code))
		junk = set()
		for name in defined - {self.method}:
			calls = re.findall(rf"(?m)^\s*{re.escape(name)}((?:\s+(?:'(?:[^']|'')*'|-?[\d.]+))+)\s*;?\s*$", code)
			if len(calls) >= 3:
				junk.add(name)
		return junk

	# --- decoders ----------------------------------------------------------
	def decode_int_array(self, values: list) -> str:
		k, m = self.key, self.modulus
		candidates = [
			"".join(chr((v - k[i % m]) % 256) for i, v in enumerate(values)),
			"".join(chr((v + k[i % m]) % 256) for i, v in enumerate(values)),
			"".join(chr(v ^ k[i % m]) for i, v in enumerate(values)),
		]
		return max(candidates, key=printable_ratio)

	def decode_string(self, data: str) -> str:
		raw_candidates = []
		if len(data) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", data):
			raw_candidates.append(bytes.fromhex(data))
		try:
			raw_candidates.append(base64.b64decode(data, validate=True))
		except Exception:
			pass
		results = [bytes(b ^ self.key[i % self.modulus] for i, b in enumerate(raw)).decode("latin-1") for raw in raw_candidates]
		results = [r for r in results if printable_ratio(r) > 0.9]
		if not results:
			raise ValueError("Not a hex/base64 XOR string")
		return max(results, key=printable_ratio)

	# --- main --------------------------------------------------------------
	def run(self) -> dict:
		code = self.prepare()
		self.find_key(code)
		self.find_decrypt_method(code)
		numbers = self.numeric_vars(code)

		junk = self.find_junk_functions(code) if self.strip_junk else set()
		if junk:
			info(f"Stage 2 junk functions removed: {', '.join(sorted(junk))}")

		strings, executed, helpers, out_lines = {}, [], [], []

		def replace_int_call(match):
			decoded = self.decode_int_array([int(x) for x in match.group(2).replace(" ", "").split(",") if x])
			helpers.append(decoded)
			return ps_literal(decoded)

		for line in code.splitlines():
			stripped = line.strip()
			if not stripped:
				continue
			if junk and re.match(rf"^({'|'.join(map(re.escape, junk))})\s+['\-\d]", stripped):
				continue

			stripped = self.RE_INT_CALL.sub(replace_int_call, stripped)

			match = self.RE_STRING_CALL.search(stripped)
			if match and match.group(1) == self.method:
				try:
					decoded = self.decode_string(match.group(2))
				except ValueError:
					out_lines.append(stripped)
					continue
				args = match.group(3).split()
				prefix = stripped[:match.start()]
				assign = re.search(r"\$(?:global:)?(\w+)\s*=\s*$", prefix)
				lead = prefix[:assign.start()] if assign else prefix	# e.g. a closing '}' glued to the line
				if args and args[0] != "0" and not assign:
					executed.append(decoded.strip())
					out_lines.append(f"{lead}{decoded.strip()};\t# [exec] {self.method}")
				elif assign:
					strings[assign.group(1)] = decoded
					out_lines.append(f"{lead}${assign.group(1)} = {ps_literal(decoded)};")
				else:
					out_lines.append(f"{lead}{ps_literal(decoded)};")
				continue
			out_lines.append(stripped)

		def resolve(text: str) -> str:
			for name, value in sorted(strings.items(), key=lambda kv: -len(kv[0])):
				text = re.sub(rf"\${re.escape(name)}\b", lambda _: ps_literal(value), text)
			for name, value in numbers.items():
				text = re.sub(rf"\${re.escape(name)}\b", str(value), text)
			return text

		resolved = [resolve(x) for x in executed]
		iocs = self.extract_iocs(strings, resolved)

		base = os.path.join(self.out_dir, os.path.splitext(os.path.basename(self.path))[0])
		base = base[:-len("_stage2")] if base.endswith("_stage2") else base
		out_path = base + "_stage2_decoded.ps1"
		text = ["# ---- decoded helper code (int arrays) ----"]
		text += [f"# {value}" for value in helpers]
		text += ["", "# ---- deobfuscated script ----"] + out_lines
		text += ["", "# ---- executed code, variables resolved ----"] + resolved
		write_text(out_path, "\n".join(text) + "\n")

		info(f"Stage 2 decoded script written to {out_path}")
		print_iocs("Stage 2 IOCs", iocs)

		return {"file": self.path, "decoded_file": out_path, "key": self.key.decode(errors="replace"),
				"decrypt_method": self.method, "strings": strings, "executed": resolved, "iocs": iocs}

	@staticmethod
	def extract_iocs(strings: dict, resolved: list) -> dict:
		everything = "\n".join(list(strings.values()) + resolved)
		generic = extract_iocs_from_text([ps_literal(v) for v in strings.values()] + resolved)
		iocs = {
			"urls": sorted({u for blob in strings.values() for u in re.split(r"[>|\s,;]", blob) if re.match(r"https?://", u)}),
			"registry": sorted(set(re.findall(r"(?:HKCU|HKLM|HKEY_[A-Z_]+):?\\[^'\"\s]+", everything))),
			"user_agent": [v for v in strings.values() if "Windows NT" in v or "Mozilla" in v],
			"com_objects": [v for v in strings.values() if re.fullmatch(r"[A-Za-z0-9]+\.[A-Za-z0-9.]+\.\d+(\.\d+)?", v)],
		}
		value_name = re.search(r"New-Item\s+'([^']+)'.*?PSPath\s+'([^']+)'", everything)
		if value_name:
			iocs["registry_value"] = f"{value_name.group(1)} -> {value_name.group(2)}"
		substring = re.search(r"\.substring\(\s*(\d+)\s*,\s*(\d+)\s*\)", everything, re.I)
		if substring:
			iocs["stage3_substring"] = [int(substring.group(1)), int(substring.group(2))]
		for name, value in generic.items():
			if name not in iocs or not iocs[name]:
				iocs[name] = value
		return {k: v for k, v in iocs.items() if v}


#######################################################################
# STAGE 3 - payload carved from the downloaded blob
#######################################################################

def extract_stage3(blob_file: str, offset: int, length: int, out_dir: str) -> str:
	"""Downloaded file / registry value: base64 -> ASCII -> substring(offset, length)."""
	with open(blob_file, "rb") as in_file:
		data = in_file.read().strip()
	text = base64.b64decode(data).decode("ascii", errors="replace")
	stage3 = text[offset:offset + length]
	out_path = write_text(os.path.join(out_dir, os.path.basename(blob_file) + "_stage3.ps1"), stage3)
	info(f"Stage 3 ({len(stage3)} chars) written to {out_path}")
	return out_path


#######################################################################
# CLI
#######################################################################

def parse_arguments():
	parser = argparse.ArgumentParser(
		prog="Agenttesla Decoder",
		description="Static decoder for the Agent Tesla JS -> PowerShell loader chain. Nothing is executed.")
	parser.add_argument("input", help=".rar / .zip / .js dropper, or the stage 2 .ps1")
	parser.add_argument("--stage", choices=["1", "2", "all"], default="all",
						help="1 = JS dropper -> PowerShell, 2 = PowerShell loader -> IOCs, all = both (default)")
	parser.add_argument("-o", "--out-dir", default=None, help="Output directory (default: next to the input)")
	parser.add_argument("--password", default=None, help="Archive password, if any")
	parser.add_argument("--method", default=None, help="Override the stage 2 string decrypt method name")
	parser.add_argument("--force-stage2", action="store_true", help="Run stage 2 even if the check says it is not needed")
	parser.add_argument("--keep-junk", action="store_true", help="Keep junk function calls in the stage 2 output")
	parser.add_argument("--blob", default=None, help="Downloaded payload (e.g. Minuting.mix) or registry value -> stage 3")
	parser.add_argument("--offset", type=int, default=None, help="Stage 3 substring offset (default: from stage 2)")
	parser.add_argument("--length", type=int, default=None, help="Stage 3 substring length (default: from stage 2)")
	parser.add_argument("--json", default=None, help="Write the full report as JSON to this file")
	return parser.parse_args()


def run_stage3(args, iocs: dict, out_dir: str, report: dict) -> None:
	if not args.blob:
		return
	offset, length = args.offset, args.length
	if (offset is None or length is None) and "stage3_substring" in iocs:
		offset, length = iocs["stage3_substring"]
	if offset is None or length is None:
		warn("Stage 3 offset/length unknown, pass --offset and --length")
		return
	with Timer("stage 3 extraction"):
		report["stage3"] = extract_stage3(args.blob, offset, length, out_dir)


def main():
	args = parse_arguments()
	out_dir = args.out_dir or os.path.dirname(os.path.abspath(args.input))
	os.makedirs(out_dir, exist_ok=True)
	report = {"input": args.input, "stage1": [], "stage2": []}

	for path in unpack_archive(args.input, out_dir, args.password):
		code = read_text(path)
		kind = detect_type(code)
		info(f"Processing {os.path.basename(path)} (detected: {'JScript dropper' if kind == 'js' else 'PowerShell'})")

		stage1_result, stage2_code, stage2_path = None, code, path
		if kind == "js":
			if args.stage == "2":
				warn("Input is JScript, running stage 1 first to get the PowerShell")
			with Timer("stage 1"):
				stage1_result = Stage1Dropper(path, out_dir).run()
			stage2_code, stage2_path = stage1_result.pop("powershell"), stage1_result["stage2_file"]
			report["stage1"].append(stage1_result)
		elif args.stage == "1":
			warn("Input is already PowerShell, nothing to do for stage 1 (use --stage 2)")
			continue

		# is stage 2 decoding necessary?
		needed, reasons = Stage2Loader.needs_decoding(stage2_code)
		if needed:
			info(f"Stage 2 decoding needed ({'; '.join(reasons)})")
		else:
			info("Stage 2 decoding not needed: no encoded strings left in the PowerShell" + (f" ({'; '.join(reasons)})" if reasons else ""))

		if not needed and not args.force_stage2:
			sources = [stage2_code]
			if stage1_result:
				sources += stage1_result["decoded_strings"]
				for item in stage1_result["launch_chain"]:
					sources += [str(v) for v in item["value"]] if isinstance(item["value"], list) else [str(item["value"])]
			iocs = extract_iocs_from_text(sources)
			print_iocs("Stage 1 IOCs" if stage1_result else "PowerShell IOCs", iocs)
			(stage1_result if stage1_result else report).setdefault("iocs", iocs)
			if stage1_result:
				stage1_result["stage2_needed"] = False
			run_stage3(args, iocs, out_dir, report)
			continue

		if stage1_result:
			stage1_result["stage2_needed"] = True
		if args.stage == "1":
			info(f"Run --stage 2 (or --stage all) on {stage2_path} to decode it")
			continue

		try:
			with Timer("stage 2"):
				result = Stage2Loader(stage2_path, out_dir, code=stage2_code, method=args.method,
									  strip_junk=not args.keep_junk).run()
		except ValueError as error:
			warn(f"Stage 2 failed ({error}), falling back to plain IOC extraction")
			result = {"file": stage2_path, "error": str(error), "iocs": extract_iocs_from_text([stage2_code])}
			print_iocs("PowerShell IOCs", result["iocs"])
		report["stage2"].append(result)
		run_stage3(args, result["iocs"], out_dir, report)

	if args.json:
		with open(args.json, "w", encoding="utf-8") as out_file:
			json.dump(report, out_file, indent=2, default=str)
		info(f"Report written to {args.json}")


if __name__ == "__main__":
	main()
