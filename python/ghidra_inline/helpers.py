"""Eager array-oriented operations on the selected program. No implicit output."""
import codecs
import re

_MISSING = object()

class Helpers:
    def __init__(self, program, monitor, check, decompilers, writable=False):
        self.program, self.monitor, self.check, self.writable = program, monitor, check, writable
        self._decompilers = decompilers

    @staticmethod
    def _array(values):
        if not isinstance(values, (list, tuple)):
            raise TypeError('Targets must be an array, including for one target: [value]')
        return values

    def _batch(self, values, operation, label):
        results = []
        for index, value in enumerate(self._array(values)):
            self.check()
            try:
                result = operation(value)
            except Exception as exc:
                exc.add_note(f'gh.{label}: item {index}, target {repr(value)[:160]}')
                raise
            results.append((value, result))
        return results

    def _change(self, targets, value, operation, label):
        self.require_write()
        self._array(targets)
        assignments = [(target, value) for target in targets] if value is not _MISSING else targets
        for item in assignments:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise TypeError(f'{label}: use [(target, value), ...] or ([targets], common_value)')
        def apply(pair):
            operation(*pair)
            return None
        return [(pair[0], result) for pair, result in self._batch(assignments, apply, label)]

    def require_write(self):
        if not self.writable:
            raise RuntimeError('This operation requires exec --write')

    def _address(self, value):
        if hasattr(value, 'getAddressSpace'):
            return value
        try:
            return self.program.getAddressFactory().getAddress(hex(value) if isinstance(value, int) else str(value))
        except Exception:
            return None

    def _required_address(self, value):
        address = self._address(value)
        if address is None:
            raise ValueError(f'Invalid address: {value}')
        return address

    def _memory_address(self, value):
        address = self._required_address(value)
        if not self.program.getMemory().contains(address):
            raise ValueError(f'Address outside program memory: {address}')
        return address

    def address(self, targets):
        return self._batch(targets, self._address, 'address')

    def _function(self, value, *, containing=False):
        if hasattr(value, 'getEntryPoint') and hasattr(value, 'getProgram'):
            if value.getProgram() != self.program:
                raise ValueError('Function belongs to another program')
            return value
        fm = self.program.getFunctionManager()
        address = self._address(value)
        function = fm.getFunctionAt(address) if address is not None else None
        if function is None and address is not None:
            owner = fm.getFunctionContaining(address)
            if owner is not None:
                if not containing:
                    raise ValueError(f'Address {address} is inside function {owner.getName()} at '
                                     f'{owner.getEntryPoint()}; specify its entry point or resolve '
                                     'explicitly with gh.function([address])')
                function = owner
        if function is None:
            found = {}
            for symbol in self.program.getSymbolTable().getSymbols(str(value)):
                self.check()
                candidate = fm.getFunctionAt(symbol.getAddress())
                if candidate is not None:
                    found[str(candidate.getEntryPoint())] = candidate
            if len(found) == 1:
                return next(iter(found.values()))
            if len(found) > 1:
                raise ValueError(f'Ambiguous function {value}; use an address from {list(found)}')
            raise ValueError(f'Function not found: {value}')
        return function

    def function(self, targets):
        return self._batch(targets, lambda value: self._function(value, containing=True), 'function')

    def _bounds(self, start, end):
        return (self._required_address(start) if start is not None else None,
                self._required_address(end) if end is not None else None)

    @staticmethod
    def _within(address, start, end):
        return ((start is None or (address.getAddressSpace() == start.getAddressSpace() and address.compareTo(start) >= 0))
                and (end is None or (address.getAddressSpace() == end.getAddressSpace() and address.compareTo(end) <= 0)))

    def _select(self, items, predicate, limit, offset):
        if offset < 0 or (limit is not None and limit < 0):
            raise ValueError('limit and offset must be nonnegative; limit=None means all')
        result, skipped = [], 0
        if limit == 0:
            return result
        for item in items:
            self.check()
            if not predicate(item):
                continue
            if skipped < offset:
                skipped += 1
                continue
            result.append(item)
            if limit is not None and len(result) >= limit:
                break
        return result

    def functions(self, *, name=None, start=None, end=None, min_size=None, max_size=None,
                  unnamed=None, limit=None, offset=0):
        start, end = self._bounds(start, end)
        needle = name.casefold() if name is not None else None
        def matches(f):
            size = f.getBody().getNumAddresses()
            default = str(f.getSymbol().getSource()) == 'DEFAULT'
            return ((needle is None or needle in str(f.getName()).casefold())
                    and self._within(f.getEntryPoint(), start, end)
                    and (min_size is None or size >= min_size)
                    and (max_size is None or size <= max_size)
                    and (unnamed is None or unnamed == default))
        return self._select(self.program.getFunctionManager().getFunctions(True), matches, limit, offset)

    def decompile(self, targets, *, timeout=0, with_addresses=False):
        self._array(targets)
        if not targets:
            return []
        with self._decompilers.lease(reuse=not self.writable) as interface:
            def run(value):
                function = self._function(value)
                result = interface.decompileFunction(function, timeout, self.monitor)
                self.check()
                if not result.decompileCompleted():
                    raise RuntimeError(str(result.getErrorMessage()))
                if with_addresses:
                    return self._decompile_lines(function, result)
                return str(result.getDecompiledFunction().getC())
            return self._batch(targets, run, 'decompile')

    def _decompile_lines(self, function, result):
        from ghidra.app.decompiler import PrettyPrinter, ClangStatement
        from ghidra.program.model.symbol import IllegalCharCppTransformer
        printer = PrettyPrinter(function, result.getCCodeMarkup(), IllegalCharCppTransformer())
        source = str(printer.print_().getC()).splitlines()
        rows = []
        for number, (line, text) in enumerate(zip(printer.getLines(), source, strict=True), 1):
            self.check()
            addresses = set()
            for token in line.getAllTokens():
                operation = token.getPcodeOp()
                if operation is not None:
                    addresses.add(operation.getSeqnum().getTarget())
                parent = token.Parent()
                while parent is not None:
                    if isinstance(parent, ClangStatement):
                        operation = parent.getPcodeOp()
                        if operation is not None:
                            addresses.add(operation.getSeqnum().getTarget())
                        break
                    parent = parent.Parent()
            rows.append({'line': number, 'text': text, 'addresses': sorted(addresses,
                key=lambda address: (str(address.getAddressSpace().getName()), int(address.getUnsignedOffset())))})
        return rows

    def _read_bytes(self, value, size):
        from jpype import JArray, JByte
        if size < 0:
            raise ValueError('size must be nonnegative')
        if size == 0:
            return b''
        buffer = JArray(JByte)(size)
        count = self.program.getMemory().getBytes(self._required_address(value), buffer)
        if count != size:
            raise ValueError(f'Expected {size} bytes, read {count}')
        return bytes(buffer)

    def read_bytes(self, targets, *, size):
        return self._batch(targets, lambda value: self._read_bytes(value, size), 'read_bytes')

    def read_string(self, targets, *, max_length=4096, encoding='utf-8', errors='strict'):
        normalized = codecs.lookup(encoding).name
        unit = 2 if normalized.startswith('utf-16') else 4 if normalized.startswith('utf-32') else 1
        def read(value):
            address = self._required_address(value)
            data = bytearray()
            for offset in range(0, max_length - unit + 1, unit):
                self.check()
                chunk = self._read_bytes(address.add(offset), unit)
                if chunk == bytes(unit):
                    return data.decode(encoding, errors)
                data.extend(chunk)
            raise ValueError(f'String has no NUL terminator within {max_length} bytes')
        return self._batch(targets, read, 'read_string')

    def memory_blocks(self, *, name=None, limit=None, offset=0):
        needle = name.casefold() if name is not None else None
        return self._select(self.program.getMemory().getBlocks(),
            lambda b: needle is None or needle in str(b.getName()).casefold(), limit, offset)

    def disassemble(self, targets, *, count=20):
        if count < 0:
            raise ValueError('count must be nonnegative')
        def read(value):
            result, address = [], self._required_address(value)
            for _ in range(count):
                self.check()
                instruction = self.program.getListing().getInstructionAt(address)
                if instruction is None:
                    if not result:
                        raise ValueError(f'No defined instruction at {address}')
                    break
                result.append(instruction)
                address = instruction.getMaxAddress().next()
                if address is None:
                    break
            return result
        return self._batch(targets, read, 'disassemble')

    def _related(self, targets, method, limit, offset):
        def read(value):
            items = sorted(getattr(self._function(value), method)(self.monitor),
                           key=lambda f: str(f.getEntryPoint()))
            return self._select(items, lambda f: True, limit, offset)
        return self._batch(targets, read, 'callers' if method == 'getCallingFunctions' else 'callees')

    def callers(self, targets, *, limit=None, offset=0):
        return self._related(targets, 'getCallingFunctions', limit, offset)

    def callees(self, targets, *, limit=None, offset=0):
        return self._related(targets, 'getCalledFunctions', limit, offset)

    def strings(self, *, text=None, start=None, end=None, limit=None, offset=0):
        from ghidra.program.util import DefinedStringIterator
        start, end = self._bounds(start, end)
        needle = text.casefold() if text is not None else None
        return self._select(DefinedStringIterator.forProgram(self.program),
            lambda s: self._within(s.getAddress(), start, end)
            and (needle is None or needle in str(s.getValue()).casefold()), limit, offset)

    def find_strings(self, patterns, *, regex=False, case_sensitive=False,
                     start=None, end=None, limit=None, offset=0):
        from ghidra.program.util import DefinedStringIterator
        start, end = self._bounds(start, end)
        def search(pattern):
            expression = re.compile(pattern if regex else re.escape(pattern), 0 if case_sensitive else re.IGNORECASE)
            return self._select(DefinedStringIterator.forProgram(self.program),
                lambda s: self._within(s.getAddress(), start, end) and expression.search(str(s.getValue())) is not None,
                limit, offset)
        return self._batch(patterns, search, 'find_strings')

    @staticmethod
    def _byte_pattern(pattern):
        if isinstance(pattern, (bytes, bytearray)):
            raw = bytes(pattern)
            masks = b'\xff' * len(raw)
        elif isinstance(pattern, str):
            compact = ''.join(pattern.split())
            if len(compact) % 2:
                raise ValueError('Byte patterns must contain complete bytes')
            tokens = [compact[i:i+2] for i in range(0, len(compact), 2)]
            raw = bytes(int(token.replace('?', '0'), 16) for token in tokens)
            masks = bytes(int(''.join('0' if c == '?' else 'f' for c in token), 16) for token in tokens)
        else:
            raise TypeError('Byte pattern must be bytes or a hex string with optional ? wildcards')
        if not raw:
            raise ValueError('Byte pattern must not be empty')
        return raw, masks

    def find_bytes(self, patterns, *, start=None, end=None, limit=None, offset=0):
        from jpype import JArray, JByte
        start = self._required_address(start) if start is not None else self.program.getMinAddress()
        end = self._required_address(end) if end is not None else self.program.getMaxAddress()
        if offset < 0 or (limit is not None and limit < 0):
            raise ValueError('limit and offset must be nonnegative')
        def search(pattern):
            raw, mask = self._byte_pattern(pattern)
            data, masks = JArray(JByte)(raw), JArray(JByte)(mask)
            result, skipped, cursor = [], 0, start
            while cursor is not None and cursor.compareTo(end) <= 0 and (limit is None or len(result) < limit):
                self.check()
                hit = self.program.getMemory().findBytes(cursor, end, data, masks, True, self.monitor)
                self.check()
                if hit is None:
                    break
                if skipped < offset:
                    skipped += 1
                else:
                    result.append(hit)
                cursor = hit.next()
            return result
        return self._batch(patterns, search, 'find_bytes')

    def symbols(self, *, name=None, kind=None, start=None, end=None, limit=None, offset=0):
        start, end = self._bounds(start, end)
        needle = name.casefold() if name is not None else None
        return self._select(self.program.getSymbolTable().getAllSymbols(True),
            lambda s: (needle is None or needle in str(s.getName()).casefold())
            and (kind is None or str(s.getSymbolType()).casefold() == kind.casefold())
            and self._within(s.getAddress(), start, end), limit, offset)

    def xrefs_to(self, targets, *, limit=None, offset=0):
        return self._batch(targets, lambda value: self._select(
            self.program.getReferenceManager().getReferencesTo(self._required_address(value)),
            lambda r: True, limit, offset), 'xrefs_to')

    def xrefs_from(self, targets, *, limit=None, offset=0):
        return self._batch(targets, lambda value: self._select(
            self.program.getReferenceManager().getReferencesFrom(self._required_address(value)),
            lambda r: True, limit, offset), 'xrefs_from')

    @staticmethod
    def _comment_type(kind):
        from ghidra.program.model.listing import CommentType
        return CommentType.valueOf(kind.upper())

    def get_comment(self, targets, *, kind='EOL'):
        comment_type = self._comment_type(kind)
        return self._batch(targets, lambda value: self.program.getListing().getComment(
            comment_type, self._required_address(value)), 'get_comment')

    def set_comment(self, targets, text=_MISSING, *, kind='EOL'):
        comment_type = self._comment_type(kind)
        return self._change(targets, text, lambda value, text: self.program.getListing().setComment(
            self._memory_address(value), comment_type, text), 'set_comment')

    def _writable_function(self, value):
        function = self._function(value)
        self._memory_address(function.getEntryPoint())
        return function

    def rename_function(self, targets, name=_MISSING):
        from ghidra.program.model.symbol import SourceType
        return self._change(targets, name, lambda value, text: self._writable_function(value).setName(
            text, SourceType.USER_DEFINED), 'rename_function')

    def rename_label(self, targets, name=_MISSING):
        from ghidra.program.model.symbol import SourceType, SymbolType
        def rename(value, text):
            address = self._memory_address(value)
            table = self.program.getSymbolTable()
            primary = table.getPrimarySymbol(address)
            if primary is not None and primary.getSymbolType() == SymbolType.LABEL:
                primary.setName(text, SourceType.USER_DEFINED)
            else:
                table.createLabel(address, text, SourceType.USER_DEFINED)
        return self._change(targets, name, rename, 'rename_label')

    def types(self, *, name=None, limit=None, offset=0):
        needle = name.casefold() if name is not None else None
        return self._select(self.program.getDataTypeManager().getAllDataTypes(),
            lambda t: needle is None or needle in str(t.getPathName()).casefold(), limit, offset)

    def _type(self, value):
        from ghidra.program.model.data import BuiltInDataTypeManager
        from ghidra.util.data import DataTypeParser
        from java.util import ArrayList
        if hasattr(value, 'getDataTypeManager'):
            return value
        manager = self.program.getDataTypeManager()
        if str(value).startswith('/'):
            found = manager.getDataType(value)
            if found is None:
                found = BuiltInDataTypeManager.getDataTypeManager().getDataType(value)
            if found is None:
                raise ValueError(f'Data type not found: {value}')
            return found
        matches = ArrayList()
        manager.findDataTypes(value, matches)
        if len(matches) > 1:
            raise ValueError(f'Ambiguous type {value}: {[str(t.getPathName()) for t in matches]}')
        if len(matches) == 1:
            return matches[0]
        parser = DataTypeParser(BuiltInDataTypeManager.getDataTypeManager(), manager,
                               None, DataTypeParser.AllowedDataTypes.ALL)
        return parser.parse(value)

    def get_type(self, names):
        return self._batch(names, self._type, 'get_type')

    def set_signature(self, targets, signature=_MISSING):
        from ghidra.app.util.parser import FunctionSignatureParser
        from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
        from ghidra.program.model.symbol import SourceType
        parser = FunctionSignatureParser(self.program.getDataTypeManager(), None)
        def apply(value, text):
            function = self._writable_function(value)
            parsed = parser.parse(function.getSignature(), text)
            command = ApplyFunctionSignatureCmd(function.getEntryPoint(), parsed, SourceType.USER_DEFINED, False, True)
            if not command.applyTo(self.program, self.monitor):
                raise RuntimeError(str(command.getStatusMsg()))
        return self._change(targets, signature, apply, 'set_signature')

    def apply_type(self, targets, type_name=_MISSING, *, clear=False, length=None):
        from ghidra.program.model.data import DataUtilities
        mode = (DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA if clear else
                DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
        def apply(value, data_type):
            DataUtilities.createData(self.program, self._memory_address(value), self._type(data_type),
                                     -1 if length is None else length, mode)
        return self._change(targets, type_name, apply, 'apply_type')
