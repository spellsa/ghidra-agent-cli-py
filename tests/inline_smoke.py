"""Normal-use integration tests against generated sample programs or supplied projects.
Run inside the agent: GHIDRA_CLI_SERVER=host:port python3 tests/inline_smoke.py
"""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

CLI = os.environ.get('GHIDRA_CLI_BIN', 'ghidra')
PROJECT = os.environ.get('GHIDRA_TEST_PROJECT', '/projects/smoke.gpr')
PROGRAM_A = os.environ.get('GHIDRA_TEST_PROGRAM_A', 'sample_a')
PROGRAM_B = os.environ.get('GHIDRA_TEST_PROGRAM_B', 'sample_b')
ADDRESS = os.environ.get('GHIDRA_TEST_FUNCTION')

def call(*args, code=None, check=True):
    result = subprocess.run([CLI, *args], input=code, text=True, capture_output=True, timeout=60)
    if check and result.returncode:
        path = result.stderr.strip()
        detail = Path(path).read_text() if Path(path).is_file() else path
        raise AssertionError(detail)
    return result

def spawn(target, code, write=False):
    process = subprocess.Popen([CLI, '--target', target, 'exec', *(['--write'] if write else [])],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    process.stdin.write(code)
    process.stdin.close()
    process.stdin = None
    return process

class LiveInline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = call('use', '--project', PROJECT, '--program', PROGRAM_A).stdout.strip()
        cls.b = call('use', '--project', PROJECT, '--program', PROGRAM_B).stdout.strip()
        cls.address = ADDRESS or call('--target', cls.a, 'exec', code='print(hex(gh.functions(limit=1)[0].getEntryPoint().getOffset()))').stdout.strip()
    def execute(self, code, target=None, write=False):
        result = call('--target', target or self.a, 'exec', *(['--write'] if write else []), code=code)
        self.assertEqual(result.stderr, '')
        return result.stdout
    def test_01_existing_data_and_plain_output(self):
        self.assertEqual(self.execute('print(program.getName())'), PROGRAM_A + '\n')
        self.assertGreater(int(self.execute('print(program.getFunctionManager().getFunctionCount())')), 0)
        self.assertEqual(self.execute('pass'), '')
        self.assertEqual(self.execute('print("literal\\\\n")'), 'literal\\n\n')
        self.execute('private_variable = 123')
        self.assertEqual(self.execute('print("private_variable" in globals())'), 'False\n')
        self.assertEqual(call('use', '--project', PROJECT, '--program', PROGRAM_A).stdout.strip(), self.a)
        result = call('--target', self.a, 'exec', '--', 'one', 'two', code='print(*args)')
        self.assertEqual(result.stdout, 'one two\n')
    def test_02_helpers_and_pipeline(self):
        code = f'print(gh.decompile([{self.address}])[0][1])'
        text = self.execute(code)
        self.assertIn('{', text)
        result = subprocess.run(['bash', '-c', f'set -o pipefail; {CLI} --target {self.a} exec | rg -n "return"'],
            input=code, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('return', result.stdout)
        with tempfile.TemporaryDirectory(prefix='ghidra-inline-smoke-') as directory:
            p = Path(directory) / 'function.c'
            with p.open('w') as output:
                subprocess.run([CLI, '--target', self.a, 'exec'], input=code, text=True, stdout=output, check=True)
            grep = subprocess.run(['rg', '-n', 'return', str(p)], capture_output=True, text=True, check=True)
            self.assertIn('return', grep.stdout)
        self.execute('for i, s in enumerate(gh.strings()):\n print(s.getAddress())\n if i == 1: break')
        self.execute(f'for i, r in enumerate(gh.xrefs_to([{self.address}])[0][1]):\n print(r.getFromAddress())\n if i == 1: break')
    def test_03_same_program_concurrent_output(self):
        def script(tag):
            return f'import time, sys\nprint("{tag}", time.time())\nprint("{tag}-err", file=sys.stderr)\ntime.sleep(.6)\nprint("{tag}", time.time())'
        a = spawn(self.a, script('A'))
        b = spawn(self.a, script('B'))
        outa, erra = a.communicate(timeout=10)
        outb, errb = b.communicate(timeout=10)
        self.assertEqual((a.returncode, b.returncode), (0, 0), (erra, errb))
        self.assertEqual(erra, 'A-err\n')
        self.assertEqual(errb, 'B-err\n')
        aa = [float(l.split()[1]) for l in outa.splitlines()]
        bb = [float(l.split()[1]) for l in outb.splitlines()]
        self.assertGreater(min(aa[1], bb[1]) - max(aa[0], bb[0]), .3)
    def test_04_write_order_and_different_program_parallelism(self):
        writer = spawn(self.a, 'import time\nprint("started", flush=True)\ntime.sleep(.7)\nprint(time.time())', write=True)
        self.assertEqual(writer.stdout.readline().strip(), 'started')
        same = spawn(self.a, 'import time\nprint(time.time())')
        other = spawn(self.b, 'import time\nprint(time.time())\nprint(program.getName())')
        out_other, err_other = other.communicate(timeout=10)
        out_write, err_write = writer.communicate(timeout=10)
        out_same, err_same = same.communicate(timeout=10)
        self.assertEqual([writer.returncode, same.returncode, other.returncode], [0, 0, 0], (err_write,err_same,err_other))
        self.assertLess(float(out_other.splitlines()[0]), float(out_write))
        self.assertGreater(float(out_same), float(out_write))
        self.assertIn(PROGRAM_B, out_other)
    def test_05_write_save_and_restore(self):
        before = self.execute(f'print(gh.function([{self.address}])[0][1].getName())').strip()
        try:
            self.execute(f'gh.rename_function([({self.address}, "__inline_smoke_saved")])', write=True)
            self.assertEqual(self.execute(f'print(gh.function([{self.address}])[0][1].getName())').strip(), '__inline_smoke_saved')
        finally:
            self.execute(f'gh.rename_function([({self.address}, {before!r})])', write=True)
        self.assertEqual(self.execute(f'print(gh.function([{self.address}])[0][1].getName())').strip(), before)
    def test_06_status_and_cancel(self):
        process = spawn(self.a, 'print("started", flush=True)\nx=0\nwhile True:\n x += 1')
        self.assertEqual(process.stdout.readline().strip(), 'started')
        jobs = call('--target', self.a, 'jobs').stdout.splitlines()
        active = [line.split('\t') for line in jobs if '\trunning\t' in line]
        self.assertEqual(len(active), 1)
        job = active[0][0]
        result = call('--target', self.a, 'cancel', job)
        self.assertTrue(any(state in result.stdout for state in ('cancel_requested', 'cancelled')), result.stdout)
        out, error = process.communicate(timeout=10)
        self.assertNotEqual(process.returncode, 0)
        p = Path(error.strip())
        self.assertTrue(p.is_file(), error)
        self.assertIn('CANCELLED', p.read_text())
        p.unlink()
        self.assertIn('cancelled', call('--target', self.a, 'jobs', job).stdout)
    def test_07_large_output_and_no_history(self):
        result = self.execute('for n in range(12000): print(n)')
        self.assertEqual(len(result.splitlines()), 12000)
        self.assertEqual(result.splitlines()[-1], '11999')
    def test_08_error_detail_is_local_and_exact_source(self):
        code = 'print("before")\nraise ValueError("inline-smoke-error")\n'
        result = call('--target', self.a, 'exec', code=code, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, 'before\n')
        p = Path(result.stderr.strip())
        self.assertTrue(p.is_absolute())
        self.assertTrue(p.is_file())
        detail = p.read_text()
        self.assertIn(code, detail)
        self.assertIn(hashlib.sha256(code.encode()).hexdigest(), detail)
        self.assertIn('inline-smoke-error', detail)
        p.unlink()

    def test_09_eager_batch_and_listing_filters(self):
        self.execute("""
fs = gh.functions(limit=3)
assert isinstance(fs, list) and len(fs) == 3
addresses = [f.getEntryPoint() for f in fs]
inputs = [addresses[1], addresses[0], addresses[1]]
assert [a for a, f in gh.function(inputs)] == inputs
assert [a for a, address in gh.address(inputs)] == inputs
assert len(gh.decompile(inputs[:2])) == 2
assert gh.decompile([]) == []
assert gh.function([]) == []
assert [f.getEntryPoint() for f in gh.functions(limit=2, offset=1)] == addresses[1:]
assert len(gh.functions(start=addresses[0], end=addresses[1])) == 2
assert len(gh.functions(name=str(fs[0].getName()), limit=1)) == 1
assert gh.functions(limit=0) == []
assert all(f.getBody().getNumAddresses() >= 10 for f in gh.functions(min_size=10,limit=3))
assert isinstance(gh.symbols(limit=3), list)
assert isinstance(gh.memory_blocks(limit=3), list)
assert isinstance(gh.types(limit=3), list)
print('batch/list filters verified')
""")
    def test_10_memory_disassembly_and_search(self):
        self.execute("""
addresses = [f.getEntryPoint() for f in gh.functions(min_size=32, limit=2)]
read = gh.read_bytes(addresses,size=8)
assert [len(data) for address,data in read] == [8,8]
assert all(len(code) == 3 for address,code in gh.disassemble(addresses,count=3))
assert len(gh.callers(addresses,limit=2)) == 2
assert len(gh.callees(addresses,limit=2)) == 2
assert len(gh.xrefs_to(addresses,limit=2)) == 2
assert len(gh.xrefs_from(addresses,limit=2)) == 2
pattern=read[0][1]
start=addresses[0]
end=start.add(32)
hits=gh.find_bytes([pattern, pattern.hex(), '?? '+pattern[1:].hex(' ')], start=start,end=end,limit=1)
assert all(values == [start] for pattern,values in hits)
assert gh.find_bytes([pattern],start=start,end=end,limit=0)[0][1] == []
strings=gh.strings(limit=2)
assert strings
needle=str(strings[0].getValue())
assert gh.find_strings([needle],limit=1)[0][1][0].getAddress() == strings[0].getAddress()
assert isinstance(gh.read_string([program.getMinAddress()],max_length=128)[0][1],str)
assert [str(t.getName()) for name,t in gh.get_type(['int','char *','byte[4]'])] == ['int','char *','byte[4]']
print('memory/search helpers verified')
""")
    def test_11_batch_writes_and_rollback(self):
        before=self.execute("print([(str(f.getEntryPoint()),str(f.getName()),str(f.getSignature())) for f in gh.functions(limit=2)])")
        self.execute("""
fs=gh.functions(limit=2)
addresses=[f.getEntryPoint() for f in fs]
transaction=program.startTransaction('temporary batch verification')
try:
    assert gh.rename_function([(addresses[0],'__batch_one'),(addresses[1],'__batch_two')]) == [(a,None) for a in addresses]
    assert [str(f.getName()) for f in fs] == ['__batch_one','__batch_two']
    assert gh.set_comment(addresses,'shared') == [(a,None) for a in addresses]
    assert all(str(c)=='shared' for a,c in gh.get_comment(addresses))
    gh.set_comment([(addresses[0],'one'),(addresses[1],'two')],kind='PLATE')
    assert [str(c) for a,c in gh.get_comment(addresses,kind='PLATE')] == ['one','two']
    gh.set_signature([(addresses[0],'int __batch_one(int value)'),(addresses[1],'int __batch_two(void)')])
    assert fs[0].getParameterCount() == 1
    data=program.getListing().getUndefinedDataAfter(program.getMinAddress(),monitor)
    a=data.getAddress()
    b=a.add(1)
    gh.rename_label([(a,'__batch_label_one'),(b,'__batch_label_two')])
    assert str(program.getSymbolTable().getPrimarySymbol(a).getName()) == '__batch_label_one'
    gh.apply_type([a,b],'byte')
    assert str(program.getListing().getDataAt(a).getDataType().getName()) == 'byte'
    gh.apply_type([(a,'byte'),(b,'byte')],clear=True)
    gh.set_comment(addresses,None)
    assert all(c is None for a,c in gh.get_comment(addresses))
finally:
    program.endTransaction(transaction,False)
print('all batch write helpers verified')
""",write=True)
        after=self.execute("print([(str(f.getEntryPoint()),str(f.getName()),str(f.getSignature())) for f in gh.functions(limit=2)])")
        self.assertEqual(after,before)
        failure=call('--target',self.a,'exec','--write',code=f'gh.rename_function([({self.address},"__must_rollback"),("__missing_function__","unreachable")])',check=False)
        self.assertNotEqual(failure.returncode,0)
        p=Path(failure.stderr.strip())
        self.assertIn('item 1',p.read_text())
        p.unlink()
        self.assertEqual(self.execute("print([(str(f.getEntryPoint()),str(f.getName()),str(f.getSignature())) for f in gh.functions(limit=2)])"),before)

    def test_12_function_selector_contract(self):
        self.execute("""
f = gh.functions(limit=1)[0]
a = f.getEntryPoint()
selectors = [int(a.getOffset()), str(a), str(a.getAddressSpace().getName()) + ':' + str(a),
             str(f.getName()), f, a]
results = gh.decompile(selectors)
assert [key for key, source in results] == selectors
assert len({source for key, source in results}) == 1
assert all(found == f for key, found in gh.function(selectors))
assert [resolved for key, resolved in gh.address([selectors[0], selectors[1], selectors[2], a])] == [a]*4
print('all function and address selectors verified')
""")

    def test_13_interior_address_requires_explicit_resolution(self):
        self.execute("""
f = gh.functions(min_size=4, limit=1)[0]
a = f.getEntryPoint().add(1)
assert f.getBody().contains(a)
assert gh.function([a])[0][1] == f
for value in [int(a.getOffset()), str(a), a]:
    try:
        gh.decompile([value])
    except ValueError as error:
        assert str(f.getEntryPoint()) in str(error)
        assert 'gh.function' in str(error)
    else:
        raise AssertionError('interior address silently accepted')
assert gh.decompile([gh.function([a])[0][1]])[0][1]
print('explicit containing-function resolution verified')
""")

    def test_14_outside_memory_write_rolls_back(self):
        before = self.execute(f'print(repr(gh.get_comment([{self.address}])[0][1]))')
        code = f"gh.set_comment([{self.address}, 0x12345678], '__must_rollback')"
        failure = call('--target', self.a, 'exec', '--write', code=code, check=False)
        self.assertNotEqual(failure.returncode, 0)
        p = Path(failure.stderr.strip())
        detail = p.read_text()
        self.assertIn('outside program memory', detail)
        self.assertIn('item 1', detail)
        p.unlink()
        self.assertEqual(self.execute(f'print(repr(gh.get_comment([{self.address}])[0][1]))'), before)
        self.execute("""
a = gh.address([0x12345678])[0][1]
assert not program.getMemory().contains(a)
assert gh.get_comment([a])[0][1] is None
for mutate in [lambda: gh.set_comment([a], 'outside'),
               lambda: gh.rename_label([a], '__outside_memory'),
               lambda: gh.apply_type([a], 'byte')]:
    try:
        mutate()
    except ValueError as error:
        assert 'outside program memory' in str(error)
    else:
        raise AssertionError('outside-memory mutation accepted')
assert program.getSymbolTable().getPrimarySymbol(a) is None
assert gh.get_comment([a])[0][1] is None
print('outside-memory mutations rejected')
""", write=True)

    def test_15_head_reports_cancellation(self):
        code = 'import time\nfor n in range(30):\n print(n,flush=True)\n time.sleep(.1)'
        result = subprocess.run(['bash', '-c',
            f'{CLI} --target {self.a} exec | head -2; status=("${{PIPESTATUS[@]}}"); '
            'printf "cli_status=%s head_status=%s\\n" "${status[0]}" "${status[1]}" >&2; '
            'exit "${status[0]}"'], input=code, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stdout, '0\n1\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('CANCEL_REQUESTED:', result.stderr)
        self.assertIn('cli_status=1 head_status=0', result.stderr)
        job = result.stderr.split('cancellation requested for job ')[1].splitlines()[0]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = call('--target', self.a, 'jobs', job).stdout.split('\t')[1]
            if state == 'cancelled':
                break
            time.sleep(.05)
        self.assertEqual(state, 'cancelled')

    def test_16_decompile_line_addresses(self):
        self.execute("""
addresses = [f.getEntryPoint() for f in gh.functions(limit=3)]
plain = gh.decompile(addresses)
mapped = gh.decompile(addresses, with_addresses=True)
assert [key for key, rows in mapped] == addresses
assert gh.decompile([], with_addresses=True) == []
for (key, rows), (_, source) in zip(mapped, plain, strict=True):
    function = gh.function([key])[0][1]
    assert [row['line'] for row in rows] == list(range(1, len(rows)+1))
    assert [row['text'] for row in rows] == source.splitlines()
    assert any(row['addresses'] for row in rows)
    assert any(not row['addresses'] for row in rows)
    for row in rows:
        addresses = row['addresses']
        assert isinstance(addresses, list)
        assert len(addresses) == len(set(addresses))
        for address in addresses:
            assert function.getBody().contains(address)
            assert program.getListing().getInstructionContaining(address) is not None
print('source lines and instruction address mappings verified')
""")
        self.execute("""
f = gh.functions(limit=1)[0]
transaction = program.startTransaction('temporary decompile comment verification')
try:
    gh.set_comment([f.getEntryPoint()], 'first line\\nsecond line\\nthird line', kind='PLATE')
    source = gh.decompile([f])[0][1]
    rows = gh.decompile([f], with_addresses=True)[0][1]
    assert [row['text'] for row in rows] == source.splitlines()
    assert 'first line' in source and 'third line' in source
finally:
    program.endTransaction(transaction, False)
print('multiline comment line alignment verified')
""", write=True)

    def test_17_decompiler_reuse_and_parallel_leases(self):
        code = f'gh.decompile([{self.address}]); print(sorted(id(i) for i in gh._decompilers._idle))'
        self.execute('gh._decompilers.clear()')
        first = self.execute(code)
        self.assertEqual(self.execute(code), first)
        script = f"""
import time
with gh._decompilers.lease() as interface:
    f = gh.function([{self.address}])[0][1]
    result = interface.decompileFunction(f, 30, monitor)
    assert result.decompileCompleted()
    print(id(interface), flush=True)
    time.sleep(.7)
"""
        a = spawn(self.a, script)
        first_id = a.stdout.readline().strip()
        b = spawn(self.a, script)
        second_id = b.stdout.readline().strip()
        self.assertNotEqual(first_id, second_id)
        for process in [a, b]:
            out, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, err)
        self.assertEqual(self.execute('print(len(gh._decompilers._idle))'), '2\n')

    def test_18_write_refreshes_decompiler_state(self):
        before = self.execute(f'print(gh.decompile([{self.address}])[0][1])')
        self.execute(f"""
from ghidra.program.model.symbol import SourceType
f = gh.function([{self.address}])[0][1]
assert not gh._decompilers._idle
transaction = program.startTransaction('temporary pooled decompiler verification')
try:
    gh.decompile([f])
    assert not gh._decompilers._idle
    f.setName('__pool_write_change', SourceType.USER_DEFINED)
    assert '__pool_write_change' in gh.decompile([f])[0][1]
finally:
    program.endTransaction(transaction, False)
assert not gh._decompilers._idle
""", write=True)
        self.assertEqual(self.execute('print(len(gh._decompilers._idle))'), '0\n')
        self.assertEqual(self.execute(f'print(gh.decompile([{self.address}])[0][1])'), before)

    def test_19_execution_failure_clears_idle_decompilers(self):
        failure = call('--target',self.a,'exec',code=f'gh.decompile([{self.address}]); raise RuntimeError("pool failure")',check=False)
        self.assertNotEqual(failure.returncode,0)
        Path(failure.stderr.strip()).unlink()
        self.assertEqual(self.execute('print(len(gh._decompilers._idle))'), '0\n')
        self.assertTrue(self.execute(f'print(bool(gh.decompile([{self.address}])[0][1]))').strip() == 'True')

    def test_20_cancelled_lease_is_discarded(self):
        self.execute('gh._decompilers.clear()')
        process = spawn(self.a, f"""
with gh._decompilers.lease() as interface:
    f = gh.function([{self.address}])[0][1]
    assert interface.decompileFunction(f,30,monitor).decompileCompleted()
    print('borrowed',flush=True)
    while True:
        check_cancelled()
""")
        self.assertEqual(process.stdout.readline().strip(), 'borrowed')
        jobs=call('--target',self.a,'jobs').stdout.splitlines()
        active=[row.split('\t')[0] for row in jobs if '\trunning\t' in row]
        self.assertEqual(len(active),1)
        call('--target',self.a,'cancel',active[0])
        out,err=process.communicate(timeout=10)
        self.assertNotEqual(process.returncode,0)
        detail=Path(err.strip())
        self.assertIn('CANCELLED',detail.read_text())
        detail.unlink()
        self.assertEqual(self.execute('print(len(gh._decompilers._idle))'),'0\n')
        self.assertEqual(self.execute(f'print(bool(gh.decompile([{self.address}])[0][1]))'),'True\n')

if __name__ == '__main__':
    unittest.main(verbosity=2)
