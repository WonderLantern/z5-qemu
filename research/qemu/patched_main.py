# SPDX-License-Identifier: GPL-2.0-or-later
"""核对自建补丁固件（EG165050.BIN + 同名 .json 报告）后才允许模拟器运行。

主模块 = 正文 + 末尾 2 字节 CRC（整体 crc_hqx 余数为 0）。补丁引擎的报告列出每处改动（偏移、原字节、新字节）
和每段追加（偏移、长度、SHA-256，从原 CRC 位置开始连续追加），最后重新写 2 字节 CRC。
这里用原厂 MAIN 加报告逐字节解释补丁镜像：任何未声明的差异、原字节不符、哈希或 CRC 不对都拒绝。
"""
import binascii
import hashlib


def verify(stock, patched, report, stock_sha256):
    sha = lambda b: hashlib.sha256(b).hexdigest()
    if sha(stock) != stock_sha256 or report['input']['sha256'] != stock_sha256 or report['input']['size'] != len(stock):
        raise ValueError('report input is not the stock C1.50 MAIN')
    if report['output']['sha256'] != sha(patched) or report['output']['size'] != len(patched):
        raise ValueError('patched image does not match the report output hash/size')
    if binascii.crc_hqx(stock, 0) or binascii.crc_hqx(patched, 0):
        raise ValueError('module CRC residue is not zero')
    body = len(stock) - 2
    rebuilt = bytearray(stock[:body])
    for edit in report['edits']:
        off = int(edit['offset'], 16)
        old, new = bytes.fromhex(edit['expected']), bytes.fromhex(edit['replacement'])
        if len(old) != len(new) or off + len(old) > body or rebuilt[off:off + len(old)] != old:
            raise ValueError(f"edit {edit['name']}: original bytes differ or overlap the CRC/appends")
        rebuilt[off:off + len(new)] = new
    for append in sorted(report['appends'], key=lambda a: int(a['offset'], 16)):
        off, size = int(append['offset'], 16), append['size']
        if off < len(rebuilt):
            raise ValueError(f"append {append['name']} overlaps earlier data")
        padding = patched[len(rebuilt):off]                  # alignment padding must be zeros
        if any(padding):
            raise ValueError('non-zero padding before an append')
        rebuilt += padding
        chunk = patched[off:off + size]
        if len(chunk) != size or sha(chunk) != append['sha256']:
            raise ValueError(f"append {append['name']} hash mismatch")
        rebuilt += chunk
    if len(rebuilt) + 2 != len(patched) or bytes(rebuilt) != patched[:-2]:
        raise ValueError('patched image has undeclared differences')
    return dict(stock_sha256=stock_sha256, patched_sha256=sha(patched), size=len(patched),
                edits=[(e['name'], e['address']) for e in report['edits']],
                appends=[(a['name'], a['address'], a['size']) for a in report['appends']],
                features=[f['name'] for f in report.get('features', [])])
