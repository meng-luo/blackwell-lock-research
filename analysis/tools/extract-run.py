"""从 NVIDIA .run （makeself）里只抽取固件文件，不展开整个 1 GB 驱动树。"""
import gzip, io, lzma, bz2, sys, tarfile, os, re

RUN = os.environ.get("NVIDIA_RUN", "NVIDIA-Linux-x86_64-610.43.03.run")
OUT = os.environ.get("FW_OUT", "linux-fw")

MAGICS = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
]

def find_payloads(path):
    """找脚本之后的所有压缩流起点。"""
    size = os.path.getsize(path)
    hits = []
    with open(path, "rb") as f:
        # 脚本部分通常 < 1 MB，先读前 4 MB 定性
        head = f.read(4 * 1024 * 1024)
        for magic, name in MAGICS:
            start = 0
            while True:
                i = head.find(magic, start)
                if i < 0:
                    break
                hits.append((i, name))
                start = i + 1
                if len(hits) > 40:
                    break
        # 文件尾附近也可能有真正的 payload
        f.seek(max(0, size - 512 * 1024 * 1024))
        tailoff = f.tell()
        tail = f.read()
        for magic, name in MAGICS:
            start = 0
            while True:
                i = tail.find(magic, start)
                if i < 0:
                    break
                hits.append((tailoff + i, name))
                start = i + 1
                if len(hits) > 80:
                    break
    # 去重排序
    return sorted(set(hits))

def try_tar(path, off, comp):
    """尝试从 off 处当作压缩 tar 打开，返回 tarfile 或 None。"""
    f = open(path, "rb")
    f.seek(off)
    try:
        if comp == "gzip":
            stream = gzip.GzipFile(fileobj=f)
        elif comp == "xz":
            stream = lzma.LZMAFile(f)
        elif comp == "bzip2":
            stream = bz2.BZ2File(f)
        else:
            return None
        return tarfile.open(fileobj=stream, mode="r|")
    except Exception:
        f.close()
        return None

def main():
    if not os.path.exists(RUN):
        sys.exit(f"missing {RUN}")
    print(f"file: {RUN}  ({os.path.getsize(RUN):,} bytes)")
    hits = find_payloads(RUN)
    print(f"压缩流候选 {len(hits)} 个（前 12 个）:")
    for off, name in hits[:12]:
        print(f"  0x{off:09x}  {name}")

    for off, name in hits:
        if name != "gzip":
            continue
        t = try_tar(RUN, off, name)
        if t is None:
            continue
        print(f"\n>>> offset 0x{off:x} ({name}) 可解析为 tar")
        fw = []
        total = 0
        try:
            for m in t:
                total += 1
                n = m.name
                low = n.lower()
                if m.isfile() and (("firmware" in low) or low.endswith(".bin")):
                    fw.append((n, m.size))
                if total % 20000 == 0:
                    print(f"    ...扫描 {total} 项，命中固件 {len(fw)}")
        except Exception as e:
            print(f"    扫描中断: {e}")
        print(f"  共 {total} 项，固件候选 {len(fw)} 个：")
        for n, s in fw[:60]:
            print(f"    {s:12,}  {n}")
        if fw:
            print("\n  >>> 记下这个 offset，下一步做选择性抽取")
            return off, fw
    print("\n未找到可解析的 payload tar")

if __name__ == "__main__":
    main()
