#!/usr/bin/env python
import sys
import os
import re
import argparse
import r2pipe

class R2Snowman:
    def __init__(self, fn, nc="/usr/local/bin/nocode"):
        self.filename = fn
        self.nocode = nc
        self.do_decompile()
        self.do_get_sym()

    def do_decompile(self):
        prog = "{nocode} {fn}".format(nocode=self.nocode, fn=self.filename)
        self.decompiled = os.popen(prog).read().strip()
        self.decompiled_splited = self.decompiled.strip().split("\n")

    def get_decompile(self):
        return self.decompiled

    def do_get_sym(self):
        prog = "{nocode} --print-symbols {fn}".format(nocode=self.nocode, fn=self.filename)
        hasil = os.popen(prog).read()
        self.symbol = self.parse_symbol(hasil)

    def get_sym(self):
        return self.symbol

    def parse_symbol(self, str_sym):
        sp = str_sym.strip().split("\n")
        sps = []
        syms = []
        for p in sp:
            sps += [p.split(", ")]
        for s in sps:
            sym =  {}
            sym['name'] = re.match(r"^symbol name = \'(.*)'$", s[0]).group(1)
            sym['type'] = re.match(r"^type = (.*)", s[1]).group(1)
            sym['value'] = re.match(r"^value = (.*)", s[2]).group(1)
            sym['section'] = re.match(r"^section =?(.*)", s[3]).group(1)
            syms += [sym]
        return syms

    def get_func_sym(self):
        funcs = []
        for sym in self.symbol:
            if sym['type'] == 'Function':
                funcs += [sym['name']]
        return funcs

    def get_func_source(self):
        reg = "[a-zA-Z0-9_-]+((\[\])+|(\*)+)? (fun_[0-9a-f]{0,16})\((.*)\) \{$"
        funcs = []
        for line in self.decompiled_splited:
            regex = re.match(reg, line)
            if regex:
                funcs += [regex.group(4)]
        return funcs

    def get_funcs(self):
        return self.get_func_sym() + self.get_func_source()

    def get_func_loc(self, fname):
        reg = "[a-zA-Z0-9_-]+((\[\])+|(\*)+)? {f}\((.*)\) \{{$"
        d_splited = self.decompiled_splited
        res = (-1, -1)
        ln = 0
        for l in d_splited:
            if re.match(reg.format(f=fname), l):
                for i in range(ln, len(d_splited)):
                    if d_splited[i] == '}':
                        break
                start_l = ln
                end_l = i
                res = (start_l, end_l)
                break
            ln += 1
        return res

    def get_line_func(self):
        ln = 0
        fs = self.get_funcs()
        func_n = {}
        reg = "[a-zA-Z0-9_-]+((\[\])+|(\*)+)? {f}\((.*)\) \{{$"
        for f in fs:
            h = self.get_func_loc(f)
            if h == (-1, -1):
                print("Function {0} not found".format(f))
            else:
                print("Function {0} match on line {1} until line {2}".format(f, h[0], h[1]))

    def do_decompile_func(self, f):
        h = self.get_func_loc(f)
        if h == (-1, -1):
            return "Can't decompile function {0}".format(f)
        code = self.decompiled_splited[h[0]:h[1]+1]
        return "\n".join(code)
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", type=str, default=None, nargs="?")
    parser.add_argument("-f", "--func", type=str, default=None, nargs="?")
    parser.add_argument("-l", "--list", action="store_true")
    args = parser.parse_args()
    filename = args.binary
    func = args.func
    if not filename:
        try:
            r2 = r2pipe.open("#!pipe")
            filename = str(r2.cmd("e file.path"))
        except:
            print("Can't open filename or radare session")
            sys.exit()
    dc = R2Snowman(filename)
    if func == None and not args.list:
        print(dc.get_decompile())
    elif func:
        print(dc.do_decompile_func(func))
    elif args.list:
        funcs = dc.get_funcs()
        for f in funcs:
            print("]- {}".format(f))

if __name__ == '__main__':
    main()
