#!/usr/bin/env python3
# coding=utf-8
# python version 3.7 by-6time

import os, sys


def domain():
    with open("1.txt", "r", encoding="utf-8") as f1:
        httplist = f1.readlines()
    with open("2.txt", "r", encoding="utf-8") as f2:
        urllist = f2.readlines()
    for line1 in httplist:
        for line2 in urllist:
            if line2[0] == "/":
                line2 = line2[1:]
            print(line1.strip().rstrip() + line2.strip().rstrip())


if __name__ == "__main__":
    print("""
    枚举合并
    """)
    # _ok = input('已确认更改信息?(y/n)')
    # os.system('pause')
    domain()
