"""
A minimal Brainfuck interpreter, just to run dlp/.soul.bf

    python examples/run_easter_egg.py
"""

import re
from pathlib import Path


def run_brainfuck(code: str) -> str:
    code = re.sub(r"[^+\-.\[\]<>]", "", code)
    tape = [0] * 30000
    ptr = 0
    out = []
    i = 0
    while i < len(code):
        c = code[i]
        if c == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif c == ">":
            ptr += 1
        elif c == "<":
            ptr -= 1
        elif c == ".":
            out.append(chr(tape[ptr]))
        elif c == "[" and tape[ptr] == 0:
            depth = 1
            while depth:
                i += 1
                depth += {"[": 1, "]": -1}.get(code[i], 0)
        elif c == "]" and tape[ptr] != 0:
            depth = 1
            while depth:
                i -= 1
                depth += {"]": 1, "[": -1}.get(code[i], 0)
        i += 1
    return "".join(out)


if __name__ == "__main__":
    egg_path = Path(__file__).parent.parent / "dlp" / ".soul.bf"
    lines = egg_path.read_text().splitlines()
    bf_line = next(l for l in lines if l.strip().startswith("+"))
    print(run_brainfuck(bf_line))
