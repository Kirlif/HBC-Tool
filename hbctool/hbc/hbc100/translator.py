# Copyright 2026 github.com/Kirlif

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import pathlib
import json
from hbctool.util import *

basepath = pathlib.Path(__file__).parent.absolute()

operand_type = {
    "Reg8": (1, to_uint8, from_uint8),
    "Reg32": (4, to_uint32, from_uint32),
    "UInt8": (1, to_uint8, from_uint8),
    "UInt16": (2, to_uint16, from_uint16),
    "UInt32": (4, to_uint32, from_uint32),
    "Addr8": (1, to_int8, from_int8),
    "Addr32": (4, to_int32, from_int32),
    "Reg32": (4, to_uint32, from_uint32),
    "Imm32": (4, to_uint32, from_uint32),
    "Double": (8, to_double, from_double),
}


f = open(f"{basepath}/data/opcode.json", "r")
opcode_operand = json.load(f)
opcode_mapper = list(opcode_operand.keys())
opcode_mapper_inv = {}
for i, v in enumerate(opcode_mapper):
    opcode_mapper_inv[v] = i

f.close()


def disassemble(bc):
    i = 0
    insts = []
    while i < len(bc):
        opcode = opcode_mapper[bc[i]]
        i += 1
        inst = (opcode, [])
        operand_ts = opcode_operand[opcode]
        for oper_t in operand_ts:
            is_str = oper_t.endswith(":S")
            if is_str:
                oper_t = oper_t[:-2]

            size, conv_to, _ = operand_type[oper_t]
            val = conv_to(bc[i : i + size])
            inst[1].append((oper_t, is_str, val))
            i += size

        insts.append(inst)

    return insts


def assemble(fid, insts):
    bc = []
    for opcode, operands in insts:
        op = opcode_mapper_inv[opcode]
        bc.append(op)
        assert len(opcode_operand[opcode]) == len(
            operands
        ), f"Function {fid}: Malicious instruction: {op}, {operands}"
        for oper_t, _, val in operands:
            assert (
                oper_t in operand_type
            ), f"Function {fid}: Malicious operand type: {oper_t}"
            _, _, conv_from = operand_type[oper_t]
            bc += conv_from(val)
    return bc
