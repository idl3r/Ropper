# coding=utf-8
#
# Copyright 2014 Sascha Schirra
#
# This file is part of Ropper.
#
# Ropper is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ropper is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ropper.common.utils import *
from ropper.common.error import *
from ropper.common.enum import Enum
from ropper.arch import x86
from multiprocessing import Process, Pool, Queue, cpu_count, current_process, JoinableQueue
from .gadget import Gadget, GadgetType
from binascii import hexlify, unhexlify
from struct import pack
import re
import struct
import sys
import capstone

import cProfile

# Optional keystone support
try:
    import keystone
except:
    pass


class Format(Enum):
    _enum_ = 'RAW STRING HEX'

class Ropper(object):

    def __init__(self, callback=None):
        """
        callback function signature:
        def callback(section, gadgets, progress)
        """
        super(Ropper, self).__init__()
        self.__callback = callback
        self.__cs = None


    def __getCs(self, arch):
        if not self.__cs or self.__cs.arch != arch.arch or self.__cs.mode != arch.mode:
            self.__cs = capstone.Cs(arch.arch, arch.mode)
        return self.__cs

    def assemble(self, code, arch=x86, format=Format.HEX):
        if 'keystone' not in globals():
            raise RopperError('Keystone is not installed! Please install Keystone. \nLook at http://keystone-engine.org')

        ks = keystone.Ks(arch.ksarch[0], arch.ksarch[1])
        try:
            byte_list =  ks.asm(code.encode('ascii'))[0]
        except BaseException as e:
            raise RopperError(e)

        if not byte_list:
            return "invalid"
        to_return = byte_list

        if format == Format.STRING:
            to_return = '"'
            for byte in byte_list:
                to_return += '\\x%02x' % byte

            to_return += '"'
        elif format == Format.HEX:
            to_return = ''
            for byte in byte_list:
                to_return += '%02x' % byte
        elif format == Format.RAW:
            to_return = ''
            for byte in byte_list:
                to_return += '%s' % chr(byte)

        return to_return

    def disassemble(self, opcode, arch=x86):
        opcode, size= self._formatOpcodeString(opcode, regex=False)
        cs = self.__getCs(arch)

        to_return = ''
        byte_count = 0

        opcode_tmp = opcode

        while byte_count < size:
            old_byte_count = byte_count
            for i in cs.disasm(opcode_tmp,0):
                to_return += '%s %s\n' % (i.mnemonic , i.op_str)
                byte_count += len(i.bytes)

            if old_byte_count == byte_count or byte_count < len(opcode):
                byte_count += 1
                opcode_tmp = opcode[byte_count:]
                to_return += '<invalid>\n'

        return to_return

    def searchJmpReg(self, binary, regs):
        toReturn = []
        Gadget.IMAGE_BASES[binary.fileName] = binary.imageBase
        for section in binary.executableSections:

            gadgets = self._searchJmpReg(section, binary, regs)
            toReturn.extend(gadgets)

        return toReturn


    def _searchJmpReg(self, section, binary, regs):
        if binary.arch.arch != capstone.CS_ARCH_X86:
            raise NotSupportedError(
                'Wrong architecture, \'jmp <reg>\' only supported on x86/x86_64')

        cs = self.__getCs(binary.arch)
        toReturn = []
        Register = Enum('Register', 'ax cx dx bx sp bp si di')

        for reg in regs:
            reg_tmp = reg.strip()[1:]
            if not Register[reg_tmp]:
                raise RopperError('Invalid register: "%s"' % reg)
            insts = [toBytes(0xff , 0xe0 | Register[reg_tmp]), toBytes(0xff, 0xd0 | Register[reg_tmp]),  toBytes(0x50 | Register[reg_tmp] , 0xc3)]

            for inst in insts:
                toReturn.extend(self._searchOpcode(section, binary, inst, len(inst),True))

        return sorted(toReturn, key=lambda x: str(x))



    def _formatOpcodeString(self, opcode, regex=True):
        if len(opcode) % 2 > 0:
            raise RopperError('The length of the opcode has to be a multiple of two')

        opcode = opcode.encode('ascii')
        size = int(len(opcode)/2)
        for b in (b'5c',b'5d',b'5b',b'28',b'29',b'2b',b'2a',b'2e',b'3f'):
           
            if opcode.find(b) % 2 == 0:
                opcode = opcode.replace(b,b'%s%s' % (hexlify(b'\\'),b))

        m = re.search(b'\?', opcode)
        while m:
            if m.start() % 2 == 0:
                char = opcode[m.start()+1]
                if type(char) == int:
                    char = chr(char)
                if char == '?':
                    opcode = opcode[:m.start()] + hexlify(b'[\x00-\xff]') +  opcode[m.start()+2:]
                else:
                    raise RopperError('A ? for the highest 4 bit of a byte is not supported (e.g. ?1, ?2, ..., ?a)')
            elif m.start() % 2 == 1:
                char = opcode[m.start()-1]
                if type(char) == int:
                    char = chr(char)
                high = int(char,16)
                start = high << 4
                end  = start + 0xf
                
                opcode = opcode[:m.start()-1] + hexlify(b'['+pack('B',start)+b'-'+pack('B',end)+b']') + opcode[m.start()+1:]

            m = re.search(b'\?', opcode)
        try:
            
            opcode = unhexlify(opcode)
            
        except BaseException as e:
            #raise RopperError(e)
            raise RopperError('Invalid characters in opcode string: %s' % opcode)
        return opcode,size


    def searchInstructions(self, binary, code):
        Gadget.IMAGE_BASES[binary.fileName] = binary.imageBase
        opcode = self.assemble(code, binary.arch)
        return self.searchOpcode(binary, opcode, disass=True)


    def searchOpcode(self, binary, opcode, disass=False):
        Gadget.IMAGE_BASES[binary.fileName] = binary.imageBase
        opcode, size = self._formatOpcodeString(opcode)
        gadgets = []
        for section in binary.executableSections:
            gadgets.extend(self._searchOpcode(section, binary, opcode, size, disass))

        return gadgets


    def _searchOpcode(self, section, binary, opcode, size, disass=False):

        disassembler = self.__getCs(binary.arch)
        toReturn = []
        code = bytearray(section.bytes)
        offset = section.offset
        for match in re.finditer(opcode, code):
            opcodeGadget = Gadget(binary.fileName, section.name, binary.arch)

            if (offset + match.start()) % binary.arch.align == 0:
                if disass:
                    could_disass = False
                    #for i in disassembler.disasm(struct.pack('B' * size, *code[match.start():match.end()]), offset + match.start()):
                    for i in disassembler.disasm(struct.pack('B' * size, *code[match.start():match.end()]), offset + match.start()):
                        opcodeGadget.append(
                            i.address, i.mnemonic , i.op_str, bytes=i.bytes)
                        could_disass = True
                    if not could_disass:
                        continue
                else:
                    opcodeGadget.append(
                        offset + match.start(), hexlify(match.group(0)).decode('utf-8'),bytes=match.group())
            else:
                continue

            toReturn.append(opcodeGadget)

        return toReturn


    def searchPopPopRet(self, binary):
        Gadget.IMAGE_BASES[binary.fileName] = binary.imageBase
        toReturn = []
        for section in binary.executableSections:

            pprs = self._searchPopPopRet(section,binary)
            toReturn.extend(pprs)


        return toReturn

    def _searchPopPopRet(self, section, binary):
        if binary.arch != x86:
            raise NotSupportedError(
                'Wrong architecture, \'pop pop ret\' is only supported on x86')

        disassembler = self.__getCs(binary.arch)
        code = section.bytes
        offset = section.offset
        toReturn = []
        pprs = binary.arch.pprs
        for ppr in pprs:
            for match in re.finditer(ppr, code):
                if (offset + match.start()) % binary.arch.align == 0:
                    pprg = Gadget(binary.fileName,section.name, binary.arch)
                    for i in disassembler.disasm(bytes(bytearray(code)[match.start():match.end()]), offset + match.start()):
                        pprg.append(i.address, i.mnemonic , i.op_str, bytes=i.bytes)
        
                    toReturn.append(pprg)
        return toReturn

    def searchGadgets(self, binary, instructionCount=5, gtype=GadgetType.ALL):
        Gadget.IMAGE_BASES[binary.fileName] = binary.imageBase
        gadgets = []
        for section in binary.executableSections:
            vaddr = binary.imageBase

            if self.__callback:
                self.__callback(section, None, 0)

            if sys.platform.startswith('win'):
                newGadgets = self._searchGadgetsSingle(section=section, binary=binary, instruction_count=instructionCount, gtype=gtype)
            else:
                newGadgets = self._searchGadgetsForked(section=section, binary=binary, instruction_count=instructionCount, gtype=gtype)
            
            gadgets.extend(newGadgets)

        return sorted(gadgets, key=Gadget.simpleInstructionString)

    def _searchGadgetsSingle(self, section, binary, instruction_count=5, gtype=GadgetType.ALL):

        toReturn = []
        code = bytes(bytearray(section.bytes))
        offset = section.offset

        arch = binary.arch

        max_progress = len(code) * len(arch.endings[gtype])

        vaddrs = set()
        for ending in arch.endings[gtype]:
            offset_tmp = 0
            tmp_code = code[:]

            match = re.search(ending[0], tmp_code)
            while match:
                offset_tmp += match.start()
                index = match.start()

                if offset_tmp % arch.align == 0:
                    #for x in range(arch.align, (depth + 1) * arch.align, arch.align): # This can be used if you want to use a bytecount instead of an instruction count per gadget
                    none_count = 0

                    for x in range(0, index, arch.align):
                        code_part = tmp_code[index - x-1:index + ending[1]]
                        gadget, leng = self.__createGadget(arch, code_part, offset + offset_tmp - x, ending,binary.fileName, section.name)
                        if gadget:
                            if leng > instruction_count:
                                break
                            if gadget:
                                if gadget.address not in vaddrs:
                                    vaddrs.update([gadget.address])
                                    toReturn.append(gadget)
                            none_count = 0
                        else:
                            none_count += 1
                            if none_count == arch.maxInvalid:
                                break

                tmp_code = tmp_code[index+arch.align:]
                offset_tmp += arch.align

                match = re.search(ending[0], tmp_code)

                if self.__callback:
                    progress = arch.endings[gtype].index(ending) * len(code) + len(code) - len(tmp_code)
                    self.__callback(section, toReturn, float(progress) / max_progress)

        if self.__callback:
            self.__callback(section, toReturn, 1.0)

        return toReturn

    def _searchGadgetsForked(self, section, binary, instruction_count=5, gtype=GadgetType.ALL):

        to_return = []
        code = bytes(bytearray(section.bytes))
        
        processes = []
        arch = binary.arch

        max_progress = len(code) * len(arch.endings[gtype])

        ending_queue = JoinableQueue()
        gadget_queue = Queue()
        tmp_code = code[:]

        process_count = min(cpu_count()+1, len(arch.endings[gtype]))
        for ending in arch.endings[gtype]:
            ending_queue.put(ending)

        for cpu in range(process_count):
            ending_queue.put(None)

        print("Process count: %d" % process_count)

        proc_id = 0
        for cpu in range(process_count):
            processes.append(Process(target=self.__gatherGadgetsByEndingsProfiling, args=(tmp_code, arch, binary.fileName, section.name, section.offset, ending_queue, gadget_queue, instruction_count, proc_id), name="GadgetSearch%d"%cpu))
            processes[cpu].daemon=True
            processes[cpu].start()

        
        
        count = 0
        ending_count = 0
        if self.__callback:
            self.__callback(section, to_return, 0)
        while ending_count < len(arch.endings[gtype]):
            gadgets = gadget_queue.get()
            if gadgets != None:
                to_return.extend(gadgets)

                ending_count += 1
                if self.__callback:
                    self.__callback(section, to_return, float(ending_count) / len(arch.endings[gtype]))
            
        return to_return

    def gatherGadgetsByEndings(self,code, arch, fileName, sectionName, offset, ending_queue, gadget_queue, instruction_count, proc_id):
        
        #try:
        while True:
            ending = ending_queue.get()
            if ending is None:
                ending_queue.task_done()
                break
            
            # print("__gatherGadgetsByEndings")
            gadgets = self.__gatherGadgetsByEnding(code, arch, fileName, sectionName, offset, ending, instruction_count)
            
            gadget_queue.put(gadgets)
            ending_queue.task_done()
            
            
        #except BaseException as e:
        #    raise RopperError(e)
        
    def test(self, num):
        print(num)
        pass

    def __gatherGadgetsByEndingsProfiling(self,code, arch, fileName, sectionName, offset, ending_queue, gadget_queue, instruction_count, proc_id):
        # cProfile.runctx('self.__gatherGadgetsByEndings(code, arch, fileName, sectionName, offset, ending_queue, gadget_queue, instruction_count, proc_id)', globals(), locals(), 'prof%d.prof' % proc_id)
        # cProfile.runctx('self.test(proc_id)', globals(), locals())
        cProfile.runctx('self.gatherGadgetsByEndings(code, arch, fileName, sectionName, offset, ending_queue, gadget_queue, instruction_count, proc_id)', globals(), locals())

    def __gatherGadgetsByEnding(self, code, arch, fileName, sectionName, offset, ending, instruction_count):
        vaddrs = set()
        # code_part_set = set()
        code_part_sets = {}
        offset_tmp = 0
        
        tmp_code = code[:]
        to_return = []
        match = re.search(ending[0], tmp_code)

        while match:
            offset_tmp += match.start()
            index = match.start()

            if offset_tmp % arch.align == 0:
                #for x in range(arch.align, (depth + 1) * arch.align, arch.align): # This can be used if you want to use a bytecount instead of an instruction count per gadget
                none_count = 0

                # for x in range(0, index+1, arch.align):
                # for x in range((instruction_count - 1) * arch.align, index+1, arch.align):
                # for x in range((instruction_count - 1) * arch.align, instruction_count * arch.align, arch.align):
                for x in range(0, instruction_count * arch.align, arch.align):
                    code_part = tmp_code[index - x:index + ending[1]]
                    code_len = x + 1

                    try:
                        if code_part in code_part_sets[code_len]:
                            continue
                    except KeyError:
                        code_part_sets[code_len] = set()

                    code_part_sets[code_len].add(code_part)

                    gadget, leng = self.__createGadget(arch, code_part, offset + offset_tmp - x , ending, fileName, sectionName)
                    if gadget:
                        if leng > instruction_count:
                            break
                        if gadget:
                            to_return.append(gadget)
                            # print("%d -> %d" % (x, leng))
                        none_count = 0
                    else:
                        none_count += 1
                        if none_count == arch.maxInvalid:
                            break

            tmp_code = tmp_code[index+arch.align:]
            offset_tmp += arch.align

            match = re.search(ending[0], tmp_code)

        # print len(to_return)
        return to_return

    def __setop(self, op, target, other1, other2):
        if op in other1:
            other1.remove(op)
        if op in other2:
            other2.remove(op)
        if op not in target:
            target.add(op)

    def __createGadget(self, arch, code_str, codeStartAddress, ending, binary=None, section=None):
        gadget = Gadget(binary, section, arch)
        hasret = False

        gadget.code_str = code_str  # Raw code bytes

        disassembler = self.__getCs(arch)
        disassembler.detail = True

        # Register status:
        #   i:  input register
        #   b:  bound to input register
        #   c:  controlled register (by input)
        #   x:  clobbered register by other instructions
        #   register can be both input and some other status apparently, but eventually it will be either bound, controlled, clobbered or just irrelevant
        # Global flag:
        #   usable  : if whole gadget is clobbered
        # Transition rules:
        #   ldr, ldp:
        #       if op2/op3 is currently not marked, then mark it input
        #       if op2/op3 is currently input/bound/controlled, then op1/(op1/op2) become controlled
        #   str, stp:
        #       if op2/op3 is not input/bound or controlled, then this instruction implies a uncontrolled write and considered unusable
        #   mov, add, sub:
        #       if op2 is not marked, then op2 is input
        #       op1 is marked as bound if op2 is input/bound, or controlled if op2 is controlled
        #       otherwise op1 is clobberred
        #   movz:
        #       clobber op1
        #   br, blr:
        #       unusable of op1 is clobbered
        #       mark op1 as input if it is not markedl
        #   ldrb, ldrh, adrp:
        #       for now, clobber op1
        #   b, bl:
        #       already bad instructions
        input_regs = set()
        bound_regs = set()
        controlled_regs = set()
        clobbered_regs = set()
        usable = True

        for i in disassembler.disasm(code_str, codeStartAddress):
            (regs_read, regs_write) = i.regs_access()   # that's why we set detail = True

            if (i.mnemonic in ['ldr']):
                # print("ldr %s; %d" % (i.op_str, len(i.operands)))
                op1 = i.reg_name(i.operands[0].reg)
                if op1.startswith('w'):
                    fullsize_op = 'x' + op1[1:]
                    self.__setop(fullsize_op, clobbered_regs, bound_regs, controlled_regs)
                else:
                    if (len(i.operands) == 2) and \
                    (i.operands[1].type == capstone.arm64.ARM64_OP_MEM) and \
                    (i.operands[1].mem.base != 0) and \
                    (i.operands[1].mem.index == 0):
                        # print("ldr %s; %d" % (i.op_str, len(i.operands)))
                        op2 = i.reg_name(i.operands[1].mem.base)

                        if op2 not in (input_regs | bound_regs | controlled_regs | clobbered_regs):
                            input_regs.add(op2)

                        if ((op2 in input_regs) and (op2 not in clobbered_regs)) or \
                        (op2 in bound_regs) or \
                        (op2 in controlled_regs):
                            # op1 be controlled
                            self.__setop(op1, controlled_regs, bound_regs, clobbered_regs)
                        else:
                            # op1 is clobbered
                            self.__setop(op1, clobbered_regs, controlled_regs, bound_regs)
                    else:
                        self.__setop(op1, clobbered_regs, controlled_regs, bound_regs)
            elif (i.mnemonic in ['ldp']):
                op1 = i.reg_name(i.operands[0].reg)
                op2 = i.reg_name(i.operands[1].reg)

                if op1.startswith('w'):
                    fullsize_op = 'x' + op1[1:]
                    self.__setop(fullsize_op, clobbered_regs, bound_regs, controlled_regs)
                    fullsize_op = 'x' + op2[1:]
                    self.__setop(fullsize_op, clobbered_regs, bound_regs, controlled_regs)
                else:
                    if (len(i.operands) == 3) and \
                    (i.operands[2].type == capstone.arm64.ARM64_OP_MEM) and \
                    (i.operands[2].mem.base != 0) and \
                    (i.operands[2].mem.index == 0):
                        # print("ldp %s; %d" % (i.op_str, len(i.operands)))
                        op3 = i.reg_name(i.operands[2].mem.base)

                        if op3 not in (input_regs | bound_regs | controlled_regs | clobbered_regs):
                            input_regs.add(op3)

                        if ((op3 in input_regs) and (op3 not in clobbered_regs)) or \
                        (op3 in bound_regs) or \
                        (op3 in controlled_regs):
                            # op1 be controlled
                            self.__setop(op1, controlled_regs, bound_regs, clobbered_regs)
                            self.__setop(op2, controlled_regs, bound_regs, clobbered_regs)
                        else:
                            # op1 is clobbered
                            self.__setop(op1, clobbered_regs, controlled_regs, bound_regs)
                            self.__setop(op2, clobbered_regs, controlled_regs, bound_regs)
                    else:
                        self.__setop(op1, clobbered_regs, controlled_regs, bound_regs)
                        self.__setop(op2, clobbered_regs, controlled_regs, bound_regs)
            elif (i.mnemonic in ['str', 'stp']):
                pass
            elif (i.mnemonic in ['mov', 'add', 'sub']):
                op1 = i.reg_name(i.operands[0].reg)
                op2 = i.reg_name(i.operands[1].reg)

                if op1.startswith('w'):
                    fullsize_op = 'x' + op1[1:]
                    self.__setop(fullsize_op, clobbered_regs, bound_regs, controlled_regs)
                else:
                    if (i.mnemonic != 'mov') and \
                    (i.operands[2].type != capstone.arm64.ARM64_OP_IMM):
                        self.__setop(op1, clobbered_regs, controlled_regs, bound_regs)
                    else:
                        if op2 not in (input_regs | bound_regs | controlled_regs | clobbered_regs):
                            input_regs.add(op2)
                        if ((op2 in input_regs) and (op2 not in clobbered_regs)) or \
                        (op2 in bound_regs):
                            self.__setop(op1, bound_regs, controlled_regs, clobbered_regs)
                        elif (op2 in controlled_regs):
                            self.__setop(op1, controlled_regs, bound_regs, clobbered_regs)
                        else:
                            self.__setop(op1, clobbered_regs, bound_regs, controlled_regs)
            elif (i.mnemonic in ['br', 'blr']):
                op1 = i.reg_name(i.operands[0].reg)

                if op1 in clobbered_regs:
                    usable = False
                elif (op1 in input_regs) and \
                (op1 not in controlled_regs):
                    usable = False
                elif op1 not in (input_regs | bound_regs | controlled_regs | clobbered_regs):
                    input_regs.add(op1)
            elif (i.mnemonic in ['ldrb', 'ldrh', 'adrp', 'movz']):
                op1 = i.reg_name(i.operands[0].reg)

                if op1.startswith('w'):
                    fullsize_op = 'x' + op1[1:]
                    op1 = fullsize_op
                self.__setop(op1, clobbered_regs, bound_regs, controlled_regs)
            elif (i.mnemonic in ['cbnz', 'tbnz']):
                op1 = i.reg_name(i.operands[0].reg)

                if op1.startswith('w'):
                    fullsize_op = 'x' + op1[1:]
                    op1 = fullsize_op

                # if op1 not in (input_regs | bound_regs | controlled_regs | clobbered_regs):
                #     input_regs.add(op1)
                elif (op1 in input_regs) or \
                (op1 in bound_regs) or \
                (op1 in clobbered_regs):
                    usable = False
            elif (i.mnemonic in ['cbz', 'tbz']):
                op1 = i.reg_name(i.operands[0].reg)

                if op1.startswith('w'):
                    fullsize_op = 'x' + op1[1:]
                    op1 = fullsize_op

                if op1 not in (input_regs | bound_regs | controlled_regs | clobbered_regs):
                    input_regs.add(op1)
                elif (op1 in input_regs) or \
                (op1 in bound_regs) or \
                (op1 in clobbered_regs):
                    usable = False


            # if arch == ropper.arch.ARM64:
            #     str_regs_read = ''
            #     for r in regs_read:
            #         str_regs_read += i.reg_name(r)
            #         str_regs_read += ' '

            #     str_regs_write = ''
            #     for r in regs_write:
            #         str_regs_write += i.reg_name(r)
            #         str_regs_write += ' '

            # for r in i.regs_read:
            #     print("%s " %i.reg_name(r)),
            # print

            if re.match(ending[0], i.bytes):
                hasret = True
            
            if hasret or i.mnemonic not in arch.badInstructions:
                gadget.append(
                    # i.address, i.mnemonic,i.op_str, bytes=i.bytes, regs_read = str_regs_read, regs_write = str_regs_write)
                    i.address, i.mnemonic,i.op_str, bytes=i.bytes)

            if hasret or i.mnemonic in arch.badInstructions:
                break

        gadget.input_regs = input_regs
        gadget.bound_regs = bound_regs
        gadget.controlled_regs = controlled_regs
        gadget.clobbered_regs = clobbered_regs
        gadget.usable = usable


        leng = len(gadget)
        if hasret and leng > 0:
            return gadget,leng
        return None, -1


    def __disassembleBackward(self, section, binary, vaddr,offset, count):
        gadget = Gadget(binary.fileName, section.name, binary.arch)
        counter = 0
        toReturn = None
        code = bytes(bytearray(section.bytes))
        disassembler = self.__getCs(binary.arch)

        while len(gadget) < count:
            gadget = Gadget(binary.fileName, section.name, binary.arch)
            for i in disassembler.disasm(struct.pack('B' * len(code[offset - counter:]), *bytearray(code[offset - counter:])), vaddr-counter):
                gadget.append(i.address, i.mnemonic , i.op_str, i.bytes)
                if i.address == vaddr:
                    toReturn = gadget
                    break
                if i.address > vaddr:
                    if len(gadget) > count:
                        return toReturn
                    gadget = Gadget(binary.fileName, section.name, binary.arch)
                    break


            counter += binary.arch.align
            if offset - counter < 0:
                return toReturn

            if not toReturn:
                toReturn = Gadget(binary.fileName, section.name, binary.arch)
                toReturn.append(vaddr,'bad instructions')
        return toReturn


    def disassembleAddress(self, section, binary, vaddr, offset, count):
        if vaddr % binary.arch.align != 0:
            raise RopperError('The address doesn\'t have the correct alignment')
        Gadget.IMAGE_BASES[binary.fileName] = binary.imageBase
        code = bytes(bytearray(section.bytes))
        disassembler = capstone.Cs(binary.arch.arch, binary.arch.mode)

        if count < 0:
            return self.__disassembleBackward(section, binary, vaddr, offset, count*-1)
        gadget  = Gadget(binary.fileName, section.name, binary.arch)
        c = 0

        for i in disassembler.disasm(struct.pack('B' * len(code[offset:]), *bytearray(code[offset:])), offset):
            gadget.append(i.address, i.mnemonic , i.op_str,bytes=i.bytes)
            c += 1
            if c == count:
                break
        if not len(gadget):
            gadget.append(vaddr,'bad instructions')
        return gadget





def toBytes(*b):
    return bytes(bytearray(b))
