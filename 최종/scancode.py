#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
Basic virtual scancode mapping
"""

_SCANCODE_QWERTY_ = {
    0x10 : "q",
    0x11 : "w",
    0x12 : "e",
    0x13 : "r",
    0x14 : "t",
    0x15 : "y",
    0x16 : "u",
    0x17 : "i",
    0x18 : "o",
    0x19 : "p",
    0x1e : "a",
    0x1f : "s",
    0x20 : "d",
    0x21 : "f",
    0x22 : "g",
    0x23 : "h",
    0x24 : "j",
    0x25 : "k",
    0x26 : "l",
    0x2c : "z",
    0x2d : "x",
    0x2e : "c",
    0x2f : "v",
    0x30 : "b",
    0x31 : "n",
    0x32 : "m",
    
    0x01 : "Esc",
    0x02 : "1!",
    0x03 : "2@",
    0x04 : "3#",
    0x05 : "4$",
    0x06 : "5%E",
    0x07 : "6^",
    0x08 : "7&",
    0x09 : "8*",
    0x0a : "9(",
    0x0b : "0)",
    0x0c : "-_",
    0x0d : "=+",
    0x0e : "Backspace",
    0x08 : "Esc",
    0x08 : "Esc",
    0x0f :'Tab', 
    0x1a :"[{", 
    0x1b :"]}",
    0x1d :'LCtrl',
    0x29 :'`~',
    0x2a :'LShift',
    0x38 :'LAlt', 
    0x39 :'Space bar',
    0x3a :'CapsLock',
    0x33 :",<", 
    0x34 :".>", 
    0x35 :"/?", 
    0x36 :"RShift",
    0x2b :"\|",
    0x3b :'F1', 0x3c :'F2', 0x3d :'F3', 0x3e :'F4', 0x3f :'F5', 0x40 :'F6', 0x41 :'F7', 0x42 :'F8', 0x43 :'F9', 0x44 :'F10',
    0x45 :'NumLock',
    0x46 :'ScrollLock',
    0x47 :'Keypad-7/Home', 0x48 :"Keypad-8/Up", 0x49 :"Keypad-9/PgUp",0x27 :';:', 0x28 :"\'\"",
    0x1c : "Enter"
}
        
def scancodeToChar(code):
    """
    @summary: try to convert native code to char code
    @return: char
    """
    if not _SCANCODE_QWERTY_.has_key(code):
        return "<scancode %x>"%code
    return _SCANCODE_QWERTY_[code];