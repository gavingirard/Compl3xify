import re
string = input("String to encode > ")
hex_str = "".join(hex(ord(x))[2:]for x in string)
print("".join(f"\\x{i}"for i in re.findall("..", hex_str)))
input()