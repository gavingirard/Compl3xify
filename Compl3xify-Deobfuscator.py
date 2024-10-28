import argparse, os

parser = argparse.ArgumentParser(description="Deobfuscate Compl3xify Programs.")

parser.add_argument("-f", "-file", help="The path to the file to deobfuscate.")
args = parser.parse_args()

target_script = args.f

def deobfuscate_script(script: str):

    try:

        add_value_target = script.split("=0x")[1].split(";")[0]
        add_modifier_target = script.split("-0x")[1].split(")")[0]
        add_value = int(add_value_target, 16) - int(add_modifier_target, 16)

        main_char_map_target = script.split("{")[1].split("}")[0]
        main_char_map_pairs = main_char_map_target.split(",")
        main_char_map = {item.split("0x")[1].split("]")[0]:item.split("0x")[2].split("]")[0] for item in main_char_map_pairs}
        main_char_map = {chr(int(value, 16) - add_value):chr(int(key, 16) - add_value) for key, value in main_char_map.items()}

        char_map_target = script.split("{")[3].split("}")[0]
        char_map_pairs = char_map_target.split(",")
        char_map = {item.split("0x")[1].split("]")[0]:item.split("0x")[2].split("]")[0] for item in char_map_pairs}
        char_map = {chr(int(value, 16) - add_value):chr(int(key, 16) - add_value) for key, value in char_map.items()}

        run_lambda_string = script.split("\"")[-4:-3][0]
        run_lambda_content = "".join(chr(int("".join(char_map[char] for char in item), 16)) for item in run_lambda_string.split("."))
        uses_reversed_strings = not "__name__" in run_lambda_content
        run_lambda_content = "".join(reversed(run_lambda_content)) if uses_reversed_strings else run_lambda_content

        source_code_strings = script.split("=None;")[1].split("];")[1].split(";")[:-4]
        source_code_map = {item.split("=")[0]:item.split("=")[1][1:-1] for item in source_code_strings}
        source_code_map = {key:(".".join(reversed(value.split("."))) if uses_reversed_strings else value) for key, value in source_code_map.items()}
        source_code_array = script.split("=[")[10].split("]")[0].split(",")
        source_code_string_array = [source_code_map[variable] for variable in source_code_array]

        source_char_map_target = run_lambda_content.split("={")[1].split("}")[0]
        source_char_map_pairs = source_char_map_target.split(",")
        source_char_map = {item.split("\"")[1:2][0]:item.split("\"")[3:4][0] for item in source_char_map_pairs}
        source_char_map = {"".join("".join(main_char_map[letter] for letter in item) for item in key):"".join("".join(main_char_map[letter] \
            for letter in item) for item in value) for key, value in source_char_map.items()}
        source_char_map = {chr(int(value, 16)):chr(int(key, 16)) for key, value in source_char_map.items()}
    
        swap_dict_pairs = run_lambda_content.split("[")[1].split("]")[0][1:-1].split("),(")
        swap_list = [(int(item.split("0x")[1].split(",")[0], 16), int(item.split("0x")[2], 16)) for item in swap_dict_pairs]
        for start, dest in swap_list:
            source_code_string_array[start], source_code_string_array[dest] = source_code_string_array[dest], source_code_string_array[start]
        joined_script = ".".join(segment for segment in source_code_string_array)
        final_script = "".join(chr(int("".join(source_char_map[letter] for letter in segment), 16)) for segment in joined_script.split("."))

        return final_script
    
    except:

        print("Not a properly formatted Compl3xify output script!")
        exit()

if __name__ == "__main__":
    
    try:
        open(target_script, "r").close()
    except:
        print("Please give a valid path to a file for deobfuscation.")
        exit()

    with open(target_script, "r") as in_file:
        location = os.path.dirname(in_file.name)
        in_script = in_file.read()
        deobfuscated_script = deobfuscate_script(in_script)

    if not "Deobfuscated" in os.listdir(location if not location == "" else None):
        os.mkdir(os.path.join(location, "Deobfuscated"))
        
    out_location = os.path.join(location, "Deobfuscated", "DEOBF_" + os.path.basename(target_script))
    with open(out_location, "w+") as out_file:
        out_file.write(deobfuscated_script)
    print("Deobfuscation complete!")