import argparse, os, random, string, itertools, hashlib

parser = argparse.ArgumentParser(description="Obfuscate Python scripts in my signature style.")

parser.add_argument("-f", "-file", help="The path to the file to obfuscate.")
parser.add_argument("-v", "-verbose", help="Show verbose output with more information.", action="store_true")
parser.add_argument("--rev", "--reverse", help="Reverse the ordinals in the source code strings.", action="store_true")
parser.add_argument("--fh", "--fake-hash", help="Include a couple of extra fake hashes along with the real ones.", action="store_true")
parser.add_argument("-l", "-length", type=int, help="Set the length of obfuscated variable names.")
parser.add_argument("-g", "-groupsize", type=int, help="Size to use for ordinal groups in the obfuscation. Recommended to be >100 for decently" +
    " sized scripts. For scripts >2000 lines, a group size of over 500 is almost a requirement.")
parser.add_argument("--seed", help="Seed to use for randomization. Defaults to the content of the input script.")
parser.add_argument("--hashless", help="Required if you are converting to an EXE. Turns off hash checking.", action="store_true")
parser.add_argument("--varchars", help="Letters or characters to choose from when making variables.")
args = parser.parse_args()

target_script = args.f
verbose = args.v
do_reverse = args.rev
add_fake_hashes = args.fh
selected_seed = args.seed if args.seed else -1
hashless = args.hashless
group_size = args.g if args.g else 100
varchars = args.varchars if args.varchars else string.ascii_letters + string.digits
variable_length = args.l if args.l else 10

first_chars = varchars
for digit in string.digits:
    first_chars = first_chars.replace(digit, "")

def log(message):
    if verbose:
        print(f"[Verbose] > {message}")

seed_counter = 0

def create_variable():
    global seed_counter
    random.seed(seed_counter)
    seed_counter += 1
    return random.choice(first_chars) + "".join(random.choices(varchars, k=variable_length - 1))

def obfuscate_script(s: str):

    s = s.replace("\n\n", "\n")

    def grouper(n, iterable, padvalue=None):
        return itertools.zip_longest(*[iter(iterable)]*n, fillvalue=padvalue)

    log("Preparing script for string obfuscation")
    input_segments = []
    for result in grouper(group_size, s, " "):
        input_segments.append("".join(char for char in result))

    add_value_name = create_variable()
    add_value = random.randint(15, 30)

    def build_char_mapping():
        hex_chars = "abcdef"
        remaining = [c for c in "ghijklmnopqrstuvwx"]
        char_mapping = {}
        for hex_let in hex_chars:
            char_mapping[hex_let] = remaining.pop(random.randint(0, len(remaining) - 1))
        for index in range(len("0123456789")):
            char_mapping["0123456789"[index]] = "9876543210"[index]
        return char_mapping

    log("Generating ordinal obfuscation mapping")
    char_map_location = create_variable()
    char_map = build_char_mapping()
    local_char_map = build_char_mapping()
    run_function_char_map = build_char_mapping()

    def make_simple_ordinal(string):
        return ",".join(hex(ord(char) + add_value) for char in string)

    def _create_ordinals(string, ch_map):
        return ("\"" + "".join((char if not char in ch_map else ch_map[char]) for \
                char in ".".join(str(hex(i))[2:] for i in [ord(c) for c in string])) + "\"") \
            if not do_reverse else \
            ("\"" + "".join((char if not char in ch_map else ch_map[char]) for \
                char in ".".join(str(hex(i))[2:] for i in [ord(c) for c in "".join(reversed(string))])) + "\"")

    def make_ordinal(string):
        return _create_ordinals(string, char_map)
    
    def make_source_ordinal(string):
        return _create_ordinals(string, local_char_map)

    def make_run_func_ordinal(string):
        return _create_ordinals(string, run_function_char_map)

    log("Converting the script to ordinals")
    final_segments = [make_source_ordinal(segment) for segment in input_segments]
    aliases = [create_variable() for _ in range(len(final_segments))]
    string_segments = [f"{alias}={''.join(seg for seg in final_segments[index])}" for index, alias in enumerate(aliases)]

    final_seg = string_segments.pop()
    random.shuffle(string_segments)
    string_segments.append(final_seg)

    final = create_variable()
    script = ""

    exec_string = create_variable()
    exec_ordinals = make_ordinal("exec")
    hashlib_string = create_variable()
    hashlib_ordinals = make_ordinal("hashlib")
    sha512_string = create_variable()
    sha512_ordinals = make_ordinal("sha512")
    open_string = create_variable()
    open_ordinals = make_ordinal("open")
    dict_string = create_variable()
    dict_ordinals = make_ordinal("__dict__")
    file_string = create_variable()
    file_ordinals = make_ordinal("__file__")
    utf8_string = create_variable()
    utf8_ordinals = make_ordinal("utf-8")
    read_string = create_variable()
    read_ordinals = make_ordinal("r")
    exit_string = create_variable()
    exit_ordinals = make_ordinal("exit")
    monkey_string = create_variable()
    monkey_ordinals = make_ordinal("\nYou absolute monkey. You need to undo your changes if you want to use the script.\n"
        " [ Protected by AntiMonkey v2.0 ]\n")
    print_string = create_variable()
    print_ordinals = make_ordinal("print")
    len_string = create_variable()
    len_ordinals = make_ordinal("len")
    globals_string = create_variable()
    globals_ordinals = make_ordinal("globals")
    _dict_string = create_variable()
    _dict_ordinals = make_ordinal("dict")
    inspect_string = create_variable()
    inspect_ordinals = make_ordinal("inspect")
    sys_string = create_variable()
    sys_ordinals = make_ordinal("sys")
    modules_string = create_variable()
    modules_ordinals = make_ordinal("modules")
    clear_string = create_variable()
    clear_ordinals = make_ordinal("clear")
    three_string = create_variable()
    zero_string = create_variable()
    one_string = create_variable()

    log("Generating final script")
    add_value_modifier = random.randint(1000, 10000)

    quick_import = create_variable()
    get_builtin = create_variable()
    blank_string = create_variable()
    ordinal_conversion = create_variable()
    original_ordinal_conversion = create_variable()

    arg_var = create_variable()
    script += f"{blank_string}=lambda:{get_builtin}(\"\\x73\\x74\\x72\")();{quick_import}=lambda {arg_var}:__import__({arg_var});{get_builtin}=" \
        f"lambda {arg_var}:getattr({quick_import}(\"\\x62\\x75\\x69\\x6c\\x74\\x69\\x6e\\x73\"),{arg_var});"

    arg_var = create_variable()
    arg_var2 = create_variable()
    script += f"{original_ordinal_conversion}=lambda {arg_var}:{blank_string}().join" \
        f"({get_builtin}(\"\\x63\\x68\\x72\")({arg_var2}-({add_value_name}-{hex(add_value_modifier)}))for {arg_var2} in {arg_var});{ordinal_conversion}=None;"

    none_set_variables = [hashlib_string, sha512_string, open_string, dict_string, file_string, utf8_string, read_string, exit_string, \
        monkey_string, print_string, len_string, _dict_string, inspect_string, sys_string, modules_string, clear_string, three_string, \
        zero_string, one_string]
    
    log("Creating ordinal revealing function")
    s_chr_string = create_variable()
    s_chr_ordinals = make_simple_ordinal("chr")
    s_int_string = create_variable()
    s_int_ordinals = make_simple_ordinal("int")
    s_values_string = create_variable()
    s_values_ordinals = make_simple_ordinal("values")
    s_ord_string = create_variable()
    s_ord_ordinals = make_simple_ordinal("ord")
    s_exec_string = create_variable()
    s_exec_ordinals = make_simple_ordinal("exec")
    s_globals_string = create_variable()
    s_globals_ordinals = make_simple_ordinal("globals")
    s_reversed_string = create_variable()
    s_reversed_ordinals = make_simple_ordinal("reversed")

    ordinal_conversion_exec_string_loc = create_variable()
    get_key_function = create_variable()
    arg_var = create_variable()
    arg_var2 = create_variable()
    arg_var3 = create_variable()
    arg_var4 = create_variable()
    ordinal_conversion_exec_string = f"def {get_key_function}({arg_var},{arg_var2}):\n    for {arg_var3},{arg_var4} in {arg_var}.items():\n" \
        f"        if({arg_var4}=={arg_var2}):\n            return {arg_var3}\n"

    arg_var = create_variable()
    arg_var2 = create_variable()
    arg_var3 = create_variable()
    arg_var4 = create_variable()
    ordinal_conversion_exec_string += f"def {ordinal_conversion}({arg_var}):return " + (f"{blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_reversed_string}))(" if do_reverse else "") + f"{blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_chr_string}))({get_builtin}({original_ordinal_conversion}({s_int_string}))({arg_var2},0x10))for {arg_var2} " \
        f"in {blank_string}().join(({get_key_function}({char_map_location},{arg_var3})if({arg_var3} in getattr({char_map_location}," \
        f"{original_ordinal_conversion}({s_values_string}))())else {arg_var3})for {arg_var3} in {blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_chr_string}))({get_builtin}({original_ordinal_conversion}({s_ord_string}))({arg_var4}))for {arg_var4} in " \
        f"{arg_var})).split(\"\\x2e\"))" + ("))" if do_reverse else "")
    script += f"{ordinal_conversion_exec_string_loc}=[{make_simple_ordinal(ordinal_conversion_exec_string)}];"

    script += "".join(f"{seg};" for seg in string_segments) + f"{exec_string}={exec_ordinals};{add_value_name}=" \
        f"{hex(add_value + add_value_modifier)};{globals_string}={globals_ordinals};"
    script += "".join(f"{var}=" for var in none_set_variables) + "None;"

    script += f"{s_chr_string}=[{s_chr_ordinals}];{s_int_string}=[{s_int_ordinals}];{s_values_string}=[{s_values_ordinals}];{s_ord_string}=" \
        f"[{s_ord_ordinals}];{s_exec_string}=[{s_exec_ordinals}];{s_globals_string}=[{s_globals_ordinals}];{s_reversed_string}=[{s_reversed_ordinals}];"

    temp_char_map = ','.join(f'{original_ordinal_conversion}([{make_simple_ordinal(char)}]):{original_ordinal_conversion}([' \
        f'{make_simple_ordinal(rep)}])' for char, rep in char_map.items())
    script += f"{char_map_location}={{{temp_char_map}}};"

    script += f"{ordinal_conversion_exec_string_loc}=[{make_simple_ordinal(ordinal_conversion_exec_string)}];"
    script += f"{get_builtin}({original_ordinal_conversion}({s_exec_string}))({original_ordinal_conversion}({ordinal_conversion_exec_string_loc})" \
        f",{get_builtin}({original_ordinal_conversion}({s_globals_string}))());"

    log("Hiding exec() variable definitions")
    secret_vars = (f"global {','.join(var for var in none_set_variables)};{hashlib_string}={hashlib_ordinals};{sha512_string}={sha512_ordinals};"
        f"{open_string}={open_ordinals};{dict_string}={dict_ordinals};{file_string}={file_ordinals};{utf8_string}={utf8_ordinals};{read_string}"
        f"={read_ordinals};{exit_string}={exit_ordinals};{monkey_string}={monkey_ordinals};{print_string}={print_ordinals};{len_string}="
        f"{len_ordinals};{_dict_string}={_dict_ordinals};{inspect_string}={inspect_ordinals};{sys_string}={sys_ordinals};{modules_string}="
        f"{modules_ordinals};{clear_string}={clear_ordinals};{three_string}=0x3;{zero_string}=0x0;{one_string}=0x1;")

    secret_vars_name = create_variable()
    script += f"{secret_vars_name}={make_ordinal(secret_vars)};"
    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}({secret_vars_name}),{get_builtin}({ordinal_conversion}(" \
        f"{globals_string}))());"

    do_monkey = create_variable()
    script += f"{do_monkey}=lambda:{get_builtin}({ordinal_conversion}({print_string}))({ordinal_conversion}({monkey_string}));" 

    log("Building shuffling and hash checking functions")
    swap_assignments = [num for num in range(len(aliases) if len(aliases) % 2 == 0 else len(aliases) - 1)]
    random.shuffle(swap_assignments)
    swap_dictionary = []
    script_swap_dict = create_variable()

    for index in range(0, len(swap_assignments), 2):
        aliases[swap_assignments[index]], aliases[swap_assignments[index + 1]] = aliases[swap_assignments[index + 1]], \
            aliases[swap_assignments[index]]
        swap_dictionary.append(f"({hex(swap_assignments[index])},{hex(swap_assignments[index + 1])})")

    script += f"{final}=[{','.join(alias for alias in aliases)}];"
    
    def hash_string(content):
        return hashlib.sha512(content.encode("utf-8")).hexdigest()

    def generate_hash_ordinals(content, variable_name):
        return f"{variable_name}={make_ordinal(content)};"
    
    def get_hash_creation_lambda(lambda_name, s):
        return f"{lambda_name}=lambda:getattr({quick_import}({ordinal_conversion}({hashlib_string})),{ordinal_conversion}({sha512_string}))" \
            f"({get_builtin}({ordinal_conversion}({open_string}))(__file__,{ordinal_conversion}({read_string})).read().split(\"\\x22\\x22\",0x2)[{s}]" \
            f".encode({ordinal_conversion}({utf8_string}))).hexdigest();" if not hashless else f"{lambda_name}=lambda:None;"

    script += create_variable() + "=\"\";"
    first_half_hash_target = script.split("\"\"")[0]
    first_half_hash = hash_string(first_half_hash_target)
    log("First half hash:  [ " + first_half_hash + " ]")

    first_half_hash_location = create_variable()
    second_half_hash_location = create_variable()
    hash_arrays = []
    hash_arrays.append(generate_hash_ordinals(first_half_hash, first_half_hash_location))
    future_hash_split_location = len(script)
    script += create_variable() + "=\"\";"

    first_half_hash_getter_location = create_variable()
    script += first_half_hash_getter_location + "="
    first_half_hash_getter_exec_string = get_hash_creation_lambda(first_half_hash_getter_location, "0x0")
    first_half_hash_getter_exec_string_loc = create_variable()

    second_half_hash_getter_location = create_variable()
    script += second_half_hash_getter_location + "="
    second_half_hash_getter_exec_string = get_hash_creation_lambda(second_half_hash_getter_location, "0x2")
    second_half_hash_getter_exec_string_loc = create_variable()

    first_half_hash_checker_location = create_variable()
    script += first_half_hash_checker_location + "="
    arg_var = create_variable()
    first_half_hash_checker_exec_string = f"{first_half_hash_checker_location}=lambda {arg_var}:{arg_var}!={ordinal_conversion}(" \
        f"{first_half_hash_location})" if not hashless else f"{first_half_hash_checker_location}=lambda {arg_var}:False;"
    first_half_hash_checker_exec_string_loc = create_variable()

    second_half_hash_checker_location = create_variable()
    script += second_half_hash_checker_location + "=None;"
    arg_var = create_variable()
    second_half_hash_checker_exec_string = f"{second_half_hash_checker_location}=lambda {arg_var}:{arg_var}!={ordinal_conversion}(" \
        f"{second_half_hash_location})" if not hashless else f"{second_half_hash_checker_location}=lambda {arg_var}:False;"
    second_half_hash_checker_exec_string_loc = create_variable()

    script += f"{first_half_hash_getter_exec_string_loc}={make_ordinal(first_half_hash_getter_exec_string)};"
    script += f"{first_half_hash_checker_exec_string_loc}={make_ordinal(first_half_hash_checker_exec_string)};"
    script += f"{second_half_hash_getter_exec_string_loc}={make_ordinal(second_half_hash_getter_exec_string)};"
    script += f"{second_half_hash_checker_exec_string_loc}={make_ordinal(second_half_hash_checker_exec_string)};"

    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}({first_half_hash_getter_exec_string_loc}));"
    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}({first_half_hash_checker_exec_string_loc}));"
    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}({second_half_hash_getter_exec_string_loc}));"
    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}({second_half_hash_checker_exec_string_loc}));"

    log("Creating reverse swapping and hash checking functions")
    swap_function_variables = [create_variable() for _ in range(len(swap_dictionary))]
    swap_function_exec_string_locations = [create_variable() for _ in range(len(swap_dictionary))]
    swap_functions_with_first_hash_checkers = list(set(random.choices(swap_function_variables, k=5 if len(swap_function_variables) >= 5 else \
        len(swap_function_variables))))
    swap_functions_with_second_hash_checkers = list(set(random.choices(swap_function_variables, k=5 if len(swap_function_variables) >= 5 else \
        len(swap_function_variables))))
    swap_function_loaders = ""

    perform_swap_exec_string_loc = create_variable()
    swap_arg_var = create_variable()
    perform_swap_exec_code = f"{final}[{script_swap_dict}[{swap_arg_var}][{zero_string}]],{final}[{script_swap_dict}[{swap_arg_var}]" \
            f"[{one_string}]]={final}[{script_swap_dict}[{swap_arg_var}][{one_string}]],{final}[{script_swap_dict}[{swap_arg_var}][{zero_string}]];"
    script += f"{perform_swap_exec_string_loc}={make_ordinal(perform_swap_exec_code)};"

    perform_swap_lambda = create_variable()
    arg_var = create_variable()
    script += f"{perform_swap_lambda}=lambda {arg_var}:{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}(" \
        f"{perform_swap_exec_string_loc}),{get_builtin}({ordinal_conversion}({_dict_string}))({get_builtin}({ordinal_conversion}({globals_string}))" \
            f"(),**{{\"{swap_arg_var}\":{arg_var}}}));"

    for index in range(len(swap_function_variables)):

        string_for_exec = f"{perform_swap_lambda}({hex(index)});"

        if swap_function_variables[index] in swap_functions_with_first_hash_checkers:
            string_for_exec += f"[{do_monkey}(),{get_builtin}({ordinal_conversion}({exit_string}))()]if({first_half_hash_checker_location}(" \
                f"{first_half_hash_getter_location}()))else({blank_string}());"
        else:
            string_for_exec += "".join(random.choices(string.ascii_letters, k=(22 + (7 * variable_length)))) + "=None;"
        
        if swap_function_variables[index] in swap_functions_with_second_hash_checkers:
            string_for_exec += f"[{do_monkey}(),{get_builtin}({ordinal_conversion}({exit_string}))()]if({second_half_hash_checker_location}(" \
                f"{second_half_hash_getter_location}()))else({blank_string}())"
        else:
            string_for_exec += "".join(random.choices(string.ascii_letters, k=(22 + (7 * variable_length)))) + "=None"

        script += f"{swap_function_exec_string_locations[index]}={make_ordinal(string_for_exec)};"
        swap_function_loaders += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}(" \
            f"{swap_function_exec_string_locations[index]}));"

    run_function, layer_1_runner, layer_2_runner, layer_3_runner, layer_4_runner, layer_5_runner = [create_variable() for _ in range(6)]

    log("Building final run functions")
    script += f"{layer_1_runner}=None;"
    run_lambda_exec_string_loc = create_variable()
    monkey_exit_temp = create_variable()
    inspect_location = create_variable()
    caller_location = create_variable()
    arg_var = create_variable()
    temp_exit = create_variable()

    special_ord_conv = create_variable()
    local_char_map_loc = create_variable()

    temp_char_map = ','.join(f'{ordinal_conversion}({make_ordinal(char)}):{ordinal_conversion}(' \
        f'{make_ordinal(rep)})' for char, rep in local_char_map.items())

    arg_var = create_variable()
    arg_var2 = create_variable()
    arg_var3 = create_variable()
    arg_var4 = create_variable()
    run_lambda_exec_string = f"{local_char_map_loc}={{{temp_char_map}}};{script_swap_dict}=[" + ",".join(i for i in swap_dictionary) + "];"

    run_lambda_exec_string += f"\ndef {special_ord_conv}({arg_var}):return " + (f"{blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_reversed_string}))(" if do_reverse else "") + f"{blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_chr_string}))({get_builtin}({original_ordinal_conversion}({s_int_string}))({arg_var2},0x10))for {arg_var2} " \
        f"in {blank_string}().join(({get_key_function}({local_char_map_loc},{arg_var3})if({arg_var3} in getattr({local_char_map_loc}," \
        f"{original_ordinal_conversion}({s_values_string}))())else {arg_var3})for {arg_var3} in {blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_chr_string}))({get_builtin}({original_ordinal_conversion}({s_ord_string}))({arg_var4}))for {arg_var4} in " \
        f"{arg_var})).split(\"\\x2e\"))" + ("))" if do_reverse else "")

    # -> ????????
    run_lambda_exec_string += f"\ndef {monkey_exit_temp}():{do_monkey}();{get_builtin}({ordinal_conversion}({exit_string}))()\ndef {run_function}():" \
        f"{inspect_location}={quick_import}({ordinal_conversion}({inspect_string}));{caller_location}={inspect_location}.getouterframes(" \
        f"{inspect_location}.currentframe(),0x2);[{blank_string}()if({caller_location}[0x0][0x3]==\"{run_function}\")and({caller_location}[0x1][0x3]" \
        f"==\"{layer_5_runner}\")and({caller_location}[0x2][0x3]==\"{layer_4_runner}\")and({caller_location}[0x3][0x3]==\"{layer_3_runner}\")and(" \
        f"{caller_location}[0x4][0x3]==\"{layer_2_runner}\")and({caller_location}[0x5][0x3]==\"{layer_1_runner}\")else({monkey_exit_temp}())];" \
        f"{swap_function_loaders}{get_builtin}({ordinal_conversion}({exec_string}))({blank_string}().join({special_ord_conv}({arg_var})for {arg_var}" \
        f" in {final}),{get_builtin}({ordinal_conversion}({globals_string}))());{temp_exit}={get_builtin}({ordinal_conversion}({exit_string}));getattr" \
        f"(getattr(getattr({quick_import}({ordinal_conversion}({sys_string})),{ordinal_conversion}({modules_string}))[__name__],{ordinal_conversion}" \
        f"({dict_string})),{ordinal_conversion}({clear_string}))();{temp_exit}()"

    run_function_ordinal_conversion_exec_loc = create_variable()
    run_function_ordinal_conversion = create_variable()
    run_function_ordinal_conversion_char_map_loc = create_variable()
    arg_var = create_variable()
    arg_var2 = create_variable()
    arg_var3 = create_variable()
    arg_var4 = create_variable()

    run_function_ordinal_conversion_exec_string = f"def {run_function_ordinal_conversion}({arg_var}):return " + (f"{blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_reversed_string}))(" if do_reverse else "") + f"{blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_chr_string}))({get_builtin}({original_ordinal_conversion}({s_int_string}))({arg_var2},0x10))for {arg_var2} " \
        f"in {blank_string}().join(({get_key_function}({run_function_char_map},{arg_var3})if({arg_var3} in getattr({run_function_char_map}," \
        f"{original_ordinal_conversion}({s_values_string}))())else {arg_var3})for {arg_var3} in {blank_string}().join({get_builtin}(" \
        f"{original_ordinal_conversion}({s_chr_string}))({get_builtin}({original_ordinal_conversion}({s_ord_string}))({arg_var4}))for {arg_var4} in " \
        f"{arg_var})).split(\"\\x2e\"))" + ("))" if do_reverse else "")
    
    temp_char_map = ','.join(f'{original_ordinal_conversion}([{make_simple_ordinal(char)}]):{original_ordinal_conversion}([' \
        f'{make_simple_ordinal(rep)}])' for char, rep in run_function_char_map.items())
    script += f"{run_function_ordinal_conversion_char_map_loc}={{{temp_char_map}}};"
    
    script += f"{run_function_ordinal_conversion}=None;"
    script += f"{run_function_ordinal_conversion_exec_loc}={make_ordinal(run_function_ordinal_conversion_exec_string)};"
    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}({run_function_ordinal_conversion_exec_loc}));"

    script += f"{run_lambda_exec_string_loc}={make_run_func_ordinal(run_lambda_exec_string)};"

    stack_protection_string_loc = create_variable()
    stack_protection_string = f"def {layer_5_runner}():{run_function}()\ndef {layer_4_runner}():{layer_5_runner}()\ndef {layer_3_runner}():" \
        f"{layer_4_runner}()\ndef {layer_2_runner}():{layer_3_runner}()\ndef {layer_1_runner}():{layer_2_runner}()"
    script += f"{stack_protection_string_loc}={make_ordinal(stack_protection_string)};"

    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({run_function_ordinal_conversion}({run_lambda_exec_string_loc}));"
    script += f"{get_builtin}({ordinal_conversion}({exec_string}))({ordinal_conversion}({stack_protection_string_loc}));"
    script += f"{layer_1_runner}()"

    second_half_hash_target = script.split("\"\"")[2]    
    second_half_hash = hashlib.sha512(second_half_hash_target.encode("utf-8")).hexdigest()
    log("Second half hash: [ " + second_half_hash + " ]")
    hash_arrays.append(f"{second_half_hash_location}={make_ordinal(second_half_hash)};")
    if add_fake_hashes:
        hash_arrays.extend(generate_hash_ordinals(hash_string(create_variable()), create_variable()) for _ in range(3))
    random.shuffle(hash_arrays)
    script = script[:future_hash_split_location] + "".join(h for h in hash_arrays) + script[future_hash_split_location:]

    return script

if __name__ == "__main__":
    try:
        open(target_script, "r").close()
    except:
        print("Please give a valid path to a file for obfuscation.")
        exit()

    with open(target_script, "r") as in_file:
        log("Opening '" + target_script + "' as the target script") 
        location = os.path.dirname(in_file.name)
        in_script = in_file.read()
        if selected_seed == -1:
            random.seed(in_script)
        else:
            random.seed(selected_seed)
        seed_counter = random.randint(1000, 10000)
        obfuscated_script = obfuscate_script(in_script)

    if not "Obfuscated" in os.listdir(location if not location == "" else None):
        log("Creating the directory 'Obfuscated' for output")
        os.mkdir(os.path.join(location, "Obfuscated"))
        
    out_location = os.path.join(location, "Obfuscated", "OBF_" + os.path.basename(target_script))
    with open(out_location, "w+") as out_file:
        log("Writing the obfuscated output script to " + out_location)
        out_file.write(obfuscated_script)
    print("Obfuscation complete!")