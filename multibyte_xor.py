import argparse
import xordiffstream
import pprint
import yara

def calculate_difference_stream(stream, key_length):
    length_of_diff_stream = len(stream) - key_length
    diff_stream = bytearray(b'')
    for x in range(length_of_diff_stream):
        diff_stream.append(stream[x] ^ stream[x + key_length]) #^ operation returns value as decimal
    return diff_stream

def filter_plaintexts(plaintexts, key_length):
    filtered_plaintexts = []

    for pt in plaintexts:
        if len(pt) >= (2 * key_length):
            filtered_plaintexts.append(pt)

    return filtered_plaintexts

def determine_possible_keys(key_length, cipher_text, plaintexts):
    all_key_strings = []
    possible_keys = []

    plaintext_diff_streams = []

    cipher_text = bytearray(cipher_text, 'utf-8')
    for x in range(len(plaintexts)):
        plaintexts[x] = bytearray(plaintexts[x], 'utf-8')

    cipher_diff_stream = calculate_difference_stream(cipher_text, key_length)

    filtered_plaintexts = filter_plaintexts(plaintexts, key_length)

    for pt in filtered_plaintexts:
        plaintext_diff_streams.append(calculate_difference_stream(pt, key_length))

    #question: how many plaintexts do we want to cycle through? shouled we just attempt the largest one and work backwards until we find a match?
    for pt_index in range(len(filtered_plaintexts)):
        l = len(filtered_plaintexts[pt_index])
        i = cipher_diff_stream.find(plaintext_diff_streams[pt_index])
        key_string = bytearray(b'')
        for x in range(l):
            key_string.append(cipher_text[i + x] ^ plaintexts[pt_index][x]) #^ operation returns value as decimal
        all_key_strings.append(key_string)
        
        possible_keys.append(pull_key_from_repeating_key(key_string, i, key_length))


    return possible_keys

def pull_key_from_repeating_key(repeating_key, index_in_cipher, key_length):
    initial_key_index = index_in_cipher % key_length
    return repeating_key[key_length-initial_key_index:2*key_length-initial_key_index]



def main():

    parser = argparse.ArgumentParser(description="Searches for plaintext strings in XOR encrypted file")
    parser.add_argument('-p','--plaintext',
                        default="",
                        dest="plaintext_path",
                        help='path to plaintext file with strings to search for')

    parser.add_argument('-c','--ciphertext',
                        default="",
                        dest="ciphertext_path",
                        help='path to XOR encrypted file to be searched')

    parser.add_argument('-l','--length',
                        type=int,
                        default=0,
                        dest="key_length",
                        help='length of XOR key, in bytes')

    args = parser.parse_args()

    if args.plaintext_path != "":
        plaintext_filename = args.plaintext_path
    else:
        plaintext_filename = input("\nEnter plaintext file name:")

    if args.ciphertext_path != "":
        filename = args.ciphertext_path
    else:
        filename = input("\nEnter ciphertext file name:")

    if args.key_length > 0:
        key_length = args.key_length
    else:
        key_length = int(input("\nEnter a key length:"))

    #load in ciphertext file as bytearray
    ciphertext = open(filename, "rb").read()

    pts = []
    with open(plaintext_filename) as fp:
        line = fp.readline()
        while line:
            pts.append(line.strip())
            line = fp.readline()

    pts = filter_plaintexts(pts, key_length)
    plaintext_pts = [None] * len(pts)

    #convert pts from strings to bytearrays
    for i in range(len(pts)):
        plaintext_pts[i] = pts[i]
        pts[i] = bytearray(pts[i], "utf-8")

    #calculate diff stream for ciphertext
    ciphertext_diff_stream = xordiffstream.diff_stream(ciphertext, key_length)

    #calculate diff stream for plaintexts
    pt_diff_streams = []
    for i in range(len(pts)):
        pt_diff_streams.append(bytearray(xordiffstream.diff_stream(pts[i], key_length)))
        
    #construct yara rule from plaintexts
    rule = 'rule test_rule{ \nstrings: \n'
    rule_tail = "condition: \n\t"
    for diff_stream in pt_diff_streams:
        rule = rule + '\t${} =  \"{}\"  \n'.format("a" + str(pt_diff_streams.index(diff_stream)), diff_stream.hex())
        rule_tail = rule_tail + "${} or ".format("a" + str(pt_diff_streams.index(diff_stream)))
    rule = rule + rule_tail[0:-3] + "\n}"
    #print(rule)

    #user yara API to compile and run matches of rule
    compiled_rules = yara.compile(source=rule)
    matches = compiled_rules.match(data=ciphertext_diff_stream.hex())
    #pprint.pprint(matches)
    #print(matches[0].strings)
    #print(matches[0].strings[0])
    #print(matches[0].strings[1][1])
    print("\n**********************************************************************")
    if len(matches) == 0:
        print("No matches were found!")
    else:    
        for match in matches[0].strings:
            print("Plaintext (\"" + plaintext_pts[int(match[1][2:])] + "\") was matched at offset " + str(match[0]) + " and was encoded as 0x" + str(match[2].hex()))        
#print(match)
    print("**********************************************************************\n")

if __name__ == '__main__':
    main()
