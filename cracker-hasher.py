import hashlib

def get_input():
    inputted_value = input("Welcome to the password hash cracker and password hasher!\nChoose between the following\n1- Crack a hash\n2- Hash a password:\n").lower()
    
    option_array = ["sha_1", "sha_256", "sha_512", "md5"]
    function_map = {
        "sha_1": sha_1_cracker,
        "sha_256": sha_256_cracker,
        "sha_512": sha_512_cracker,
        "md5": sha_md5_cracker,
    }
    try:
        # Case 1: Crack a hash
        if inputted_value == '1' or inputted_value == 'crack a hash':
            for i, opt in enumerate(option_array, 1):
                print(f"{i}- {opt}")
            hash_type = input("Select the hash type: ").lower()

            if hash_type not in option_array:
                raise ValueError("Input error, check the list of options and re-enter the input!")
            
            file_name = input("Enter the file path: ")
            hash_to_crack = input("Enter the hash to crack: ")
            
            result = function_map[hash_type](hash_to_crack, file_name)
            print(result)
        
        # Case 2: Hash a password
        elif inputted_value == '2' or inputted_value == 'hash a password':
            password = input("Enter the password that you want to hash: ")
            for i, opt in enumerate(option_array, 1):
                print(f"{i}- {opt}")
            hash_type = input("Select the hash type: ").lower()

            if hash_type not in option_array:
                raise ValueError("Input error, check the list of options and re-enter the input!")
            
            hashed_value = function_map[hash_type + '_hasher'](password)
            print(f"Hashed password: {hashed_value}")
    
    except ValueError as e:
        print(e)

def sha_1_cracker(hash_to_crack, file_wordlist):
    with open(file_wordlist, 'r') as words:
        for word in words:
            word = word.strip()
            hashed = sha_1_hasher(word)
            if hash_to_crack == hashed:
                return f"Password found: {word}"
    return "Password not found in the wordlist file"

def sha_1_hasher(input):
    hashed_value = hashlib.sha1()
    hashed_value.update(input.encode('utf-8'))
    return hashed_value.hexdigest()

def sha_256_cracker(hash_to_crack, file_wordlist):
    with open(file_wordlist, 'r') as words:
        for word in words:
            word = word.strip()
            hashed = sha_256_hasher(word)
            if hash_to_crack == hashed:
                return f"Password found: {word}"
    return "Password not found in the wordlist file"

def sha_256_hasher(input):
    hashed_value = hashlib.sha256()
    hashed_value.update(input.encode('utf-8'))
    return hashed_value.hexdigest()

def sha_512_cracker(hash_to_crack, file_wordlist):
    with open(file_wordlist, 'r') as words:
        for word in words:
            word = word.strip()
            hashed = sha_512_hasher(word)
            if hash_to_crack == hashed:
                return f"Password found: {word}"
    return "Password not found in the wordlist file"

def sha_512_hasher(input):
    hashed_value = hashlib.sha512()
    hashed_value.update(input.encode('utf-8'))
    return hashed_value.hexdigest()

def sha_md5_cracker(hash_to_crack, file_wordlist):
    with open(file_wordlist, 'r') as words:
        for word in words:
            word = word.strip()
            hashed = md5_hasher(word)
            if hash_to_crack == hashed:
                return f"Password found: {word}"
    return "Password not found in the wordlist file"

def md5_hasher(input):
    hashed_value = hashlib.md5()
    hashed_value.update(input.encode('utf-8'))
    return hashed_value.hexdigest()

get_input()