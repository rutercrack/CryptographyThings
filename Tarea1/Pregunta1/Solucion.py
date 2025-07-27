from collections import defaultdict
import math
from functools import reduce

with open("cipher.txt", "rb") as f:
    ciphertext = f.read()
    byte_list = list(ciphertext)

print("largo de bytelist", len(byte_list))
print("Bite Maximo de byte list: ", max(byte_list))
print("Bite minimo de byte list: ", min(byte_list))

print("Como el largo es menor o igual que 127, hacemos mod % 128 para hacer la desencriptación.")

print("Antes de hacer eso, necesitamos hacer algo como kasinski para estimar un buen tamaño.")

def find_repeated_sequences(ciphertext, min_length=2):
    sequences = defaultdict(list)
    for i in range(len(ciphertext) - min_length + 1):
        seq = tuple(ciphertext[i:i+min_length])
        sequences[seq].append(i)
    return {seq: positions for seq, positions in sequences.items() if len(positions) > 1}

repeated_sequences = find_repeated_sequences(byte_list)

def compute_distances(repeated_sequences):
    distances = []
    for seq, positions in repeated_sequences.items():
        for i in range(1, len(positions)):
            distances.append(positions[i] - positions[0])
    return distances

distances = compute_distances(repeated_sequences)

print("Distancias:",distances)


def gcd_of_distances(distances):
    return reduce(math.gcd, distances)

possible_key_length = gcd_of_distances(distances)
print("Posible longitud de la clave:", possible_key_length)


print("\n asumamos entonces que la llave tiene 132 de largo, es una suposicion buena para iniciar")

def score_char_latin_2(c):
    freq = {
        97: 11.5,  # 'a'
        101: 12.5, # 'e'
        105: 8.5,  # 'i'
        111: 8.0,  # 'o'
        117: 3.0,  # 'u'
        115: 6.5,  # 's'
        116: 6.0,  # 't'
        114: 5.5,  # 'r'
        109: 5.0,  # 'm'
        110: 4.5,  # 'n'
        99: 3.5,   # 'c'
        108: 3.5,  # 'l'
        100: 3.0,  # 'd'
        103: 2.0,  # 'g'
        112: 2.0,  # 'p'
        98: 1.5,   # 'b'
        118: 1.5,  # 'v'
        113: 2.5,  # 'q'
        32: 10.0,  # espacio
        46: 1.0,   # '.'
        44: 1.0,   # ','
        33: -1000, # '!'
        63: -1000, # '?'
        58: -1000, # ':'
        59: -1000, # ';'
        45: -1000  # '-'
    }

    if 48 <= c <= 57:
        return -1000  # dígitos fuera de lugar en latín

    if 65 <= c <= 90:  # mayúsculas
        return -500 # 2

    if c < 32 or c > 126:
        return -1000

    return freq.get(c, -10000)

# ESTANDAR
def score_char_standart(c):
    if 97 <= c <= 122:  # Letras minúsculas (a-z)
        return 5
    elif 65 <= c <= 90:  # Letras mayúsculas (A-Z)
        return 4
    elif c == 32:        # Espacio
        return 10        # El espacio suele ser el carácter más frecuente
    elif 48 <= c <= 57:  # Números (0-9)
        return 1
    elif c in [44, 46, 58, 59]:  # , . : ;
        return 2
    else:
        return -10       # Penalizar caracteres no imprimibles
    

def break_key(ciphertext, key_length):
    chunks = [[] for _ in range(key_length)]
    for i, byte in enumerate(ciphertext):
        chunks[i % key_length].append(byte)
    
    key = []
    for pos in range(key_length):
        best_score = -float('inf')
        best_guess = 0
        for guess in range(1, 128):  # Solo valores imprimibles
            valid = True
            current_score = 0
            for encrypted_byte in chunks[pos]:
                decrypted_byte = (encrypted_byte - guess) % 128
                # Filtro estricto: solo caracteres imprimibles o espacio
                if decrypted_byte != 32 and (decrypted_byte < 32 or decrypted_byte > 126):
                    valid = False
                    break
                current_score += score_char_latin_2(decrypted_byte)  # Usando tu función
            if valid and current_score > best_score:
                best_score = current_score
                best_guess = guess
        key.append(best_guess)
    return bytes(key)
    
def decrypt(ciphertext, key):
    decrypted = []
    for i, byte in enumerate(ciphertext):
        decrypted.append((byte - (key[i % len(key)])) % 128)
    return bytes(decrypted)



def find_key_adjustment_for_cipher_pos(ciphertext_bytes, current_key, ciphertext_pos, desired_char):

    desired_byte = ord(desired_char)
    key_pos = ciphertext_pos % len(current_key)  # La posición de la clave que afecta a ciphertext_pos
    
    encrypted_byte = ciphertext_bytes[ciphertext_pos]
    
    # Calcula el valor necesario para key[key_pos] (MOD 128)
    key_value = (encrypted_byte - desired_byte) % 128
    
    return (key_pos, key_value)


#############################################################

print("\n")

key = break_key(byte_list, 132) #132


############################################################
def find_string_in_decrypted(ciphertext, key, search_string):

    # Desciframos el texto
    decrypted = decrypt(ciphertext, key)
    decrypted_text = decrypted.decode('latin-1') 
    
    # Buscamos el string en el texto descifrado
    index = decrypted_text.find(search_string)
    if index == -1:
        return None
    
    # Verificamos que el string encontrado no cruce límites de la clave
    for i in range(len(search_string)):
        pos_in_cipher = index + i
        if pos_in_cipher >= len(ciphertext):
            return None
    
    return index

##################################
print(decrypt(byte_list, key))
##################################

def smart_crib_drag(ciphertext, current_key, crib, confidence_threshold=0.8):
    best_key = current_key
    best_score = -1
    crib_length = len(crib)
    
    for pos in range(len(ciphertext) - crib_length + 1):
        temp_key = bytearray(current_key)
        matches = 0
        
        for i in range(crib_length):
            cipher_pos = pos + i
            key_pos = cipher_pos % len(temp_key)
            decrypted = (ciphertext[cipher_pos] - temp_key[key_pos]) % 128
            
            if chr(decrypted).lower() == crib[i].lower():
                matches += 1
            else:
                new_key_byte = (ciphertext[cipher_pos] - ord(crib[i])) % 128
                temp_key[key_pos] = new_key_byte
        
        # Solo considerar si al menos el 80% de los caracteres coinciden
        if matches / crib_length >= confidence_threshold:
            test_decrypt = decrypt(ciphertext, temp_key)
            score = sum(score_char_latin_2(c) for c in test_decrypt)
            
            if score > best_score:
                best_score = score
                best_key = temp_key
                print(f"Mejor ajuste en posición {pos}: {crib} → {test_decrypt[pos:pos+crib_length]}")
    
    return bytes(best_key)

def score_bigrams(text):
    latin_bigrams = ['is', 'ae', 'us', 'tu', 'nt', 'es', 'qu']
    score = 0
    for i in range(len(text)-1):
        bigram = chr(text[i]) + chr(text[i+1])
        if bigram.lower() in latin_bigrams:
            score += 10  # Bonus por bigrama válido
    return score

def iterative_key_adjustment(ciphertext, initial_key, language='latín'):
    key = bytearray(initial_key)
    for iteration in range(3):  # 3 pasadas
        for pos in range(len(key)):
            best_score = -float('inf')
            best_byte = key[pos]
            
            for guess in range(32, 128):  # Solo ASCII imprimible
                key[pos] = guess
                decrypted = decrypt(ciphertext, key)
                
                # Score combinado
                current_score = sum(score_char_latin_2(c) for c in decrypted)
                current_score += score_bigrams(decrypted)
                
                if current_score > best_score:
                    best_score = current_score
                    best_byte = guess
            
            key[pos] = best_byte
        
        print(f"Iteración {iteration+1}: {decrypt(ciphertext, key)[:100]}...")
    return bytes(key)

# TESTING


##############################################
# YA SE CUAL ES: FINALMENTE THE END, ARREGLEMOS LA LLAVE ENTONCES.
indice = find_string_in_decrypted(byte_list, key, "Oea")
print(f"El índice de 'Oea' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 0, 'N'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 2, 'c'))

indice = find_string_in_decrypted(byte_list, key, "mouqtuo")
print(f"El índice de 'mouqtuo' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 8, 'n'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 9, 'i'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 11, 's'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 14, 's'))

indice = find_string_in_decrypted(byte_list, key, "tace")
print(f"El índice de 'tace' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 19, 'p'))

indice = find_string_in_decrypted(byte_list, key, "rat")
print(f"El índice de 'rat' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 25, 'e'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 26, 'x'))

indice = find_string_in_decrypted(byte_list, key, "emiebeeli")
print(f"El índice de 'emiebeeli' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 33, 'd'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 34, 'u'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 35, 'x'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 36, ' '))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 39, 'l'))

indice = find_string_in_decrypted(byte_list, key, "vuo")
print(f"El índice de 'vuo' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 46, 'u'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 48, 's'))

indice = find_string_in_decrypted(byte_list, key, "cuit")
print(f"El índice de 'cuit' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 50, 'f'))

indice = find_string_in_decrypted(byte_list, key, "tqueo")
print(f"El índice de 'tqueo' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 55, ' '))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 58, 'i'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 59, 'n'))

indice = find_string_in_decrypted(byte_list, key, "ssat")
print(f"El índice de 'ssat' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 76, 'e'))

indice = find_string_in_decrypted(byte_list, key, "eneo")
print(f"El índice de 'eneo' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 85, 'o'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 86, 'r'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 87, 'e'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 88, 's'))

indice = find_string_in_decrypted(byte_list, key, "neges")
print(f"El índice de 'neges' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 90, 'r'))

indice = find_string_in_decrypted(byte_list, key, " ne ")
print(f"El índice de ' ne ' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 97, 'i'))

indice = find_string_in_decrypted(byte_list, key, "beaemeretqm")
print(f"El índice de 'beaemeretqm' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 99, 'd'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 100, 'e'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 101, 'g'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 102, 'e'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 103, 'n'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 104, 'e'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 105, 'r'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 106, 'a'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 107, 't'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 108, 'u'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 109, 'm'))

indice = find_string_in_decrypted(byte_list, key, "en aleis")
print(f"El índice de 'en aleis' en la lista original es: {indice}")
print(find_key_adjustment_for_cipher_pos(byte_list, key, 111, 'i'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 116, 'i'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 120, 'h'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 122, 'i'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 123, 'c'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 126, 'u'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 127, 'o'))
print(find_key_adjustment_for_cipher_pos(byte_list, key, 129, 'u'))



indice = find_string_in_decrypted(byte_list, key, "Volsdadebeelum")
print(f"El índice de 'Volsdadebeelum' en la lista original es: {indice}")

print(find_key_adjustment_for_cipher_pos(byte_list, key, 161, 'U'))

key = bytearray(key)  # Convertir a mutable
key[0] = 2 
key[2] = 21  
key[8] = 42
key[9] = 89
key[11] = 105
key[14] = 22
key[19] = 110
key[25] = 59
key[26] = 35
key[33] = 92
key[34] = 0
key[35] = 123
key[36] = 126
key[39] = 52
#key[46] = 120
key[48] = 103
key[50] = 20
key[55] = 110
key[58] = 26
key[59] = 71
key[76] = 82
key[85] = 112
key[86] = 28
key[87] = 125
key[88] = 11
key[90] = 81
key[97] = 60
key[99] = 88
key[100] = 101
key[101] = 84
key[102] = 61
key[103] = 15
key[104] = 66
key[105] = 46
key[106] = 6
key[107] = 73
key[108] = 85
key[109] = 105
key[111] = 73
key[116] = 118
key[120] = 14
key[122] = 125
key[123] = 26
key[126] = 102
key[127] = 97
key[129] = 106

#key[29] = 36
key = bytes(key)      # Opcional: volver a bytes (si necesitas immutabilidad)


print(len(key))
print(len(decrypt(byte_list, key)))
print(decrypt(byte_list, key))