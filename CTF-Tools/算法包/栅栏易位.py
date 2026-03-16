def encryptRailFence(text, key):
    # Remove spaces and newlines
    text = text.replace(" ", "").replace("\n", "")
    # Create an array for each rail
    rail = ['' for _ in range(key)]
    direction = None  # None for initial condition
    row = 0

    for char in text:
        rail[row] += char
        # Change direction when top or bottom rail is reached
        if row == 0:
            direction = 1  # Move down
        elif row == key - 1:
            direction = -1  # Move up
        row += direction

    # Concatenate all rails to get ciphertext
    cipher = ''.join(rail)
    return cipher

def decryptRailFence(cipher, key):
    # Create a matrix to mark the places of characters
    length = len(cipher)
    rail = [['\n' for _ in range(length)] for _ in range(key)]

    # Mark the positions with '*'
    direction = None
    row, col = 0, 0
    for _ in range(length):
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        rail[row][col] = '*'
        col += 1
        row += direction

    # Fill the '*' positions with cipher text characters
    index = 0
    for i in range(key):
        for j in range(length):
            if rail[i][j] == '*' and index < length:
                rail[i][j] = cipher[index]
                index += 1

    # Read the matrix in zigzag manner to construct the plaintext
    result = []
    row, col = 0, 0
    for _ in range(length):
        if row == 0:
            direction = 1
        elif row == key - 1:
            direction = -1
        if rail[row][col] != '\n':
            result.append(rail[row][col])
            col += 1
        row += direction

    return ''.join(result)

# Example usage:
text = "WEAREDISCOVEREDFLEEATONCE"
key = 3
cipher = "toosoeaorwatrymrinhd"
print("Encrypted:", cipher)

decrypted = decryptRailFence(cipher, key)
print("Decrypted:", decrypted)
