import numpy as np
import scipy.io.wavfile as wavfile


def extract_hidden_data(audio_filename):
    # Read the audio file
    rate, data = wavfile.read(audio_filename)

    # Ensure the audio data is mono
    if data.ndim > 1:
        data = data[:, 0]

    # Perform FFT on the audio data
    freq_data = np.fft.fft(data)

    # Get the magnitude spectrum
    magnitude = np.abs(freq_data)

    # Convert magnitudes to integers
    magnitude_int = magnitude.astype(np.int64)

    # Extract the least significant bits from the magnitudes
    lsb_bits = magnitude_int & 1  # Get LSB by bitwise AND with 1

    # Flatten the array of bits
    bits = lsb_bits.tolist()

    # Group bits into bytes
    byte_list = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]
        if len(byte_bits) == 8:
            byte_str = ''.join(str(bit) for bit in byte_bits)
            byte_value = int(byte_str, 2)
            byte_list.append(byte_value)

    # Convert byte values to characters to form the hidden message
    message = ''.join(chr(byte) for byte in byte_list)

    # Print the hidden message
    print("Hidden message:")
    print(message)



# Example usage
extract_hidden_data('hidden_audio.wav')
