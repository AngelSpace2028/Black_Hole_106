import os
import sys
import math
import struct
import array
import random
import heapq
import binascii
import logging
import paq  # Python binding for PAQ9a (pip install paq)
import hashlib
from enum import Enum
from typing import List, Dict, Tuple, Optional

# === Configure Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# === Constants ===
PROGNAME = "PAQJP_6_Smart"
HUFFMAN_THRESHOLD = 1024  # Bytes threshold for Huffman vs. PAQ compression
PI_DIGITS_FILE = "pi_digits.txt"
PRIMES = [p for p in range(2, 256) if all(p % d != 0 for d in range(2, int(p**0.5)+1))]
MEM = 1 << 15  # 32,768

# === Dictionary file list ===
DICTIONARY_FILES = [
    "words_enwik8.txt", "eng_news_2005_1M-sentences.txt", "eng_news_2005_1M-words.txt",
    "eng_news_2005_1M-sources.txt", "eng_news_2005_1M-co_n.txt",
    "eng_news_2005_1M-co_s.txt", "eng_news_2005_1M-inv_so.txt",
    "eng_news_2005_1M-meta.txt", "Dictionary.txt",
    "the-complete-reference-html-css-fifth-edition.txt",
    "words.txt.paq", "lines.txt.paq", "sentence.txt.paq"
]

# === Pi Digits Functions ===
def save_pi_digits(digits: List[int], filename: str = PI_DIGITS_FILE) -> bool:
    """Save base-10 pi digits to a file."""
    try:
        with open(filename, 'w') as f:
            f.write(','.join(str(d) for d in digits))
        logging.info(f"Saved {len(digits)} pi digits to {filename}")
        return True
    except Exception as e:
        logging.error(f"Failed to save pi digits to {filename}: {e}")
        return False

def load_pi_digits(filename: str = PI_DIGITS_FILE, expected_count: int = 3) -> Optional[List[int]]:
    """Load base-10 pi digits from a file."""
    try:
        if not os.path.isfile(filename):
            logging.warning(f"Pi digits file {filename} does not exist")
            return None
        with open(filename, 'r') as f:
            data = f.read().strip()
            if not data:
                logging.warning(f"Pi digits file {filename} is empty")
                return None
            digits = []
            for x in data.split(','):
                if not x.isdigit():
                    logging.warning(f"Invalid integer in {filename}: {x}")
                    return None
                d = int(x)
                if not (0 <= d <= 255):
                    logging.warning(f"Digit out of range in {filename}: {d}")
                    return None
                digits.append(d)
            if len(digits) != expected_count:
                logging.warning(f"Loaded {len(digits)} digits, expected {expected_count}")
                return None
            logging.info(f"Loaded {len(digits)} pi digits from {filename}")
            return digits
    except Exception as e:
        logging.error(f"Failed to load pi digits from {filename}: {e}")
        return None

def generate_pi_digits(num_digits: int = 3, filename: str = PI_DIGITS_FILE) -> List[int]:
    """Generate or load pi digits, mapping to 0-255 range."""
    loaded_digits = load_pi_digits(filename, num_digits)
    if loaded_digits is not None:
        return loaded_digits
    try:
        from mpmath import mp
        mp.dps = num_digits
        pi_digits = [int(d) for d in mp.pi.digits(10)[0]]
        if len(pi_digits) != num_digits:
            logging.error(f"Generated {len(pi_digits)} digits, expected {num_digits}")
            raise ValueError("Incorrect number of pi digits generated")
        if not all(0 <= d <= 9 for d in pi_digits):
            logging.error("Generated pi digits contain invalid values")
            raise ValueError("Invalid pi digits generated")
        mapped_digits = [(d * 255 // 9) % 256 for d in pi_digits]
        save_pi_digits(mapped_digits, filename)
        return mapped_digits
    except Exception as e:
        logging.error(f"Failed to generate pi digits: {e}")
        fallback_digits = [3, 1, 4]
        mapped_fallback = [(d * 255 // 9) % 256 for d in fallback_digits[:num_digits]]
        logging.warning(f"Using {len(mapped_fallback)} fallback pi digits")
        save_pi_digits(mapped_fallback, filename)
        return mapped_fallback

PI_DIGITS = generate_pi_digits(3)

# === Helper Classes and Functions ===
class Filetype(Enum):
    DEFAULT = 0
    JPEG = 1
    TEXT = 3

class Node:
    """Huffman tree node."""
    def __init__(self, left=None, right=None, symbol=None):
        self.left = left
        self.right = right
        self.symbol = symbol

    def is_leaf(self):
        return self.left is None and self.right is None

def transform_with_prime_xor_every_3_bytes(data, repeat=100):
    """XOR every third byte with prime-derived values."""
    transformed = bytearray(data)
    for prime in PRIMES:
        xor_val = prime if prime == 2 else max(1, math.ceil(prime * 4096 / 28672))
        for _ in range(repeat):
            for i in range(0, len(transformed), 3):
                transformed[i] ^= xor_val
    return bytes(transformed)

def transform_with_pattern_chunk(data, chunk_size=4):
    """XOR each chunk with 0xFF."""
    transformed = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        transformed.extend([b ^ 0xFF for b in chunk])
    return bytes(transformed)

def is_prime(n):
    """Check if a number is prime."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

def find_nearest_prime_around(n):
    """Find the nearest prime number to n."""
    offset = 0
    while True:
        if is_prime(n - offset):
            return n - offset
        if is_prime(n + offset):
            return n + offset
        offset += 1

# === Smart Compressor ===
class SmartCompressor:
    def __init__(self):
        self.dictionaries = self.load_dictionaries()

    def load_dictionaries(self):
        """Load dictionary files for hash lookup."""
        data = []
        for filename in DICTIONARY_FILES:
            if os.path.exists(filename):
                try:
                    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                        data.append(f.read())
                    logging.info(f"Loaded dictionary: {filename}")
                except Exception as e:
                    logging.warning(f"Could not read {filename}: {e}")
            else:
                logging.warning(f"Missing dictionary: {filename}")
        return data

    def compute_sha256(self, data):
        """Compute SHA-256 hash as hex."""
        return hashlib.sha256(data).hexdigest()

    def compute_sha256_binary(self, data):
        """Compute SHA-256 hash as bytes."""
        return hashlib.sha256(data).digest()

    def find_hash_in_dictionaries(self, hash_hex):
        """Search for hash in dictionary files."""
        for filename in DICTIONARY_FILES:
            if not os.path.exists(filename):
                continue
            try:
                with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if hash_hex in line:
                            logging.info(f"Hash {hash_hex[:16]}... found in {filename}")
                            return filename
            except Exception as e:
                logging.warning(f"Error searching {filename}: {e}")
        return None

    def generate_8byte_sha(self, data):
        """Generate 8-byte SHA-256 prefix."""
        try:
            return hashlib.sha256(data).digest()[:8]
        except Exception as e:
            logging.error(f"Failed to generate SHA: {e}")
            return None

    def paq_compress(self, data):
        """Compress data using PAQ9a."""
        if not data:
            logging.warning("paq_compress: Empty input, returning empty bytes")
            return b''
        try:
            compressed = paq.compress(data)
            logging.info("PAQ9a compression complete")
            return compressed
        except Exception as e:
            logging.error(f"PAQ9a compression failed: {e}")
            return None

    def paq_decompress(self, data):
        """Decompress data using PAQ9a."""
        if not data:
            logging.warning("paq_decompress: Empty input, returning empty bytes")
            return b''
        try:
            decompressed = paq.decompress(data)
            logging.info("PAQ9a decompression complete")
            return decompressed
        except Exception as e:
            logging.error(f"PAQ9a decompression failed: {e}")
            return None

    def reversible_transform(self, data):
        """Apply reversible XOR transform with 0xAA."""
        logging.info("Applying XOR transform (0xAA)")
        transformed = bytes(b ^ 0xAA for b in data)
        logging.info("XOR transform complete")
        return transformed

    def reverse_reversible_transform(self, data):
        """Reverse XOR transform with 0xAA."""
        logging.info("Reversing XOR transform (0xAA)")
        return self.reversible_transform(data)  # XOR is symmetric

    def compress(self, input_data, input_file):
        """Compress data using Smart Compressor."""
        if not input_data:
            logging.warning("Empty input, returning minimal output")
            return bytes([0])

        original_hash = self.compute_sha256(input_data)
        logging.info(f"SHA-256 of input: {original_hash[:16]}...")

        found = self.find_hash_in_dictionaries(original_hash)
        if found:
            logging.info(f"Hash found in dictionary: {found}")
        else:
            logging.info("Hash not found, proceeding with compression")

        if input_file.endswith(".paq") and any(x in input_file for x in ["words", "lines", "sentence"]):
            sha = self.generate_8byte_sha(input_data)
            if sha and len(input_data) > 8:
                logging.info(f"SHA-8 for .paq file: {sha.hex()}")
                return sha
            logging.info("Original smaller than SHA, skipping compression")
            return None

        transformed = self.reversible_transform(input_data)
        compressed = self.paq_compress(transformed)
        if compressed is None:
            logging.error("Compression failed")
            return None

        if len(compressed) < len(input_data):
            output = self.compute_sha256_binary(input_data) + compressed
            logging.info(f"Smart compression: Original {len(input_data)} bytes, Compressed {len(compressed)} bytes")
            return output
        else:
            logging.info("Compression not efficient, returning None")
            return None

    def decompress(self, input_data):
        """Decompress data using Smart Compressor."""
        if len(input_data) < 32:
            logging.error("Input too short for Smart Compressor")
            return None

        stored_hash = input_data[:32]
        compressed_data = input_data[32:]

        decompressed = self.paq_decompress(compressed_data)
        if decompressed is None:
            return None

        original = self.reverse_reversible_transform(decompressed)
        computed_hash = self.compute_sha256_binary(original)
        if computed_hash == stored_hash:
            logging.info("Hash verification successful")
            return original
        else:
            logging.error("Hash verification failed")
            return None

# === PAQJP Compressor ===
class PAQJPCompressor:
    def __init__(self):
        self.PI_DIGITS = PI_DIGITS
        self.PRIMES = PRIMES
        self.seed_tables = self.generate_seed_tables()
        self.SQUARE_OF_ROOT = 2
        self.ADD_NUMBERS = 1
        self.MULTIPLY = 3
        self.fibonacci = self.generate_fibonacci(100)

    def generate_fibonacci(self, n: int) -> List[int]:
        """Generate Fibonacci sequence up to n terms."""
        fib = [0, 1]
        for i in range(2, n):
            fib.append(fib[i-1] + fib[i-2])
        return fib

    def generate_seed_tables(self, num_tables=126, table_size=256, min_val=5, max_val=255, seed=42):
        """Generate random seed tables."""
        random.seed(seed)
        return [[random.randint(min_val, max_val) for _ in range(table_size)] for _ in range(num_tables)]

    def get_seed(self, table_idx: int, value: int) -> int:
        """Get seed value from table."""
        if 0 <= table_idx < len(self.seed_tables):
            return self.seed_tables[table_idx][value % len(self.seed_tables[table_idx])]
        return 0

    def calculate_frequencies(self, binary_str):
        """Calculate bit frequencies."""
        if not binary_str:
            logging.warning("Empty binary string, returning empty frequencies")
            return {}
        frequencies = {}
        for bit in binary_str:
            frequencies[bit] = frequencies.get(bit, 0) + 1
        return frequencies

    def build_huffman_tree(self, frequencies):
        """Build Huffman tree from frequencies."""
        if not frequencies:
            logging.warning("No frequencies, returning None")
            return None
        heap = [(freq, Node(symbol=symbol)) for symbol, freq in frequencies.items()]
        heapq.heapify(heap)
        while len(heap) > 1:
            freq1, node1 = heapq.heappop(heap)
            freq2, node2 = heapq.heappop(heap)
            new_node = Node(left=node1, right=node2)
            heapq.heappush(heap, (freq1 + freq2, new_node))
        return heap[0][1]

    def generate_huffman_codes(self, root, current_code="", codes={}):
        """Generate Huffman codes from tree."""
        if root is None:
            logging.warning("Huffman tree is None, returning empty codes")
            return {}
        if root.is_leaf():
            codes[root.symbol] = current_code or "0"
            return codes
        if root.left:
            self.generate_huffman_codes(root.left, current_code + "0", codes)
        if root.right:
            self.generate_huffman_codes(root.right, current_code + "1", codes)
        return codes

    def compress_data_huffman(self, binary_str):
        """Compress binary string using Huffman coding."""
        if not binary_str:
            logging.warning("Empty binary string, returning empty compressed string")
            return ""
        frequencies = self.calculate_frequencies(binary_str)
        huffman_tree = self.build_huffman_tree(frequencies)
        if huffman_tree is None:
            return ""
        huffman_codes = self.generate_huffman_codes(huffman_tree)
        if '0' not in huffman_codes:
            huffman_codes['0'] = '0'
        if '1' not in huffman_codes:
            huffman_codes['1'] = '1'
        return ''.join(huffman_codes[bit] for bit in binary_str)

    def decompress_data_huffman(self, compressed_str):
        """Decompress Huffman-coded string."""
        if not compressed_str:
            logging.warning("Empty compressed string, returning empty decompressed string")
            return ""
        frequencies = self.calculate_frequencies(compressed_str)
        huffman_tree = self.build_huffman_tree(frequencies)
        if huffman_tree is None:
            return ""
        huffman_codes = self.generate_huffman_codes(huffman_tree)
        reversed_codes = {code: symbol for symbol, code in huffman_codes.items()}
        decompressed_str = ""
        current_code = ""
        for bit in compressed_str:
            current_code += bit
            if current_code in reversed_codes:
                decompressed_str += reversed_codes[current_code]
                current_code = ""
        return decompressed_str

    def paq_compress(self, data):
        """Compress data using PAQ9a."""
        if not data:
            logging.warning("paq_compress: Empty input, returning empty bytes")
            return b''
        try:
            return paq.compress(data)
        except Exception as e:
            logging.error(f"PAQ9a compression failed: {e}")
            return None

    def paq_decompress(self, data):
        """Decompress data using PAQ9a."""
        if not data:
            logging.warning("paq_decompress: Empty input, returning empty bytes")
            return b''
        try:
            return paq.decompress(data)
        except Exception as e:
            logging.error(f"PAQ9a decompression failed: {e}")
            return None

    def transform_01(self, data, repeat=100):
        """Transform using prime XOR every 3 bytes."""
        if not data:
            logging.warning("transform_01: Empty input, returning empty bytes")
            return b''
        return transform_with_prime_xor_every_3_bytes(data, repeat=repeat)

    def reverse_transform_01(self, data, repeat=100):
        """Reverse transform_01 (same as forward)."""
        return self.transform_01(data, repeat=repeat)

    def transform_03(self, data):
        """Transform using chunk XOR with 0xFF."""
        if not data:
            logging.warning("transform_03: Empty input, returning empty bytes")
            return b''
        return transform_with_pattern_chunk(data)

    def reverse_transform_03(self, data):
        """Reverse transform_03 (same as forward)."""
        return self.transform_03(data)

    def transform_04(self, data, repeat=100):
        """Subtract index modulo 256."""
        if not data:
            logging.warning("transform_04: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for _ in range(repeat):
            for i in range(len(transformed)):
                transformed[i] = (transformed[i] - (i % 256)) % 256
        return bytes(transformed)

    def reverse_transform_04(self, data, repeat=100):
        """Reverse transform_04 by adding index modulo 256."""
        if not data:
            logging.warning("reverse_transform_04: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for _ in range(repeat):
            for i in range(len(transformed)):
                transformed[i] = (transformed[i] + (i % 256)) % 256
        return bytes(transformed)

    def transform_05(self, data, shift=3):
        """Rotate bytes left by shift bits."""
        if not data:
            logging.warning("transform_05: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = ((transformed[i] << shift) | (transformed[i] >> (8 - shift))) & 0xFF
        return bytes(transformed)

    def reverse_transform_05(self, data, shift=3):
        """Rotate bytes right by shift bits."""
        if not data:
            logging.warning("reverse_transform_05: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = ((transformed[i] >> shift) | (transformed[i] << (8 - shift))) & 0xFF
        return bytes(transformed)

    def transform_06(self, data, seed=42):
        """Apply random substitution table."""
        if not data:
            logging.warning("transform_06: Empty input, returning empty bytes")
            return b''
        random.seed(seed)
        substitution = list(range(256))
        random.shuffle(substitution)
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = substitution[transformed[i]]
        return bytes(transformed)

    def reverse_transform_06(self, data, seed=42):
        """Reverse random substitution table."""
        if not data:
            logging.warning("reverse_transform_06: Empty input, returning empty bytes")
            return b''
        random.seed(seed)
        substitution = list(range(256))
        random.shuffle(substitution)
        reverse_substitution = [0] * 256
        for i, v in enumerate(substitution):
            reverse_substitution[v] = i
        transformed = bytearray(data)
        for i in range(len(transformed)):
            transformed[i] = reverse_substitution[transformed[i]]
        return bytes(transformed)

    def transform_07(self, data, repeat=100):
        """XOR with pi digits and size byte."""
        if not data:
            logging.warning("transform_07: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_07: {cycles} cycles for {len(data)} bytes")

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[shift:] + self.PI_DIGITS[:shift]

        size_byte = len(data) % 256
        for i in range(len(transformed)):
            transformed[i] ^= size_byte

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        return bytes(transformed)

    def reverse_transform_07(self, data, repeat=100):
        """Reverse transform_07."""
        if not data:
            logging.warning("reverse_transform_07: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_07: {cycles} cycles for {len(data)} bytes")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        size_byte = len(data) % 256
        for i in range(len(transformed)):
            transformed[i] ^= size_byte

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[-shift:] + self.PI_DIGITS[:-shift]

        return bytes(transformed)

    def transform_08(self, data, repeat=100):
        """XOR with nearest prime and pi digits."""
        if not data:
            logging.warning("transform_08: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_08: {cycles} cycles for {len(data)} bytes")

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[shift:] + self.PI_DIGITS[:shift]

        size_prime = find_nearest_prime_around(len(data) % 256)
        for i in range(len(transformed)):
            transformed[i] ^= size_prime

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        return bytes(transformed)

    def reverse_transform_08(self, data, repeat=100):
        """Reverse transform_08."""
        if not data:
            logging.warning("reverse_transform_08: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_08: {cycles} cycles for {len(data)} bytes")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit

        size_prime = find_nearest_prime_around(len(data) % 256)
        for i in range(len(transformed)):
            transformed[i] ^= size_prime

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[-shift:] + self.PI_DIGITS[:-shift]

        return bytes(transformed)

    def transform_09(self, data, repeat=100):
        """XOR with prime, seed, and pi digits."""
        if not data:
            logging.warning("transform_09: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_09: {cycles} cycles, {repeat} repeats for {len(data)} bytes")

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[shift:] + self.PI_DIGITS[:shift]

        size_prime = find_nearest_prime_around(len(data) % 256)
        seed_idx = len(data) % len(self.seed_tables)
        seed_value = self.get_seed(seed_idx, len(data))
        for i in range(len(transformed)):
            transformed[i] ^= size_prime ^ seed_value

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit ^ (i % 256)

        return bytes(transformed)

    def reverse_transform_09(self, data, repeat=100):
        """Reverse transform_09."""
        if not data:
            logging.warning("reverse_transform_09: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        pi_length = len(self.PI_DIGITS)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_09: {cycles} cycles, {repeat} repeats for {len(data)} bytes")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                pi_digit = self.PI_DIGITS[i % pi_length]
                transformed[i] ^= pi_digit ^ (i % 256)

        size_prime = find_nearest_prime_around(len(data) % 256)
        seed_idx = len(data) % len(self.seed_tables)
        seed_value = self.get_seed(seed_idx, len(data))
        for i in range(len(transformed)):
            transformed[i] ^= size_prime ^ seed_value

        shift = len(data) % pi_length
        self.PI_DIGITS = self.PI_DIGITS[-shift:] + self.PI_DIGITS[:-shift]

        return bytes(transformed)

    def transform_10(self, data, repeat=100):
        """XOR with value derived from 'X1' sequences."""
        if not data:
            logging.warning("transform_10: Empty input, returning empty bytes with n=0")
            return bytes([0])
        transformed = bytearray(data)
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"transform_10: {cycles} cycles, {repeat} repeats for {len(data)} bytes")

        count = 0
        for i in range(len(data) - 1):
            if data[i] == 0x58 and data[i + 1] == 0x31:
                count += 1
        logging.info(f"transform_10: Found {count} 'X1' sequences")

        n = (((count * self.SQUARE_OF_ROOT) + self.ADD_NUMBERS) // 3) * self.MULTIPLY
        n = n % 256
        logging.info(f"transform_10: Computed n = {n}")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                transformed[i] ^= n

        return bytes([n]) + bytes(transformed)

    def reverse_transform_10(self, data, repeat=100):
        """Reverse transform_10."""
        if len(data) < 1:
            logging.warning("reverse_transform_10: Data too short, returning empty bytes")
            return b''
        n = data[0]
        transformed = bytearray(data[1:])
        data_size_kb = len(data) / 1024
        cycles = min(10, max(1, int(data_size_kb)))
        logging.info(f"reverse_transform_10: {cycles} cycles, {repeat} repeats, n={n}")

        for _ in range(cycles * repeat // 10):
            for i in range(len(transformed)):
                transformed[i] ^= n

        return bytes(transformed)

    def transform_11(self, data, repeat=100):
        """Test multiple y values for best compression."""
        if not data:
            logging.warning("transform_11: Empty input, returning y=0 with no data")
            return struct.pack('B', 0)
        y_values = range(1, 256)
        best_result = None
        best_y = None
        best_size = float('inf')
        zero_count = sum(1 for b in data if b == 0)
        logging.info(f"transform_11: Testing {len(y_values)} y values for {len(data)} bytes, {zero_count} zeros")
        for y in y_values:
            transformed = bytearray(data)
            for _ in range(repeat):
                for i in range(len(transformed)):
                    transformed[i] = (transformed[i] + y + 1) % 256
            try:
                compressed = self.paq_compress(transformed)
                if compressed is None:
                    logging.warning(f"transform_11: Compression with y={y} failed")
                    continue
                if len(compressed) < best_size:
                    best_result = compressed
                    best_y = y
                    best_size = len(compressed)
            except Exception as e:
                logging.warning(f"transform_11: Compression with y={y} failed: {e}")
                continue
        if best_result is None:
            logging.error("transform_11: All compression failed, returning original with y=0")
            return struct.pack('B', 0) + data
        logging.info(f"transform_11: Selected y={best_y}, compressed size {best_size}")
        return struct.pack('B', best_y) + best_result

    def reverse_transform_11(self, data, repeat=100):
        """Reverse transform_11."""
        if len(data) < 1:
            logging.warning("reverse_transform_11: Data too short, returning empty bytes")
            return b''
        y = struct.unpack('B', data[:1])[0]
        compressed_data = data[1:]
        if not compressed_data:
            logging.warning("reverse_transform_11: No compressed data, returning empty bytes")
            return b''
        try:
            decompressed = self.paq_decompress(compressed_data)
            if not decompressed:
                logging.warning("reverse_transform_11: Decompression empty")
                return b''
        except Exception as e:
            logging.error(f"reverse_transform_11: Decompression failed: {e}")
            return b''
        transformed = bytearray(decompressed)
        zero_count = sum(1 for b in transformed if b == 0)
        logging.info(f"reverse_transform_11: {len(transformed)} bytes, y={y}, {zero_count} zeros")
        for _ in range(repeat):
            for i in range(len(transformed)):
                transformed[i] = (transformed[i] - y - 1) % 256
        zero_count_after = sum(1 for b in transformed if b == 0)
        logging.info(f"reverse_transform_11: Restored, {zero_count_after} zeros")
        return bytes(transformed)

    def transform_12(self, data, repeat=100):
        """XOR with Fibonacci sequence."""
        if not data:
            logging.warning("transform_12: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        data_size = len(data)
        fib_length = len(self.fibonacci)
        logging.info(f"transform_12: Fibonacci transform for {data_size} bytes, repeat={repeat}")
        
        for _ in range(repeat):
            for i in range(len(transformed)):
                fib_index = i % fib_length
                fib_value = self.fibonacci[fib_index] % 256
                transformed[i] ^= fib_value
        
        return bytes(transformed)

    def reverse_transform_12(self, data, repeat=100):
        """Reverse Fibonacci XOR transform."""
        if not data:
            logging.warning("reverse_transform_12: Empty input, returning empty bytes")
            return b''
        transformed = bytearray(data)
        data_size = len(data)
        fib_length = len(self.fibonacci)
        logging.info(f"reverse_transform_12: Reversing Fibonacci for {data_size} bytes, repeat={repeat}")
        
        for _ in range(repeat):
            for i in range(len(transformed)):
                fib_index = i % fib_length
                fib_value = self.fibonacci[fib_index] % 256
                transformed[i] ^= fib_value
        
        return bytes(transformed)

    def generate_transform_method(self, marker):
        """Generate dynamic transform for markers 13-255."""
        def transform(data, repeat=1000):
            if not data:
                logging.warning(f"transform_{marker}: Empty input, returning empty bytes")
                return b''
            transformed = bytearray(data)
            data_size = len(data)
            scale_factor = max(2000, min(256000, data_size))
            size_mod = (data_size % scale_factor) % 256
            logging.info(f"transform_{marker}: size_mod={size_mod} for {data_size} bytes")
            for _ in range(repeat):
                for i in range(len(transformed)):
                    transformed[i] ^= (size_mod + (i % 256)) % 256
            return bytes(transformed)

        def reverse_transform(data, repeat=1000):
            if not data:
                logging.warning(f"reverse_transform_{marker}: Empty input, returning empty bytes")
                return b''
            transformed = bytearray(data)
            data_size = len(data)
            scale_factor = max(2000, min(256000, data_size))
            size_mod = (data_size % scale_factor) % 256
            logging.info(f"reverse_transform_{marker}: size_mod={size_mod} for {data_size} bytes")
            for _ in range(repeat):
                for i in range(len(transformed)):
                    transformed[i] ^= (size_mod + (i % 256)) % 256
            return bytes(transformed)
        return transform, reverse_transform

    def compress_with_best_method(self, data, filetype, input_filename, mode="slow"):
        """Compress data using the best transformation method."""
        if not data:
            logging.warning("compress_with_best_method: Empty input, returning minimal marker")
            return bytes([0])

        fast_transformations = [
            (1, self.transform_04),
            (2, self.transform_01),
            (3, self.transform_03),
            (5, self.transform_05),
            (6, self.transform_06),
            (7, self.transform_07),
            (8, self.transform_08),
            (9, self.transform_09),
            (12, self.transform_12),
        ]
        slow_transformations = fast_transformations + [
            (10, self.transform_10),
            (11, self.transform_11),
        ] + [(i, self.generate_transform_method(i)[0]) for i in range(13, 256)]

        transformations = slow_transformations if mode == "slow" else fast_transformations

        if filetype in [Filetype.JPEG, Filetype.TEXT]:
            prioritized = [(7, self.transform_07), (8, self.transform_08), (9, self.transform_09), (12, self.transform_12)]
            if mode == "slow":
                prioritized += [(10, self.transform_10), (11, self.transform_11)] + \
                              [(i, self.generate_transform_method(i)[0]) for i in range(13, 256)]
            transformations = prioritized + [t for t in transformations if t[0] not in [7, 8, 9, 10, 11, 12] + list(range(13, 256))]

        methods = [('paq', self.paq_compress)]
        best_compressed = None
        best_size = float('inf')
        best_marker = None
        best_method = None

        for marker, transform in transformations:
            transformed = transform(data)
            for method_name, compress_func in methods:
                try:
                    compressed = compress_func(transformed)
                    if compressed is None:
                        continue
                    size = len(compressed)
                    if size < best_size:
                        best_size = size
                        best_compressed = compressed
                        best_marker = marker
                        best_method = method_name
                except Exception as e:
                    logging.warning(f"Compression method {method_name} with transform {marker} failed: {e}")
                    continue

        if len(data) < HUFFMAN_THRESHOLD:
            binary_str = bin(int(binascii.hexlify(data), 16))[2:].zfill(len(data) * 8)
            compressed_huffman = self.compress_data_huffman(binary_str)
            compressed_bytes = int(compressed_huffman, 2).to_bytes((len(compressed_huffman) + 7) // 8, 'big') if compressed_huffman else b''
            if compressed_bytes and len(compressed_bytes) < best_size:
                best_size = len(compressed_bytes)
                best_compressed = compressed_bytes
                best_marker = 4
                best_method = 'huffman'

        if best_compressed is None:
            logging.error("All compression methods failed, returning original with marker 0")
            return bytes([0]) + data

        logging.info(f"Best method: {best_method}, Marker: {best_marker} for {filetype.name} in {mode} mode")
        return bytes([best_marker]) + best_compressed

    def decompress_with_best_method(self, data):
        """Decompress data based on marker."""
        if len(data) < 1:
            logging.warning("decompress_with_best_method: Insufficient data")
            return b'', None

        method_marker = data[0]
        compressed_data = data[1:]

        reverse_transforms = {
            1: self.reverse_transform_04,
            2: self.reverse_transform_01,
            3: self.reverse_transform_03,
            5: self.reverse_transform_05,
            6: self.reverse_transform_06,
            7: self.reverse_transform_07,
            8: self.reverse_transform_08,
            9: self.reverse_transform_09,
            10: self.reverse_transform_10,
            11: self.reverse_transform_11,
            12: self.reverse_transform_12,
        }
        reverse_transforms.update({i: self.generate_transform_method(i)[1] for i in range(13, 256)})

        if method_marker == 4:
            binary_str = bin(int(binascii.hexlify(compressed_data), 16))[2:].zfill(len(compressed_data) * 8)
            decompressed_binary = self.decompress_data_huffman(binary_str)
            if not decompressed_binary:
                logging.warning("Huffman decompression empty")
                return b'', None
            try:
                num_bytes = (len(decompressed_binary) + 7) // 8
                hex_str = "%0*x" % (num_bytes * 2, int(decompressed_binary, 2))
                if len(hex_str) % 2 != 0:
                    hex_str = '0' + hex_str
                return binascii.unhexlify(hex_str), None
            except Exception as e:
                logging.error(f"Huffman data conversion failed: {e}")
                return b'', None

        if method_marker not in reverse_transforms:
            logging.error(f"Unknown marker: {method_marker}")
            return b'', None

        try:
            decompressed = self.paq_decompress(compressed_data)
            if not decompressed:
                logging.warning("PAQ decompression empty")
                return b'', None
            result = reverse_transforms[method_marker](decompressed)
            zero_count = sum(1 for b in result if b == 0)
            logging.info(f"Decompressed with marker {method_marker}, {zero_count} zeros")
            return result, method_marker
        except Exception as e:
            logging.error(f"PAQ decompression failed: {e}")
            return b'', None

# === Combined Compressor ===
class CombinedCompressor:
    def __init__(self):
        self.smart_compressor = SmartCompressor()
        self.paqjp_compressor = PAQJPCompressor()

    def save_base256_data(self, data: bytes, filename: str) -> bool:
        """Save bytes to a file."""
        try:
            with open(filename, 'wb') as f:
                f.write(data)
            logging.info(f"Saved {len(data)} bytes to {filename}")
            return True
        except Exception as e:
            logging.error(f"Failed to save to {filename}: {e}")
            return False

    def load_base256_data(self, filename: str) -> Optional[bytes]:
        """Load bytes from a file."""
        try:
            if not os.path.isfile(filename):
                logging.warning(f"File {filename} does not exist")
                return None
            with open(filename, 'rb') as f:
                data = f.read()
                logging.info(f"Loaded {len(data)} bytes from {filename}")
                return data
        except Exception as e:
            logging.error(f"Failed to load from {filename}: {e}")
            return None

    def compress(self, input_file, output_file, mode="slow"):
        """Compress file using best of Smart or PAQJP_6."""
        if not os.path.exists(input_file):
            logging.error(f"Input file {input_file} not found")
            return
        if not os.access(input_file, os.R_OK):
            logging.error(f"No read permission for {input_file}")
            return
        if os.path.getsize(input_file) == 0:
            logging.warning(f"Input file {input_file} is empty")
            self.save_base256_data(bytes([0]), output_file)
            return

        with open(input_file, "rb") as f:
            input_data = f.read()

        smart_compressed = self.smart_compressor.compress(input_data, input_file)
        smart_output = bytes([0x00]) + smart_compressed if smart_compressed else b''

        filetype = detect_filetype(input_file)
        paqjp_compressed = self.paqjp_compressor.compress_with_best_method(input_data, filetype, input_file, mode=mode)
        paqjp_output = bytes([0x01]) + paqjp_compressed if paqjp_compressed else b''

        best_output = None
        if smart_output and paqjp_output:
            best_output = smart_output if len(smart_output) <= len(paqjp_output) else paqjp_output
            logging.info(f"Selected {'Smart' if best_output[0] == 0x00 else 'PAQJP_6'} with size {len(best_output)} bytes")
        elif smart_output:
            best_output = smart_output
            logging.info(f"Selected Smart with size {len(smart_output)} bytes")
        elif paqjp_output:
            best_output = paqjp_output
            logging.info(f"Selected PAQJP_6 with size {len(paqjp_output)} bytes")
        else:
            logging.error("Both compression methods failed")
            return

        self.save_base256_data(best_output, output_file)
        orig_size = len(input_data)
        comp_size = len(best_output)
        ratio = (comp_size / orig_size) * 100 if orig_size > 0 else 0
        logging.info(f"Compression successful: {output_file}, Size: {comp_size} bytes")
        logging.info(f"Original: {orig_size} bytes, Compressed: {comp_size} bytes, Ratio: {ratio:.2f}%")

    def decompress(self, input_file, output_file):
        """Decompress file based on marker."""
        if not os.path.exists(input_file):
            logging.error(f"Input file {input_file} not found")
            return
        if not os.access(input_file, os.R_OK):
            logging.error(f"No read permission for {input_file}")
            return
        if os.path.getsize(input_file) == 0:
            logging.warning(f"Input file {input_file} is empty")
            self.save_base256_data(b'', output_file)
            return

        compressed_data = self.load_base256_data(input_file)
        if compressed_data is None:
            logging.error("Failed to load compressed data")
            return

        if len(compressed_data) < 1:
            logging.error("Input data too short")
            return

        marker = compressed_data[0]
        compressed_data = compressed_data[1:]

        if marker == 0x00:
            logging.info("Detected Smart Compressor (marker 00)")
            decompressed = self.smart_compressor.decompress(compressed_data)
        elif marker == 0x01:
            logging.info("Detected PAQJP_6 Compressor (marker 01)")
            decompressed, _ = self.paqjp_compressor.decompress_with_best_method(compressed_data)
        else:
            logging.error(f"Unknown compression marker: {marker:02x}")
            return

        if decompressed is None:
            logging.error("Decompression failed")
            return

        self.save_base256_data(decompressed, output_file)
        comp_size = len(compressed_data) + 1
        decomp_size = len(decompressed)
        zero_count = sum(1 for b in decompressed if b == 0)
        logging.info(f"Decompression successful: {output_file}, {zero_count} zeros")
        logging.info(f"Compressed: {comp_size} bytes, Decompressed: {decomp_size} bytes")

def detect_filetype(filename: str) -> Filetype:
    """Detect filetype based on extension."""
    _, ext = os.path.splitext(filename.lower())
    if ext in ['.jpg', '.jpeg']:
        return Filetype.JPEG
    elif ext == '.txt':
        return Filetype.TEXT
    else:
        return Filetype.DEFAULT

def main():
    """Main function for user interaction."""
    print("PAQJP_6_Smart Compression System with Dictionary")
    print("Created by Jurijus Pacalovas")
    print("Options:")
    print("1 - Compress file (Best of Smart Compressor [00] or PAQJP_6 [01])")
    print("2 - Decompress file")

    compressor = CombinedCompressor()

    try:
        choice = input("Enter 1 or 2: ").strip()
        if choice not in ('1', '2'):
            logging.error("Invalid choice. Exiting.")
            return
    except (EOFError, KeyboardInterrupt):
        logging.info("Program terminated by user")
        return

    mode = "slow"
    if choice == '1':
        try:
            mode_choice = input("Enter compression mode (1 for fast, 2 for slow): ").strip()
            if mode_choice == '1':
                mode = "fast"
            elif mode_choice == '2':
                mode = "slow"
            else:
                logging.warning("Invalid mode, defaulting to slow")
                mode = "slow"
        except (EOFError, KeyboardInterrupt):
            logging.info("Defaulting to slow mode")
            mode = "slow"
        logging.info(f"Selected compression mode: {mode}")

    input_file = input("Input file name: ").strip()
    output_file = input("Output file name: ").strip()

    if choice == '1':
        compressor.compress(input_file, output_file, mode=mode)
    elif choice == '2':
        compressor.decompress(input_file, output_file)

if __name__ == "__main__":
    main()
