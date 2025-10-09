import os
import shutil
import tarfile
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding 
import uuid
import platform
import hashlib

# --- CUSTOM EXCEPTIONS ---
class KosiCryptoError(Exception):
    """Base exception for all Kosi Crypto errors."""
    pass

class KeyPreparationError(KosiCryptoError):
    """Raised for errors in key generation, derivation, wrapping, or unwrapping."""
    pass
    
class FileIntegrityError(KosiCryptoError):
    """Raised for header mismatch, invalid salt metadata, or corrupted files."""
    pass
    
class DeviceBindingError(KosiCryptoError):
    """Raised when decryption fails due to a device ID mismatch."""
    pass

# --- Configuration ---
KEY_SIZE = 32 
SALT_SIZE = 16 
DEVICE_ID_SIZE = 32
KDF_ITERATIONS = 480000 
METADATA_SIZE = 4 + SALT_SIZE 

HMAC_SIZE = 32 
BUFFER_SIZE = 65536 # 64 KB chunk size for streaming I/O

# --- CIPHER IDENTIFICATION HEADERS ---
MAGIC_BYTES = b'\x4b\x4f\x53\x49' # KOSI in ASCII (4 bytes)
XOR_KEY = 0xAA # Obfuscation Key (1 byte)
HEADER_SIZE = 5 # 4 bytes Magic + 1 byte Cipher ID

DEVICE_BINDING_FLAG = 0x80 

CRYPTO_HEADER_SIZE = HEADER_SIZE + METADATA_SIZE # 25 bytes

# --- KEY WRAPPING CONSTANTS ---
KEY_WRAP_NONCE_SIZE = 12
KEY_WRAP_TAG_SIZE = 16

CIPHER_ID_MAP = {
    0x01: "AES-256-GCM",
    0x02: "ChaCha20-Poly1305",
    0x03: "AES-256-CBC + HMAC",
}

# ----------------------------------------------------
# A. Progress Reporting & Utility Helper
# ----------------------------------------------------

class ProgressFileWrapper:
    """Wraps a file-like object to track and report read progress."""
    def __init__(self, file_object, total_size: int, callback: callable):
        self._file = file_object
        self.total_size = total_size
        self.bytes_read = 0
        self.callback = callback

    def read(self, size: int = -1) -> bytes:
        data = self._file.read(size)
        self.bytes_read += len(data)
        
        # Report progress: (bytes_read, total_size)
        if self.callback:
            self.callback(self.bytes_read, self.total_size)
            
        return data
        
    def __getattr__(self, name):
        """Delegate other file methods (e.g., seek, tell) to the wrapped file object."""
        return getattr(self._file, name)


def _get_obfuscated_header(cipher_id: int, is_device_bound: bool) -> bytes:
    """Creates the 5-byte header with an XOR-obfuscated cipher ID and sets the device binding flag."""
    
    # Apply Device Binding Flag if enabled
    if is_device_bound:
        cipher_id |= DEVICE_BINDING_FLAG
        
    obfuscated_id = cipher_id ^ XOR_KEY
    return MAGIC_BYTES + obfuscated_id.to_bytes(1, 'big')

def _decode_obfuscated_id(obfuscated_byte: int) -> tuple[int, bool]:
    """Decodes the cipher ID and checks for the device binding flag."""
    
    decoded_id_with_flag = obfuscated_byte ^ XOR_KEY
    
    # Check if the most significant bit (0x80) is set
    is_device_bound = (decoded_id_with_flag & DEVICE_BINDING_FLAG) != 0
    
    # Mask off the flag to get the pure cipher ID
    cipher_id = decoded_id_with_flag & (~DEVICE_BINDING_FLAG)
    
    return cipher_id, is_device_bound


def _create_metadata_prefix(salt: bytes) -> bytes:
    """Creates the 20-byte prefix (Iterations + Salt) to be placed after the 5-byte header."""
    if len(salt) != SALT_SIZE:
        raise KeyPreparationError(f"Salt must be exactly {SALT_SIZE} bytes.")
        
    # Use the globally defined KDF_ITERATIONS
    iteration_bytes = KDF_ITERATIONS.to_bytes(4, 'big')
    return iteration_bytes + salt


def _parse_metadata_prefix(metadata_bytes: bytes) -> tuple[bytes, int]:
    """Parses the 20-byte prefix (Iterations + Salt) from the file read buffer."""
    if len(metadata_bytes) != METADATA_SIZE:
        raise FileIntegrityError(f"File metadata size is incorrect. Expected {METADATA_SIZE} bytes.")
        
    iteration_bytes = metadata_bytes[:4]
    salt = metadata_bytes[4:METADATA_SIZE]
    
    iterations = int.from_bytes(iteration_bytes, 'big')
    
    return salt, iterations

def _get_device_hash() -> bytes:
    """
    Generates a device-specific hash by combining the machine's node ID (MAC) 
    and hostname. This hash serves as the Device ID for binding.
    """
    # 1. Get the primary hardware address (node)
    mac_int = uuid.getnode()
    
    # 2. Get the machine's hostname
    hostname = platform.node()
    
    # 3. Combine and Encode
    combined_id = f"{mac_int}-{hostname}".encode('utf-8')
    
    # 4. Hash the combined ID to a fixed size (SHA256)
    device_hash = hashlib.sha256(combined_id).digest()
    
    if len(device_hash) != DEVICE_ID_SIZE:
         raise KeyPreparationError("Internal error: Device hash size mismatch.")

    return device_hash


# ----------------------------------------------------
# 1. Key, Salt, and Key Wrapping Functions
# ----------------------------------------------------

def generate_random_salt() -> bytes:
    """Generates a cryptographically secure random salt."""
    return os.urandom(SALT_SIZE)

def generate_random_key() -> bytes:
    """Generates a cryptographically secure, random 32-byte key."""
    return os.urandom(KEY_SIZE)

def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS, device_id: bytes = None) -> bytes:
    """
    Derives secure key material (up to 64 bytes) from a password, a salt, 
    and optionally a device_id using PBKDF2.
    """
    password_bytes = password.strip().encode() 
    
    # Concatenate device_id to the password material if provided (for device binding)
    kdf_input = password_bytes
    if device_id is not None:
        if len(device_id) != DEVICE_ID_SIZE:
             raise KeyPreparationError("Invalid Device ID size passed to derive_key.")
        # Concatenate the device hash to the password bytes for KDF input
        kdf_input = password_bytes + device_id 
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE * 2, 
        salt=salt,
        iterations=iterations, 
        backend=default_backend()
    )
    
    return kdf.derive(kdf_input)

def generate_cbc_keys(master_key_material: bytes):
    """Splits the 64-byte derived key into two 32-byte keys for CBC+HMAC."""
    if len(master_key_material) < KEY_SIZE * 2:
         raise KeyPreparationError("Insufficient key material for CBC+HMAC derivation.")
         
    cipher_key = master_key_material[:KEY_SIZE] 
    hmac_key = master_key_material[KEY_SIZE:KEY_SIZE * 2] 
    return cipher_key, hmac_key

def wrap_key(raw_key: bytes, passphrase: str) -> bytes:
    """
    Encrypts a raw key using AES-256-GCM derived from a passphrase and a new salt.
    Returns: [SALT (16b) + NONCE (12b) + TAG (16b) + Wrapped Key].
    """
    # 1. Derive AES key for wrapping
    wrap_salt = generate_random_salt()
    wrap_key_material = derive_key(passphrase, wrap_salt)[:KEY_SIZE]
    
    # 2. Encrypt (Wrap) the key
    nonce = os.urandom(KEY_WRAP_NONCE_SIZE)
    cipher = Cipher(algorithms.AES(wrap_key_material), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    wrapped_key = encryptor.update(raw_key) + encryptor.finalize()
    tag = encryptor.tag 
    
    # 3. Assemble the payload
    return wrap_salt + nonce + tag + wrapped_key


def unwrap_key(wrapped_data: bytes, passphrase: str) -> bytes:
    """
    Decrypts the wrapped key using AES-256-GCM derived from the passphrase and embedded salt.
    Returns: The raw encryption/decryption key.
    """
    
    if len(wrapped_data) < SALT_SIZE + KEY_WRAP_NONCE_SIZE + KEY_WRAP_TAG_SIZE:
        raise KeyPreparationError("Invalid wrapped key format or size.")

    # 1. Separate components
    wrap_salt = wrapped_data[:SALT_SIZE]
    nonce = wrapped_data[SALT_SIZE : SALT_SIZE + KEY_WRAP_NONCE_SIZE]
    tag = wrapped_data[SALT_SIZE + KEY_WRAP_NONCE_SIZE : SALT_SIZE + KEY_WRAP_NONCE_SIZE + KEY_WRAP_TAG_SIZE]
    wrapped_key = wrapped_data[SALT_SIZE + KEY_WRAP_NONCE_SIZE + KEY_WRAP_TAG_SIZE:]
    
    # 2. Derive the AES key for unwrapping (must use the embedded salt)
    wrap_key_material = derive_key(passphrase, wrap_salt)[:KEY_SIZE]
    
    # 3. Decrypt (Unwrap) the key
    cipher = Cipher(algorithms.AES(wrap_key_material), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        raw_key = decryptor.update(wrapped_key) + decryptor.finalize()
        return raw_key
        
    except InvalidTag:
        raise KeyPreparationError("Key unwrapping failed. Incorrect passphrase or corrupted key file.")
    except Exception as e:
        raise KeyPreparationError(f"Key unwrapping failed: {e}")

# ----------------------------------------------------
# 2. File Handling Functions (AES-256-GCM) - Streaming I/O
# ----------------------------------------------------

def encrypt_file_aes_gcm(input_filepath: str, output_filepath: str, key: bytes, salt: bytes, progress_callback: callable = None, is_device_bound: bool = False):
    """
    Encrypts a file using AES-256-GCM with streaming I/O.
    Structure: [5b Header] + [20b Metadata] + [12b Nonce] + [16b Tag] + [Ciphertext]
    """
    
    total_size = os.path.getsize(input_filepath)

    # 1. Prepare Header and Cipher components
    header = _get_obfuscated_header(0x01, is_device_bound)
    metadata = _create_metadata_prefix(salt)
    nonce = os.urandom(12) 

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_filepath, 'rb') as f_in, open(output_filepath, 'wb') as f_out:
        
        # Write HEADER (5b) + METADATA (20b) + NONCE (12b) first
        f_out.write(header + metadata + nonce) 
        
        # Skip 16 bytes for the GCM Tag (we write it at the end)
        tag_position = f_out.tell() 
        f_out.write(b'\x00' * 16) 

        # Wrap the input file for progress reporting
        p_in = ProgressFileWrapper(f_in, total_size, progress_callback)
        
        # --- STREAMING LOOP ---
        while True:
            chunk = p_in.read(BUFFER_SIZE)
            
            if not chunk:
                break
            
            # Encrypt and write immediately
            ciphertext_chunk = encryptor.update(chunk)
            f_out.write(ciphertext_chunk)

        # 2. Finalize encryption and get the tag
        ciphertext_final = encryptor.finalize()
        tag = encryptor.tag
        
        f_out.write(ciphertext_final)
        
        # 3. Go back and write the final tag
        f_out.seek(tag_position)
        f_out.write(tag)
        
        # Return to end for proper file closing
        f_out.seek(0, 2)


def decrypt_file_aes_gcm(input_filepath: str, output_filepath: str, key: bytes, progress_callback: callable = None):
    """
    Decrypts a file encrypted with AES-256-GCM using streaming I/O.
    """
    
    NONCE_SIZE = 12
    TAG_SIZE = 16
    
    HEADER_NONCE_TAG_SIZE = CRYPTO_HEADER_SIZE + NONCE_SIZE + TAG_SIZE 
    total_size = os.path.getsize(input_filepath)
    
    with open(input_filepath, 'rb') as f_in, open(output_filepath, 'wb') as f_out:
        
        # 1. Read header, metadata, nonce, and tag
        header_data = f_in.read(HEADER_NONCE_TAG_SIZE)
        if len(header_data) < HEADER_NONCE_TAG_SIZE:
             raise FileIntegrityError("Encrypted file too small or corrupted.")

        # Extract Nonce and Tag relative to the CRYPTO_HEADER_SIZE offset
        nonce = header_data[CRYPTO_HEADER_SIZE : CRYPTO_HEADER_SIZE + NONCE_SIZE]
        tag = header_data[CRYPTO_HEADER_SIZE + NONCE_SIZE : HEADER_NONCE_TAG_SIZE]
        
        # 2. Initialize Decryptor
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        bytes_processed = 0
        ciphertext_size = total_size - HEADER_NONCE_TAG_SIZE

        # 3. STREAMING DECRYPTION
        while bytes_processed < ciphertext_size:
            read_size = min(BUFFER_SIZE, ciphertext_size - bytes_processed)
            chunk = f_in.read(read_size)
            
            if not chunk: 
                break
            
            # Decrypt and write immediately
            plaintext_chunk = decryptor.update(chunk)
            f_out.write(plaintext_chunk)
            
            bytes_processed += len(chunk)
            
            # Report progress
            if progress_callback:
                current_read = HEADER_NONCE_TAG_SIZE + bytes_processed
                progress_callback(current_read, total_size)

        # 4. Finalize Decryption (which verifies the tag)
        try:
            plaintext_final = decryptor.finalize()
            f_out.write(plaintext_final)
            
        except InvalidTag as e:
            # The InvalidTag is raised if the key is wrong OR the device ID was wrong.
            raise FileIntegrityError(f"Invalid key or corrupted file (Invalid Tag).") from e
        except Exception as e:
            raise FileIntegrityError(f"Decryption failed due to: {e}")


# ----------------------------------------------------
# 3. File Handling Functions (ChaCha20-Poly1305) - Single Read (Streaming I/O Read/Write)
# ----------------------------------------------------

def encrypt_file_chacha(input_filepath: str, output_filepath: str, key: bytes, salt: bytes, progress_callback: callable = None, is_device_bound: bool = False):
    """
    Encrypts a file using ChaCha20-Poly1305 AEAD primitive. 
    Structure: [5b Header] + [20b Metadata] + [12b Nonce] + [Ciphertext] + [16b Tag]
    """
    
    total_size = os.path.getsize(input_filepath)
    
    # 1. Prepare Header and Cipher components
    header = _get_obfuscated_header(0x02, is_device_bound)
    metadata = _create_metadata_prefix(salt)
    nonce = os.urandom(12) 
    
    chacha = ChaCha20Poly1305(key)
    plaintext = b'' 
    
    with open(input_filepath, 'rb') as f_in, open(output_filepath, 'wb') as f_out:
        
        # Wrap the input file for chunked reading and progress reporting
        p_in = ProgressFileWrapper(f_in, total_size, progress_callback)
        
        # --- CHUNKED READING LOOP (Streaming I/O to build buffer) ---
        while True:
            chunk = p_in.read(BUFFER_SIZE)
            if not chunk:
                break
            plaintext += chunk
            
        if progress_callback: 
            progress_callback(total_size, total_size, "Finalizing Encryption (One-Shot AEAD)...")

        # 2. One-Shot Encryption
        ciphertext_with_tag = chacha.encrypt(nonce, plaintext, associated_data=None)

        # 3. Write all data
        f_out.write(header + metadata + nonce + ciphertext_with_tag) 


def decrypt_file_chacha(input_filepath: str, output_filepath: str, key: bytes, progress_callback: callable = None):
    """
    Decrypts a file encrypted with ChaCha20-Poly1305 AEAD primitive.
    Reads the full file data in one go for the single-shot decrypt call.
    """
    
    NONCE_SIZE = 12
    NONCE_START = CRYPTO_HEADER_SIZE
    
    total_size = os.path.getsize(input_filepath)
    
    with open(input_filepath, 'rb') as f_in, open(output_filepath, 'wb') as f_out:
        
        # 1. Read all file data at once (Required for single-shot AEAD)
        # Use the wrapper to show progress on reading the input file, even if non-streaming
        p_in = ProgressFileWrapper(f_in, total_size, progress_callback)
        data = p_in.read(total_size) 
        
        if len(data) < NONCE_START + NONCE_SIZE + 16:
            raise FileIntegrityError("Encrypted file appears corrupted or incomplete.")

        # Separate the components (Nonce, Ciphertext + Tag)
        nonce = data[NONCE_START : NONCE_START + NONCE_SIZE]   
        ciphertext_with_tag = data[NONCE_START + NONCE_SIZE :] 
        
        if progress_callback:
            progress_callback(total_size, total_size, "Reading Complete. Starting Decryption...") 
        
        chacha = ChaCha20Poly1305(key)
        
        try:
            # 2. Decrypt the buffered data (One-Shot Decryption)
            plaintext = chacha.decrypt(nonce, ciphertext_with_tag, associated_data=None)
            
            # 3. Write the plaintext back to the output file
            f_out.write(plaintext)
            
            if progress_callback:
                progress_callback(total_size, total_size, "Decryption Complete.")
                
        except InvalidTag as e:
            # The InvalidTag is raised if the key is wrong OR the device ID was wrong.
            raise FileIntegrityError("Decryption failed. Invalid key, wrong algorithm, or file corrupted (Invalid Tag).") from e
        except Exception as e:
            raise FileIntegrityError(f"Decryption failed due to an unexpected error: {e}")


# ----------------------------------------------------
# 4. File Handling Functions (AES-256-CBC + HMAC) - Streaming
# ----------------------------------------------------

def encrypt_file_aes_cbc(input_filepath: str, output_filepath: str, key_material: bytes, salt: bytes, progress_callback: callable = None, is_device_bound: bool = False):
    """
    Encrypts a file using AES-256-CBC and authenticates with HMAC-SHA256, using streaming.
    Structure: [5b Header] + [20b Metadata] + [16b IV] + [32b HMAC Tag] + [Ciphertext]
    """
    cipher_key, hmac_key = generate_cbc_keys(key_material)
    
    total_size = os.path.getsize(input_filepath)
        
    # 1. Prepare Header and Cipher components
    header = _get_obfuscated_header(0x03, is_device_bound)
    metadata = _create_metadata_prefix(salt)
    iv = os.urandom(algorithms.AES.block_size // 8) # 16 bytes IV

    # Initialize components
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    
    # HMAC starts with IV
    h.update(iv)
    
    with open(input_filepath, 'rb') as f_in, open(output_filepath, 'wb') as f_out:
        
        # Write header, metadata, and IV first
        f_out.write(header + metadata + iv) 
        
        # Skip 32 bytes for the HMAC tag (we write it at the end)
        tag_position = f_out.tell() 
        f_out.write(b'\x00' * HMAC_SIZE) 

        # Wrap the input file for progress reporting
        p_in = ProgressFileWrapper(f_in, total_size, progress_callback)

        while True:
            chunk = p_in.read(BUFFER_SIZE)
            
            if not chunk:
                break
            
            # 1. Pad and encrypt the chunk
            padded_chunk = padder.update(chunk)
            ciphertext_chunk = encryptor.update(padded_chunk)
            
            # 2. Update HMAC with ciphertext and write ciphertext
            h.update(ciphertext_chunk)
            f_out.write(ciphertext_chunk)
            
        # Handle final padding and encryption
        final_padded = padder.finalize()
        final_ciphertext = encryptor.update(final_padded) + encryptor.finalize()
        
        h.update(final_ciphertext)
        f_out.write(final_ciphertext)
        
        # Finalize HMAC
        tag = h.finalize()
        
        # Go back and write the final tag
        f_out.seek(tag_position)
        f_out.write(tag)
        
        # Return to end for proper file closing
        f_out.seek(0, 2)


def decrypt_file_aes_cbc(input_filepath: str, output_filepath: str, key_material: bytes, progress_callback: callable = None):
    """
    Decrypts and verifies a file encrypted with AES-256-CBC and HMAC-SHA256, using streaming.
    """
    cipher_key, hmac_key = generate_cbc_keys(key_material)
    
    total_size = os.path.getsize(input_filepath)
    block_size_bytes = algorithms.AES.block_size // 8 # 16 bytes
    
    HEADER_IV_TAG_SIZE = CRYPTO_HEADER_SIZE + block_size_bytes + HMAC_SIZE

    with open(input_filepath, 'rb') as f_in, open(output_filepath, 'wb') as f_out:
        
        # Read header, metadata, IV, and tag
        header_iv_tag_data = f_in.read(HEADER_IV_TAG_SIZE)
        if len(header_iv_tag_data) < HEADER_IV_TAG_SIZE:
             raise FileIntegrityError("Encrypted file too small or corrupted.")

        # Extract IV and Tag relative to CRYPTO_HEADER_SIZE offset
        iv = header_iv_tag_data[CRYPTO_HEADER_SIZE : CRYPTO_HEADER_SIZE + block_size_bytes]
        tag = header_iv_tag_data[CRYPTO_HEADER_SIZE + block_size_bytes : HEADER_IV_TAG_SIZE]
        
        # Initialize components
        decryptor = Cipher(algorithms.AES(cipher_key), modes.CBC(iv), backend=default_backend()).decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        
        # HMAC starts with IV
        h.update(iv)
        
        ciphertext_size = total_size - HEADER_IV_TAG_SIZE
        bytes_processed = 0
        last_chunk = b''

        # 1. Stream Decryption and HMAC Verification
        while bytes_processed < ciphertext_size:
            read_size = min(BUFFER_SIZE, ciphertext_size - bytes_processed)
            chunk = f_in.read(read_size)
            
            if not chunk: # End of file
                break
            
            # Update HMAC *before* decryption
            h.update(chunk) 
            
            # Decrypt: Process the last chunk of ciphertext from the previous iteration 
            # and append the new chunk for processing in the next iteration.
            decrypted_data = decryptor.update(last_chunk)
            f_out.write(unpadder.update(decrypted_data))

            last_chunk = chunk # Store current chunk as the "last chunk" for the next iteration
            bytes_processed += len(chunk)
            
            # Report progress
            if progress_callback:
                current_read = HEADER_IV_TAG_SIZE + bytes_processed
                progress_callback(current_read, total_size)


        # 2. Final HMAC Verification
        try:
            h.verify(tag)
        except Exception:
            # If HMAC verification fails, it could be due to a device ID mismatch
            raise FileIntegrityError("HMAC verification failed. Invalid password, wrong key, or file corrupted (Integrity Error).")

        # 3. Final Decryption and Unpadding
        try:
            # Process the very last chunk and finalize the decryptor
            decrypted_data = decryptor.update(last_chunk) + decryptor.finalize()
            plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
            
            f_out.write(plaintext)
            
        except Exception as e:
            raise FileIntegrityError("Decryption failed. Invalid password, wrong key, or padding error (Decryption Error).") from e


# ----------------------------------------------------
# 5. Archival Folder Handling
# ----------------------------------------------------

def encrypt_folder_archival(input_dir: str, output_filepath: str, key: bytes, salt: bytes, encrypt_func, progress_callback: callable = None, is_device_bound: bool = False):
    """
    Archives a folder, encrypts the archive using the specified function, and cleans up.
    """
    if not os.path.isdir(input_dir):
        raise FileIntegrityError(f"Input is not a directory: {input_dir}")
        
    temp_archive_base = os.path.splitext(output_filepath)[0]
    temp_archive_path = temp_archive_base + ".temp.tar"
    
    try:
        if progress_callback: progress_callback(0, 1, "Archiving folder...")
        
        shutil.make_archive(
            os.path.splitext(temp_archive_path)[0], 
            'tar', 
            root_dir=os.path.dirname(input_dir), 
            base_dir=os.path.basename(input_dir)
        )
        
        # 2. Encrypt the single archive file using the passed function
        if progress_callback: progress_callback(0, 1, "Encrypting archive...")
        
        # Pass the salt and the new is_device_bound parameter
        encrypt_func(temp_archive_path, output_filepath, key, salt, progress_callback, is_device_bound) 

    finally:
        # 3. Cleanup: Delete the temporary archive file
        if os.path.exists(temp_archive_path):
            os.remove(temp_archive_path)

def decrypt_folder_archival(input_filepath: str, output_dir: str, key: bytes, decrypt_func, progress_callback: callable = None):
    """
    Decrypts a single encrypted file (which is an archive) and extracts its contents.
    """
    if not os.path.isfile(input_filepath):
        raise FileIntegrityError(f"Input is not a single file: {input_filepath}")
        
    temp_archive_path = os.path.splitext(input_filepath)[0] + ".temp_tar"
    
    try:
        if progress_callback: progress_callback(0, 1, "Decrypting archive...")
        
        decrypt_func(input_filepath, temp_archive_path, key, progress_callback) 
        
        if progress_callback: progress_callback(0, 1, "Extracting files...")
        os.makedirs(output_dir, exist_ok=True)
        
        with tarfile.open(temp_archive_path, 'r') as tar:
            tar.extractall(path=output_dir)
        
        if progress_callback: progress_callback(1, 1, "Extraction complete.")


    finally:
        if os.path.exists(temp_archive_path):
            os.remove(temp_archive_path)