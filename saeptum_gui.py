import customtkinter as ctk
from tkinter import filedialog, messagebox, simpledialog
import os
import sys
import threading
import time 

# Import the secure core functions
from saeptum_core import (
    derive_key, 
    generate_random_salt,
    generate_random_key, 
    encrypt_folder_archival, 
    decrypt_folder_archival, 
    KEY_SIZE, 
    SALT_SIZE,
    
    # --- KEY WRAPPING IMPORTS ---
    wrap_key,
    unwrap_key,
    
    # --- ALGORITHM IMPORTS ---
    encrypt_file_aes_gcm, 
    decrypt_file_aes_gcm,
    encrypt_file_chacha,
    decrypt_file_chacha,
    encrypt_file_aes_cbc,
    decrypt_file_aes_cbc,
    
    # IMPORTS FOR HEADER IDENTIFICATION
    MAGIC_BYTES,
    HEADER_SIZE,
    CIPHER_ID_MAP,
    _decode_obfuscated_id,
    
    # --- METADATA IMPORTS ---
    KDF_ITERATIONS,
    CRYPTO_HEADER_SIZE,
    _create_metadata_prefix,
    _parse_metadata_prefix,
    
    # --- DEVICE BINDING IMPORTS ---
    _get_device_hash,
    DeviceBindingError,
    
    # --- EXCEPTION IMPORTS ---
    KosiCryptoError,
    KeyPreparationError,
    FileIntegrityError
)

# Set the appearance mode and default color theme
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

# --- ALGORITHM MAPPING ---
ALGORITHM_MAP = {
    "AES-256-GCM": (encrypt_file_aes_gcm, decrypt_file_aes_gcm),
    "ChaCha20-Poly1305": (encrypt_file_chacha, decrypt_file_chacha),
    "AES-256-CBC + HMAC": (encrypt_file_aes_cbc, decrypt_file_aes_cbc),
}

class FileEncryptorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Basic Window Setup ---
        self.title("Saeptum Crypt")
        self.geometry("600x823") 
        self.resizable(False, False)
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing) 

        # --- Variables to hold file paths and settings ---
        self.input_file_path = ctk.StringVar(value="")
        self.output_file_path = ctk.StringVar(value="")
        self.password = ctk.StringVar()
        self.operation_mode = ctk.StringVar(value="Encrypt") 

        # Input Type Selector
        self.input_type = ctk.StringVar(value="File")
        
        # Key Handling Mode and Path
        self.key_mode = ctk.StringVar(value="Password")
        self.key_file_path = ctk.StringVar(value="")
        self.key_passphrase = ctk.StringVar(value="") 
        
        # --- DEVICE BINDING VARIABLE ---
        self.device_binding_enabled = ctk.BooleanVar(value=False)
        self.is_file_device_bound = ctk.BooleanVar(value=False) # Stores header status
        self.device_binding_checkbox = None 
        
        # --- Temporary storage for key material ---
        self.unwrapped_key_material = None 
        
        # --- Cipher Algorithm Selection ---
        self.cipher_algorithm = ctk.StringVar(value="AES-256-GCM") 
        
        # Threading variables
        self.worker_thread = None
        self.operation_success = None
        self.operation_error = None
        self.check_interval_ms = 100 
        
        # Progress tracking variables 
        self.progress_bytes_read = 0
        self.progress_total_size = 0
        self.progress_status_text = ""
        self.last_progress_update = 0
        self.min_update_delay = 0.1 

        # Widget references needed for dynamic access
        self.input_type_frame = None
        self.input_path_label = None
        self.folder_radio = None 
        self.file_radio = None 
        self.mode_selector = None 
        
        self.algorithm_label = None 
        self.algorithm_optionmenu = None
        self.password_entry = None 
        self.password_label = None
        self.password_input_container = None


        # --- Grid Configuration ---
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(padx=20, pady=20, fill="both", expand=True)
        
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        
        # --- GUI Elements ---
        self._create_widgets()
        
        self._on_operation_mode_change() 

    # Cleanup function for graceful exit
    def on_closing(self):
        """Handle window close event to ensure threads are terminated."""
        if self.worker_thread and self.worker_thread.is_alive():
            if messagebox.askyesno(
                "Process Running", 
                "An operation is currently running. Do you want to force quit the application?"
            ):
                self.destroy() 
            else:
                return 
        else:
            self.destroy()

    # --- Helper function to create file selectors with parent frame ---
    def _create_file_selector(self, row: int, parent_frame: ctk.CTkFrame, label_text: str, entry_var: ctk.StringVar, command, label_pady=(15, 5)):
        """Creates file path widgets inside a specific parent frame."""
        
        label = ctk.CTkLabel(parent_frame, text=label_text)
        label.grid(row=row, column=0, columnspan=2, pady=label_pady, sticky="w", padx=10)
        
        selector_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        selector_frame.grid(row=row + 1, column=0, columnspan=2, sticky="ew", padx=10)
        selector_frame.columnconfigure(0, weight=1)

        entry = ctk.CTkEntry(
            selector_frame, 
            textvariable=entry_var, 
            placeholder_text="Click 'Browse' to select a path..."
        )
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))

        button = ctk.CTkButton(
            selector_frame, 
            text="Browse", 
            command=command,
            width=80
        )
        button.grid(row=0, column=1, sticky="e")
        
        return label 

    # --- Widget Creation ---
    def _create_widgets(self):
        
        PADX = 20
        PADY_SECTION = 15
        
        # 1. Title Label
        title_label = ctk.CTkLabel(
            self.main_frame, 
            text="Saeptum Crypt: Secure File Encryption Utility", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(10, 25), sticky="n")

        # 2. Operation Mode Selector 
        mode_label = ctk.CTkLabel(self.main_frame, text="Operation Mode:")
        mode_label.grid(row=1, column=0, columnspan=2, pady=(0, 5), sticky="w", padx=PADX) 
        
        self.mode_selector = ctk.CTkSegmentedButton(
            self.main_frame,
            values=["Encrypt", "Decrypt"],
            variable=self.operation_mode,
            command=self._on_operation_mode_change
        )
        self.mode_selector.grid(row=2, column=0, columnspan=2, padx=PADX, pady=(0, PADY_SECTION), sticky="ew")

        # --- CONTAINER FRAME 1: INPUT/OUTPUT ---
        path_frame = ctk.CTkFrame(self.main_frame)
        path_frame.grid(row=3, column=0, columnspan=2, padx=PADX, pady=(0, PADY_SECTION), sticky="ew")
        path_frame.columnconfigure(0, weight=1)
        
        # 3. Input Type Selector 
        input_type_label = ctk.CTkLabel(path_frame, text="Input Type:")
        input_type_label.grid(row=0, column=0, columnspan=2, pady=(0, 5), sticky="w", padx=10)
        
        radio_frame = ctk.CTkFrame(path_frame, fg_color="transparent")
        radio_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 5), sticky="ew")
        
        self.file_radio = ctk.CTkRadioButton(
            radio_frame, text="Single File", variable=self.input_type, value="File"
        )
        self.file_radio.pack(side="left", padx=5) 
        
        self.folder_radio = ctk.CTkRadioButton(
            radio_frame, text="Entire Folder (Archive)", variable=self.input_type, value="Folder"
        )
        self.folder_radio.pack(side="left", padx=20) 

        # 4. Input Path Selection 
        self._create_file_selector(
            row=2, parent_frame=path_frame, label_text="Input Path:", entry_var=self.input_file_path, command=self.select_input_file, label_pady=(5, 5)
        )
        
        # 5. Output Path Selection 
        self._create_file_selector(
            row=4, parent_frame=path_frame, label_text="Output Path:", entry_var=self.output_file_path, command=self.select_output_file, label_pady=(5, 5)
        )
        
        path_frame.grid_rowconfigure(6, minsize=10) 


        # --- CONTAINER FRAME 2: KEY & ALGORITHM SETTINGS ---
        settings_frame = ctk.CTkFrame(self.main_frame)
        self.settings_frame = settings_frame
        settings_frame.grid(row=4, column=0, columnspan=2, padx=PADX, pady=(0, PADY_SECTION), sticky="ew")
        settings_frame.columnconfigure(0, weight=1)

        # 6. Key Handling Mode Selection
        key_mode_label = ctk.CTkLabel(settings_frame, text="Key/Password Source:")
        key_mode_label.grid(row=0, column=0, columnspan=2, pady=(10, 5), sticky="w", padx=10)
        
        self.key_mode_optionmenu = ctk.CTkOptionMenu(
            settings_frame,
            values=["Password", "Key File"],
            variable=self.key_mode,
        )
        self.key_mode_optionmenu.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        
        self.key_mode_optionmenu.configure(command=self._on_key_mode_change)

        # Dynamic Key Input Frame 
        self.key_input_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
        self.key_input_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10) 
        self.key_input_frame.columnconfigure(0, weight=1)
        self._create_dynamic_key_widgets(self.key_mode.get(), label_padx=0) 
        
        # 7. Algorithm Selector 
        self.algorithm_label = ctk.CTkLabel(settings_frame, text="Select Algorithm:")
        self.algorithm_label.grid(row=3, column=0, columnspan=2, pady=(15, 5), sticky="w", padx=10)
        
        self.algorithm_optionmenu = ctk.CTkOptionMenu(
            settings_frame,
            values=list(ALGORITHM_MAP.keys()), 
            variable=self.cipher_algorithm, 
        )
        self.algorithm_optionmenu.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 10))
        
        # --- Device Binding Checkbox ---
        self.device_binding_checkbox = ctk.CTkCheckBox(
            settings_frame,
            text="Enable Device Binding (Decrypts only on this device)",
            variable=self.device_binding_enabled
        )
        self.device_binding_checkbox.grid(row=5, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 10))


        # 8. Action Button
        self.action_button = ctk.CTkButton(
            self.main_frame, 
            text="START OPERATION", 
            command=self.start_operation,
            height=40,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.action_button.grid(row=5, column=0, columnspan=2, sticky="ew", padx=PADX, pady=(20, 20))
        
        # 9. Status/Progress Bar and Label
        self.progress_bar = ctk.CTkProgressBar(
            self.main_frame, 
            orientation="horizontal", 
            mode="determinate" 
        )
        self.progress_bar.set(0) 
        self.progress_bar.grid(row=6, column=0, columnspan=2, sticky="ew", padx=PADX, pady=(5, 5)) 

        self.status_label = ctk.CTkLabel(
            self.main_frame, 
            text="", 
            fg_color="transparent",
            text_color="gray"
        )
        self.status_label.grid(row=7, column=0, columnspan=2, pady=(5, 10), sticky="n")


    # --- Utility: Passphrase Dialog ---
    def _get_passphrase_dialog(self, title, prompt):
        """Displays a simple dialog to securely input a passphrase."""
        dialog = ctk.CTkInputDialog(
            text=prompt, 
            title=title
        )
        return dialog.get_input()

    # --- Check and Set Cipher Header ---
    def _check_and_set_cipher_header(self, input_path: str):
        """
        Reads the obfuscated header, sets the cipher_algorithm, and checks the 
        device binding flag, updating the UI accordingly.
        """
        # Always enable the option menu and binding checkbox if we are in Encrypt mode.
        if self.operation_mode.get() == "Encrypt":
             self.algorithm_optionmenu.configure(state="normal")
             self.device_binding_checkbox.configure(state="normal")
             return
             
        # Decrypt Mode: Assume manual selection is possible unless auto-detection succeeds
        self.algorithm_optionmenu.configure(state="normal")
        self.device_binding_checkbox.configure(state="disabled") 
        self.is_file_device_bound.set(False) 
        self.status_label.configure(text="")

        if not os.path.isfile(input_path):
            self.cipher_algorithm.set("AES-256-GCM") 
            return

        try:
            with open(input_path, 'rb') as f:
                header_data = f.read(HEADER_SIZE)
                
            if len(header_data) < HEADER_SIZE:
                self.status_label.configure(text="Decryption: File too small for header check.")
                return
                
            magic = header_data[:4]
            obfuscated_byte_int = header_data[4]
            
            if magic == MAGIC_BYTES:
                cipher_id, is_device_bound = _decode_obfuscated_id(obfuscated_byte_int)
                
                if cipher_id in CIPHER_ID_MAP:
                    cipher_name = CIPHER_ID_MAP[cipher_id]
                    self.cipher_algorithm.set(cipher_name)
                    
                    # Lock the selector to the detected cipher
                    self.algorithm_optionmenu.configure(state="disabled")
                    
                    # Update binding status and GUI based on header flag
                    self.is_file_device_bound.set(is_device_bound)
                    self.device_binding_enabled.set(is_device_bound)
                    
                    status_text = f"Cipher identified: {cipher_name}"
                    if is_device_bound:
                        status_text += " (Device-Bound)"
                    
                    self.status_label.configure(text=status_text)
                    
                else:
                    self.status_label.configure(text="Decryption: Cipher ID not recognized. Select manually.")

            else:
                self.status_label.configure(text="Decryption: Custom header not found. Select manually.")

        except Exception as e:
            self.status_label.configure(text=f"Decryption: Error reading file header.")


    # --- UI Logic on Mode Change ---
    def _on_operation_mode_change(self, *args):
        """
        Clears paths, auto-selects Single File, and updates the UI for the new mode.
        """
        # 1. Clear paths and flags
        self.input_file_path.set("")
        self.output_file_path.set("")
        self.unwrapped_key_material = None 
        self.is_file_device_bound.set(False)
        self.device_binding_enabled.set(False)

        # 2. Get current mode
        current_mode = self.operation_mode.get()

        if current_mode == "Encrypt":
            # Encrypt Mode: Enable all inputs, allow algorithm and binding selection
            self.folder_radio.configure(state="normal")
            self.file_radio.configure(state="normal")
            self.input_type.set("File")
            
            self.algorithm_label.configure(text="Select Encryption Algorithm:")
            self.algorithm_optionmenu.configure(state="normal") 
            self.cipher_algorithm.set("AES-256-GCM")
            
            self.device_binding_checkbox.configure(state="normal")

            
        else: # Decrypt Mode
            # Decrypt Mode: Dim Folder button, lock down settings
            self.folder_radio.configure(state="disabled") 
            self.file_radio.configure(state="normal") 
            self.input_type.set("File") 
            
            self.algorithm_label.configure(text="Detected Decryption Algorithm:")
            self.algorithm_optionmenu.configure(state="disabled") 
            self.cipher_algorithm.set("AES-256-GCM") 
            
            self.device_binding_checkbox.configure(state="disabled")

    # --- Password Visibility Toggle ---
    def _toggle_password_visibility(self):
        """Toggles the 'show' property of the password entry widget."""
        if self.password_entry:
            current_show = self.password_entry.cget("show")
            if current_show == "*":
                self.password_entry.configure(show="")
            else:
                self.password_entry.configure(show="*")


    # --- Dynamic Key Widget Methods ---
    def _create_dynamic_key_widgets(self, mode: str, label_padx: int):
        """Creates the appropriate input widgets (password or key file) based on the mode."""
        
        # Destroy existing widgets in the dynamic frame
        for widget in self.key_input_frame.winfo_children():
            widget.destroy()

        if mode == "Password":
            # --- PASSWORD MODE WIDGETS ---
            
            # Label
            self.password_label = ctk.CTkLabel(self.key_input_frame, text="Enter Password:")
            self.password_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5), padx=label_padx) 

            # Container for Entry and Checkbox
            self.password_input_container = ctk.CTkFrame(self.key_input_frame, fg_color="transparent")
            self.password_input_container.grid(row=1, column=0, columnspan=2, sticky="ew")
            self.password_input_container.columnconfigure(0, weight=1)
            
            self.password_entry = ctk.CTkEntry(
                self.password_input_container, 
                textvariable=self.password, 
                show="*",
                placeholder_text="Enter your secure password"
            )
            self.password_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
            
            # View Password Checkbox
            view_checkbox = ctk.CTkCheckBox(
                self.password_input_container,
                text="View Password",
                command=self._toggle_password_visibility
            )
            view_checkbox.grid(row=0, column=1, sticky="e")


        elif mode == "Key File":
            # --- KEY FILE MODE WIDGETS ---
            
            key_file_label = ctk.CTkLabel(self.key_input_frame, text="Key File Path:")
            key_file_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5), padx=label_padx)

            key_file_entry = ctk.CTkEntry(
                self.key_input_frame, 
                textvariable=self.key_file_path, 
                placeholder_text="Browse or click 'Generate' to create a new key file"
            )
            key_file_entry.grid(row=1, column=0, sticky="ew", padx=(0, 10))

            button_frame = ctk.CTkFrame(self.key_input_frame, fg_color="transparent")
            button_frame.grid(row=1, column=1, sticky="e")
            
            browse_button = ctk.CTkButton(
                button_frame, text="Browse", command=self._select_key_file, width=80
            )
            browse_button.pack(side="left", padx=(0, 5))
            
            generate_button = ctk.CTkButton(
                button_frame, text="Generate", command=self._generate_key_file, width=80
            )
            generate_button.pack(side="left")


    def _on_key_mode_change(self, choice):
        """Called when the user selects a different key mode."""
        self.unwrapped_key_material = None 
        self._create_dynamic_key_widgets(choice, label_padx=0) 

    # --- Key File Generation and Saving ---
    def _generate_key_file(self):
        """Generates a new random key, prompts for a passphrase, wraps the key, and saves it."""
        
        algorithm_name = self.cipher_algorithm.get()
        is_cbc_hmac_cipher = algorithm_name in ["AES-256-CBC + HMAC"]
        # Key file must be the right size for the selected algorithm (32 or 64 bytes)
        key_length_needed = KEY_SIZE * 2 if is_cbc_hmac_cipher else KEY_SIZE

        # 1. Prompt for Key Wrapping Passphrase
        passphrase = self._get_passphrase_dialog(
            "Secure Key Wrap", 
            "Enter a passphrase to protect the new key file (REQUIRED):"
        )
        if not passphrase:
            messagebox.showwarning("Key Error", "Passphrase is required to securely wrap the key file.")
            return

        # 2. Determine suggested filename based on current input file
        input_path = self.input_file_path.get()
        if input_path and os.path.exists(input_path):
            base_name = os.path.splitext(os.path.basename(input_path))[0]
            initial_file = base_name + ".wkey"
        else:
            initial_file = "new_secret.wkey"

        file_path = filedialog.asksaveasfilename(
            title="Save New Secure Key File",
            initialfile=initial_file,
            defaultextension=".wkey",
            filetypes=[("Wrapped Key Files", "*.wkey")]
        )
        
        if file_path:
            try:
                # 3. Generate the raw, random encryption key
                raw_random_key = os.urandom(key_length_needed) 
                
                # 4. Wrap the key using the user's passphrase
                wrapped_data = wrap_key(raw_random_key, passphrase)
                
                with open(file_path, 'wb') as f:
                    f.write(wrapped_data)
                
                self.key_file_path.set(file_path)
                
                messagebox.showwarning(
                    "🔑 SECURE KEY GENERATED & SAVED", 
                    f"A new secure key ({key_length_needed}-byte raw key) has been saved to:\n{file_path}\n\n"
                    "🚨 WARNING: You must remember the wrapping passphrase and back up this file."
                )
                self.status_label.configure(text="")
            except Exception as e:
                messagebox.showerror("Key Error", f"Failed to save key file: {e}")


    # --- Key File Selection ---
    def _select_key_file(self):
        """Opens a file dialog for selecting an existing key file (.key or .wkey)"""
        self.unwrapped_key_material = None 
        
        file_path = filedialog.askopenfilename(
            title="Select Encryption Key File",
            defaultextension=".wkey",
            filetypes=[("Wrapped Key Files", "*.wkey"), ("Raw Key Files (Insecure)", "*.key")]
        )
        if file_path:
            self.key_file_path.set(file_path)

    # --- File Dialog Functions (UX Improvement: Auto-Detect) ---
    def select_input_file(self):
        """Opens the correct dialog and sets the input path, suggesting a related .wkey."""
        
        initial_dir = os.path.expanduser("~")
        file_path = ""
        
        if self.operation_mode.get() == "Decrypt" or self.input_type.get() == "File":
            file_path = filedialog.askopenfilename(initialdir=initial_dir)
        elif self.input_type.get() == "Folder":
            file_path = filedialog.askdirectory(initialdir=initial_dir)

        if file_path:
            
            # --- AUTO-DETECT AND SET INPUT TYPE ---
            if os.path.isdir(file_path):
                 self.input_type.set("Folder")
            elif os.path.isfile(file_path):
                 self.input_type.set("File")
            # ---------------------------------------------------------

            self.input_file_path.set(file_path)
            
            # Check for header after selecting file
            self._check_and_set_cipher_header(file_path)
            
            # --- START OUTPUT PATH & KEY SUGGESTION LOGIC ---
            input_name = os.path.basename(file_path)
            input_dir = os.path.dirname(file_path)
            base_name = os.path.splitext(input_name)[0]
            
            # Suggest a corresponding .wkey file in the same directory
            if not self.key_file_path.get():
                suggested_key_path = os.path.join(input_dir, base_name + ".wkey")
                if os.path.exists(suggested_key_path):
                    self.key_file_path.set(suggested_key_path)
            
            if self.operation_mode.get() == "Encrypt":
                if self.input_type.get() == "Folder":
                     output_path = os.path.join(input_dir, "ENCRYPTED_" + input_name + ".tar.enc")
                else:
                     output_path = file_path + ".enc"
                     
            else: # Decrypt Mode
                if input_name.endswith(".tar.enc"):
                    clean_name = input_name[:-8]
                    output_path = os.path.join(input_dir, "DECRYPTED_" + clean_name)
                else:
                    if input_name.endswith(".enc"):
                        original_name = input_name[:-4] 
                        output_path = os.path.join(input_dir, original_name)
                    else:
                        output_path = os.path.join(input_dir, input_name + "_decrypted")

            self.output_file_path.set(output_path)


    def select_output_file(self):
        """Opens a save dialog for selecting the output file path or a directory."""
        
        is_dir_output = self.operation_mode.get() == "Decrypt" and self.input_file_path.get().endswith(".tar.enc")
        
        if is_dir_output:
             # Folder Decryption output is always a directory
             file_path = filedialog.askdirectory(
                title="Select Output Folder",
                initialdir=os.path.dirname(self.output_file_path.get()) or os.path.expanduser("~")
             )
        else:
             # Single File or Folder Encrypt (single file output)
             if self.operation_mode.get() == "Encrypt":
                file_path = filedialog.asksaveasfilename(
                    initialfile=self.output_file_path.get(), 
                    defaultextension=".enc",
                    filetypes=[("Encrypted File (*.enc)", "*.enc"), ("All Files", "*.*")] 
                )
             else:
                # Single File Decrypt output is a file
                suggested_name = os.path.basename(self.output_file_path.get())
                
                if suggested_name.endswith(".enc"):
                    suggested_name = suggested_name[:-4]

                file_path = filedialog.asksaveasfilename(
                    initialfile=suggested_name, 
                    defaultextension="", 
                    initialdir=os.path.dirname(self.output_file_path.get()) or os.path.expanduser("~")
                )
            
        if file_path:
            self.output_file_path.set(file_path)

    # --- PROGRESS CALLBACK (Called by the worker thread) ---
    def _progress_callback_handler(self, bytes_read: int, total_size: int, status_message: str = None):
        """
        Updates the progress variables in a thread-safe manner. 
        Note: This is called directly by the worker thread.
        """
        self.progress_bytes_read = bytes_read
        self.progress_total_size = total_size
        if status_message:
            self.progress_status_text = status_message
        
    # --- Worker Thread Management ---

    def start_operation(self):
        """
        Validates input, handles synchronous key unwrapping (if necessary), 
        and starts the heavy _process_operation in a separate thread.
        """
        input_path = self.input_file_path.get()
        output_path = self.output_file_path.get()
        mode = self.operation_mode.get()
        key_mode = self.key_mode.get() 
        
        algorithm_name = self.cipher_algorithm.get()
        is_cbc_hmac_cipher = algorithm_name in ["AES-256-CBC + HMAC"]
        key_length_needed = KEY_SIZE * 2 if is_cbc_hmac_cipher else KEY_SIZE
        
        # 0. Reset temporary key material
        self.unwrapped_key_material = None 

        # 1. INPUT VALIDATION 
        if key_mode == "Password" and not self.password.get():
            messagebox.showwarning("Missing Input", "Please enter a password.")
            return
        elif key_mode == "Key File" and not self.key_file_path.get():
            messagebox.showwarning("Missing Input", "Please select a key file.")
            return
        if not all([input_path, output_path]):
            messagebox.showwarning("Missing Input", "Please select input/output paths.")
            return
        if not os.path.exists(input_path):
             messagebox.showerror("File Error", f"Input path not found: {input_path}")
             return
        
        is_folder_input = self.input_type.get() == "Folder"
        if mode == "Encrypt" and is_folder_input != os.path.isdir(input_path):
             expected = "Folder" if is_folder_input else "File"
             messagebox.showerror("Input Mismatch", f"The selected path is a {os.path.basename(input_path)} but you selected '{expected}' input type.")
             return
        
        if mode == "Decrypt" and not os.path.isfile(input_path):
             messagebox.showerror("Input Mismatch", "Decryption input must be a single encrypted file.")
             return
        
        # --- KEY UNWRAPPING/LOADING (synchronous, main thread) ---
        if key_mode == "Key File":
            key_path = self.key_file_path.get()
            raw_key = None 

            if key_path.endswith(".wkey"):
                
                try:
                    # 1. Prompt for passphrase 
                    passphrase = self._get_passphrase_dialog(
                        f"{mode} Key File Passphrase",
                        f"Enter the passphrase to UNLOCK key file: {os.path.basename(key_path)}"
                    )
                    
                    if not passphrase:
                        messagebox.showwarning("Security Check", "Key file passphrase is required to proceed.")
                        return

                    # 2. Read wrapped data and unwrap the key
                    with open(key_path, 'rb') as f:
                        key_data = f.read()
                        
                    raw_key = unwrap_key(key_data, passphrase)
                    
                except KeyPreparationError as e:
                    messagebox.showerror("Key Error", f"Failed to unwrap key file: {e}")
                    return
                except Exception as e:
                    messagebox.showerror("Key Error", f"An unexpected error occurred during key unwrapping: {e}")
                    return
            
            else: 
                # Load raw .key file directly (insecure fallback)
                 try:
                    with open(key_path, 'rb') as f:
                        raw_key = f.read()
                 except Exception as e:
                     messagebox.showerror("File Error", f"Failed to read raw key file: {e}")
                     return

            # --- FINAL VALIDATION AND STORAGE ---
            if raw_key is None or len(raw_key) != key_length_needed:
                messagebox.showerror("Key Error", f"Key file decryption/validation failed. Ensure the passphrase is correct and the key file is valid for the selected algorithm.")
                return
            
            self.unwrapped_key_material = raw_key

        # 2. Setup UI for Threading
        self.action_button.configure(state="disabled", text="Processing...")
        self.progress_bar.configure(mode="determinate") 
        self.progress_bar.set(0)
        self.status_label.configure(text=f"Starting {mode}...")
        self.update_idletasks()
        
        # Reset threading flags and progress tracking
        self.operation_success = False
        self.operation_error = None
        self.progress_bytes_read = 0
        self.progress_total_size = 0
        self.progress_status_text = ""
        self.last_progress_update = 0

        # 3. Start Worker Thread
        self.worker_thread = threading.Thread(
            target=self._run_process_in_thread,
            args=(input_path, output_path, mode)
        )
        self.worker_thread.start()
        
        # 4. Start monitoring the thread
        self.after(self.check_interval_ms, self._monitor_thread)


    def _run_process_in_thread(self, input_path, output_path, mode):
        """Function executed by the worker thread."""
        try:
            self._process_operation(input_path, output_path, mode)
            self.operation_success = True
        except Exception as e:
            self.operation_error = e

    # --- MONITOR THREAD ---
    def _monitor_thread(self):
        """Checks the status of the worker thread and updates the GUI progress bar."""
        
        # 1. Update Progress Bar and Status Label (using shared variables)
        current_time = time.time()
        
        if self.worker_thread.is_alive() or current_time - self.last_progress_update > self.min_update_delay:
            
            # Update Progress Bar
            if self.progress_total_size > 0 and self.progress_bytes_read <= self.progress_total_size:
                progress_value = self.progress_bytes_read / self.progress_total_size
                self.progress_bar.set(progress_value)
                
                # Format bytes for display
                def format_bytes(bytes_val):
                    if bytes_val >= 1024**3: return f"{bytes_val / 1024**3:.2f} GB"
                    if bytes_val >= 1024**2: return f"{bytes_val / 1024**2:.2f} MB"
                    if bytes_val >= 1024: return f"{bytes_val / 1024:.2f} KB"
                    return f"{bytes_val} Bytes"

                read_str = format_bytes(self.progress_bytes_read)
                total_str = format_bytes(self.progress_total_size)
                
                # Update Status Label
                if self.progress_status_text:
                    status_text = f"{self.progress_status_text} | {read_str} / {total_str}"
                else:
                    status_text = f"Processing... {read_str} / {total_str}"
                    
                self.status_label.configure(text=status_text)
                
                # Reset update timer
                self.last_progress_update = current_time
            
            # If still running, check again later
            if self.worker_thread.is_alive():
                 self.after(self.check_interval_ms, self._monitor_thread)
            
        
        # 2. Finalize UI after thread exit
        if not self.worker_thread.is_alive():
            self.progress_bar.stop()
            self.progress_bar.configure(mode="determinate")
            
            # --- CLEAR SENSITIVE FIELDS ---
            self.password.set("")
            self.key_file_path.set("")
            # --- END CLEAR ---

            if self.operation_success:
                mode = self.operation_mode.get()
                self.progress_bar.set(1)
                self.status_label.configure(text=f"{mode} complete!")
                messagebox.showinfo(f"{mode} Success", f"Operation completed successfully.")
            elif self.operation_error:
                error_msg = str(self.operation_error)
                
                self.progress_bar.set(0) 
                self.status_label.configure(text=f"Operation Failed.")
                
                # Display custom exception type for clearer errors
                if isinstance(self.operation_error, DeviceBindingError):
                     error_title = "Device Binding Failed"
                     error_msg = ("The decryption key derived from your password/keyfile did not match the file's bound device ID.\n\n"
                                  "This file can only be decrypted on the original machine.")
                elif isinstance(self.operation_error, KosiCryptoError):
                     error_title = f"{type(self.operation_error).__name__} Failed"
                else:
                     error_title = "Operation Failed"
                     
                messagebox.showerror(error_title, f"An error occurred: {error_msg}")
            else:
                 self.status_label.configure(text="")
                 self.progress_bar.set(0) 
                 
            self.action_button.configure(state="normal", text="START OPERATION")
        
    def _process_operation(self, input_path: str, output_path: str, mode: str):
        """A consolidated handler for encryption and decryption, supporting all ciphers."""
        key_mode = self.key_mode.get()
        key_material = None 
        salt = None 
        device_id = None 
        
        algorithm_name = self.cipher_algorithm.get() 
        
        # Get the function pointers for the selected algorithm
        try:
            encrypt_func, decrypt_func = ALGORITHM_MAP[algorithm_name]
        except KeyError:
             raise ValueError(f"Unknown algorithm selected: {algorithm_name}")

        # Check if the algorithm requires 64 bytes of key material
        is_cbc_hmac_cipher = algorithm_name in ["AES-256-CBC + HMAC"] 
        key_length_needed = KEY_SIZE * 2 if is_cbc_hmac_cipher else KEY_SIZE
        
        # Flags
        is_encrypted_archive = mode == 'Decrypt' and input_path.endswith(".tar.enc")
        is_folder_input = self.input_type.get() == "Folder" 

        # 1. DEVICE ID MANAGEMENT (Encryption)
        is_device_bound = self.device_binding_enabled.get() 
        
        if mode == 'Encrypt' and is_device_bound:
             device_id = _get_device_hash()
        
        # 2. KEY RETRIEVAL (Phase 1)
        if key_mode == "Password":
            
            needs_key_derivation = (mode == 'Encrypt' or mode == 'Decrypt') 
            iterations = KDF_ITERATIONS
            
            if needs_key_derivation:
                 if mode == 'Encrypt': 
                     # Encryption: Generate new salt
                     salt = generate_random_salt()
                     
                     # Derive key material using device ID if bound
                     derived_material = derive_key(self.password.get(), salt, iterations, device_id)
                     key_material = derived_material[:key_length_needed]
                 
                 elif mode == 'Decrypt':
                     # Decryption: READ METADATA FROM THE FILE HEADER
                     
                     # Check the file's bound status first
                     is_file_device_bound = self.is_file_device_bound.get()
                     
                     if is_file_device_bound:
                          # If bound, calculate the current device ID for key derivation
                          device_id = _get_device_hash()

                     # Read the full header (5b Header + 20b Metadata)
                     try:
                         with open(input_path, 'rb') as f:
                            header_data = f.read(CRYPTO_HEADER_SIZE)
                     except FileNotFoundError:
                          raise FileIntegrityError("Input file not found.")
                     except PermissionError:
                          raise FileIntegrityError("Permission denied to read input file.")
                     except Exception as e:
                          raise FileIntegrityError(f"Failed to read header due to an I/O error: {e}")
                          
                     if len(header_data) < CRYPTO_HEADER_SIZE:
                         raise FileIntegrityError("Encrypted file missing key derivation metadata (File too small).")
                         
                     # Parse the 20 bytes of metadata (from index 5 onwards)
                     metadata_bytes = header_data[HEADER_SIZE:CRYPTO_HEADER_SIZE]
                     
                     try:
                         salt, iterations = _parse_metadata_prefix(metadata_bytes)
                     except FileIntegrityError as e:
                         raise FileIntegrityError(f"Corrupted key derivation metadata in file header: {e}")
                         
                     # Use derived key and potentially customized iterations, including device_id
                     derived_material = derive_key(self.password.get(), salt, iterations, device_id)
                     key_material = derived_material[:key_length_needed]
                     
            
        elif key_mode == "Key File":
            # Retrieve the key material from the temporary instance variable 
            if self.unwrapped_key_material is None:
                 raise KeyPreparationError("Key material was not securely prepared before starting the worker thread.")

            key_material = self.unwrapped_key_material


        # 3. EXECUTION BRANCH
        # --- SALT GENERATION BLOCK (Key File ENCRYPT mode) ---
        if mode == 'Encrypt' and key_mode == 'Key File':
            salt = generate_random_salt()
            is_device_bound = False
        # --- END SALT GENERATION BLOCK ---


        if is_folder_input: # Only true during Encrypt
            if mode == 'Encrypt':
                output_enc_path = output_path + ".tar.enc"
                
                # Pass the encrypt_func, key_material, salt, and the binding status
                encrypt_folder_archival(
                    input_path, 
                    output_enc_path, 
                    key_material, 
                    salt, 
                    encrypt_func,
                    self._progress_callback_handler,
                    is_device_bound 
                )
            
        elif is_encrypted_archive: 
             # Folder Decrypt (uses key_material derived at the top)
             try:
                 decrypt_folder_archival(
                     input_path, 
                     output_path, 
                     key_material, 
                     decrypt_func,
                     self._progress_callback_handler 
                 )
             except FileIntegrityError as e:
                 # Check if the error is likely due to device binding failure
                 if self.is_file_device_bound.get():
                      # Re-raise as a DeviceBindingError to trigger the specialized GUI message
                      raise DeviceBindingError(str(e))
                 raise 
             
        else:
            # --- SINGLE FILE PROCESSING ---
            if mode == 'Encrypt':
                
                # Pass the progress callback, key, salt, and binding status
                encrypt_func(input_path, output_path, key_material, salt, self._progress_callback_handler, is_device_bound) 
                
            elif mode == 'Decrypt':
                try:
                    # Pass the progress callback
                    decrypt_func(input_path, output_path, key_material, self._progress_callback_handler)
                except FileIntegrityError as e:
                    # Check if the error is likely due to device binding failure
                    if self.is_file_device_bound.get():
                         # Re-raise as a DeviceBindingError to trigger the specialized GUI message
                         raise DeviceBindingError(str(e))
                    raise 
        
# --- Run the Application ---
if __name__ == "__main__":
    try:
        app = FileEncryptorApp()
        app.mainloop()
        
        sys.exit(0) 
        
    except Exception as e:
        print(f"FATAL STARTUP ERROR: {e}")
        messagebox.showerror("Fatal Startup Error", f"The application failed to launch: {e}")
        sys.exit(1)