# ==========================================================================================
import os,sys

# ==========================================================================================
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import List, Union, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
from dataclasses import dataclass
import threading
from queue import Queue
import logging
from datetime import datetime
import hashlib
import tkinterdnd2
from tkinterdnd2 import DND_FILES, TkinterDnD
from tkinterdnd2 import *
import re
from tkinter import scrolledtext
# ===========================================================================================
# for exe
os.environ['TKDND_LIBRARY'] = os.path.join(os.path.dirname(tkinterdnd2.__file__), 'tkdnd')

def suppress_errors(exception_type, exception_value, traceback):
    pass

sys.excepthook = suppress_errors

# ===========================================================================================
class GuideWindow:
    """Creates a new window with comprehensive guide information"""
    
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Application Guide")
        self.window.geometry("600x400")
        self.window.resizable(False, False)
        
        self._create_guide()
        
    def _create_guide(self):
        """Create the guide content"""
        guide_text = scrolledtext.ScrolledText(
            self.window, 
            wrap=tk.WORD, 
            width=70, 
            height=22,
            font=('Helvetica', 10)
        )
        guide_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Comprehensive guide content
        guide_content = """
SECURE CODE PROCESSOR - COMPREHENSIVE GUIDE

1. ENCRYPTION TECHNOLOGY
------------------------
- Algorithm: AES-256 (Advanced Encryption Standard)
- Mode: GCM (Galois/Counter Mode)
- Features: Provides both confidentiality and authenticity
- Key Size: 256 bits

2. KEY GENERATION METHOD
------------------------
- Primary Algorithm: SHA-256 (Secure Hash Algorithm)
- Enhancement: Random salt addition (16 bytes)
- Strengthening: PBKDF2 (Password-Based Key Derivation Function 2)
- Iterations: 500,000 for key derivation
- Salt Size: 16 bytes for key derivation
- Nonce Size: 12 bytes for encryption

3. FILE PROCESSING
------------------------
- Chunk Processing: Files processed in 1MB chunks
- Threading: Background processing for UI responsiveness
- Progress Tracking: Real-time progress updates
- Error Handling: Comprehensive error capture and reporting

4. SECURITY FEATURES
------------------------
- Unique salt and nonce for each file
- Authenticated encryption
- Secure error handling and logging
- Metadata storage for each encrypted file
- Full authentication of encrypted data

5. HOW TO USE
------------------------
a) File Selection:
   - Use Browse buttons or drag-and-drop
   - Supports multiple files and folders
   - Handles common code file types

b) Key File:
   - Select existing .key or .txt file
   - Generate new key from text file
   - Drag-and-drop supported

c) Output Location:
   - Select destination folder for processed files
   - Creates organized output structure

d) Processing:
   - Green button for encryption
   - Red button for decryption
   - Progress bar shows completion status

6. TECHNICAL DETAILS
------------------------
The encryption process follows these steps:
1. Key derivation from key file
2. Salt and nonce generation
3. AES-GCM encryption
4. Metadata storage
5. Encrypted file writing

The decryption process follows these steps:
1. Metadata reading
2. Key derivation
3. Authentication verification
4. AES-GCM decryption
5. Original file restoration

7. FILE EXTENSIONS
------------------------
Supported code file types:
- Python (.py)
- Java (.java)
- C++ (.cpp)
- C (.c)
- JavaScript (.js)
- HTML (.html)
- CSS (.css)
- SQL (.sql)
- Microsoft word (.docx)
- Microsoft excel (.xlsx)
- Encrypted Files (.encrypted)
- pdf (.pdf)

Key file types:
- Key files (.key)
- Text files (.txt)
"""
        
        guide_text.insert(tk.END, guide_content)
        guide_text.configure(state='disabled')

@dataclass
class CryptoMetadata:
    """Stores metadata for encryption/decryption operations"""
    salt: bytes
    nonce: bytes
    timestamp: str
    original_name: str

class KeyGenerator:
    """Handles key file generation from text files"""
    
    @staticmethod
    def generate_key_file(input_path: Path, output_path: Path) -> Tuple[bool, str]:
        """Generate a key file from a text file using SHA-256"""
        try:
            with open(input_path, 'rb') as f:
                content = f.read()
            
            # Create a strong key using SHA-256
            key = hashlib.sha256(content).digest()
            
            # Add some randomness
            salt = os.urandom(16)
            key += salt
            
            with open(output_path, 'wb') as f:
                f.write(key)
            
            return True, f"Key file created successfully at {output_path}"
        except Exception as e:
            return False, f"Error generating key file: {str(e)}"

class AdvancedFileProcessor:
    """Handles all file processing and cryptographic operations"""
    
    CHUNK_SIZE = 1024 * 1024  # 1MB chunks for large file handling
    
    def __init__(self):
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        """Configure logging system"""
        logger = logging.getLogger('SecureCodeProcessor')
        logger.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Create a NullHandler instead of a FileHandler
        null_handler = logging.NullHandler()
        logger.addHandler(null_handler)
        
        return logger
    
    def _derive_key(self, key_file_content: bytes, salt: bytes) -> bytes:
        """Derive an encryption key using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000,
        )
        return kdf.derive(key_file_content)
    
    def process_file(self, 
                file_path: Path, 
                key_file_path: Path,
                output_path: Path,
                encrypt: bool = True) -> Tuple[bool, str]:
        """Process a single file for encryption/decryption"""
        try:
            with open(key_file_path, 'rb') as key_file:
                key_content = key_file.read()
            
            if encrypt:
                return self._encrypt_file(file_path, key_content, output_path)
            else:
                return self._decrypt_file(file_path, key_content, output_path)
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {str(e)}")
            return False, str(e)

    def _encrypt_file(self, file_path: Path, key_content: bytes, output_path: Path) -> Tuple[bool, str]:
        """Encrypt a single file using AES-GCM"""
        try:
            # Generate salt and nonce
            salt = os.urandom(16)
            nonce = os.urandom(12)
            
            # Derive the key
            key = self._derive_key(key_content, salt)
            aesgcm = AESGCM(key)
            
            # Prepare metadata
            metadata = CryptoMetadata(
                salt=salt,
                nonce=nonce,
                timestamp=datetime.now().isoformat(),
                original_name=file_path.name
            )
            
            with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                # Write metadata
                metadata_dict = {
                    'salt': base64.b64encode(metadata.salt).decode('utf-8'),
                    'nonce': base64.b64encode(metadata.nonce).decode('utf-8'),
                    'timestamp': metadata.timestamp,
                    'original_name': metadata.original_name
                }
                metadata_bytes = json.dumps(metadata_dict).encode('utf-8')
                metadata_length = len(metadata_bytes).to_bytes(8, byteorder='big')
                f_out.write(metadata_length)
                f_out.write(metadata_bytes)
                
                # Process file in chunks
                while chunk := f_in.read(self.CHUNK_SIZE):
                    encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                    f_out.write(encrypted_chunk)
            
            return True, f"Encrypted: {output_path}"
        except Exception as e:
            self.logger.error(f"Encryption error: {str(e)}")
            return False, f"Encryption failed: {str(e)}"

    def _decrypt_file(self, file_path: Path, key_content: bytes, output_path: Path) -> Tuple[bool, str]:
        """Decrypt a single file using AES-GCM"""
        try:
            with open(file_path, 'rb') as f_in:
                # Read metadata
                metadata_length = int.from_bytes(f_in.read(8), byteorder='big')
                metadata_bytes = f_in.read(metadata_length)
                metadata_dict = json.loads(metadata_bytes.decode('utf-8'))
                
                metadata = CryptoMetadata(
                    salt=base64.b64decode(metadata_dict['salt']),
                    nonce=base64.b64decode(metadata_dict['nonce']),
                    timestamp=metadata_dict['timestamp'],
                    original_name=metadata_dict['original_name']
                )
                
                # Derive the key
                key = self._derive_key(key_content, metadata.salt)
                aesgcm = AESGCM(key)
                
                # Create output file path
                output_path = output_path.parent / f"decrypted_{metadata.original_name}"

                with open(output_path, 'wb') as f_out:
                    while chunk := f_in.read(self.CHUNK_SIZE):
                        decrypted_chunk = aesgcm.decrypt(metadata.nonce, chunk, None)
                        f_out.write(decrypted_chunk)
                
            return True, f"Decrypted: {output_path}"
        except Exception as e:
            self.logger.error(f"Decryption error: {str(e)}")
            return False, f"Decryption failed: {str(e)}"
            
class SecureCodeProcessorGUI:
    """Advanced GUI for the Secure Code Processor application"""
    
    def __init__(self):
        self.root = TkinterDnD.Tk()
        self.root.title("Secure Code Processor")
        self.root.geometry("555x740+600+100")
        self.root.resizable(False, False)
        
        self.processor = AdvancedFileProcessor()
        self.key_generator = KeyGenerator()
        self.selected_files: List[Path] = []
        self.key_file: Union[Path, None] = None
        self.processing_queue = Queue()
        
        self._setup_styles()
        self._create_gui()
        
        self.output_path: Union[Path, None] = None

    def _setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
        style.configure('Status.TLabel', font=('Helvetica', 9))
        style.configure('Green.TButton', background='green')
        style.configure('Red.TButton', background='red')
        
    def _create_gui(self):
        """Create the main GUI elements"""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="5")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Guide Button (top-right corner)
        guide_btn = ttk.Button(
            main_frame, 
            text="?", 
            width=3,
            command=self._show_guide
        )
        guide_btn.grid(row=5, column=0, sticky=tk.E, padx=5, pady=5)
        

        # File Selection Section
        self._create_file_section(main_frame)
        
        # Key File Section
        self._create_key_section(main_frame)
        
        # Key Generator Section
        self._create_key_generator_section(main_frame)
        
        # Operation Buttons
        self._create_operation_buttons(main_frame)
        
        # Progress and Status
        self._create_progress_section(main_frame)
        
    def _show_guide(self):
        """Show the guide window"""
        GuideWindow(self.root)
            
    def _create_file_section(self, parent):
        """Create the file selection section"""
        file_frame = ttk.LabelFrame(parent, text="Code Files", padding="5")
        file_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Buttons frame
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=0, column=0, pady=5)
        
        ttk.Button(btn_frame, text="Browse Files", command=self._browse_files).grid(row=0, column=0, padx=2)
        ttk.Button(btn_frame, text="Browse Folder", command=self._browse_folder).grid(row=0, column=1, padx=2)
        ttk.Button(btn_frame, text="Clear", command=self._clear_files).grid(row=0, column=2, padx=2)
        
        # Drag and drop area
        self.files_text = tk.Text(file_frame, height=8, width=65)
        self.files_text.grid(row=1, column=0, pady=5)
        self.files_text.insert('1.0', "Drag and drop files or folders here...")
        self.files_text.configure(state='disabled')
        
        # Configure drag and drop
        self.files_text.drop_target_register(DND_FILES)
        self.files_text.dnd_bind('<<Drop>>', self._drop_files)
        
        # Output path frame
        output_frame = ttk.Frame(file_frame)
        output_frame.grid(row=2, column=0, pady=5)
        
        ttk.Label(output_frame, text="Output Path:").grid(row=0, column=0, padx=2)
        self.process_output_path_var = tk.StringVar()  # Changed variable name here
        ttk.Entry(output_frame, textvariable=self.process_output_path_var, width=50).grid(row=0, column=1, padx=2)
        ttk.Button(output_frame, text="Browse", command=self._browse_output_path).grid(row=0, column=2, padx=2)


    def _get_code_files_from_folder(self, folder_path: Path) -> List[Path]:
        """Recursively get all code files from a folder"""
        code_extensions = {'.py', '.java', '.cpp', '.js', '.html', '.css','.c','.encrypted','.sql','.docx','.xlsx','.pdf'}
        files = []
        
        for item in folder_path.rglob('*'):
            if item.is_file() and item.suffix.lower() in code_extensions:
                files.append(item)
        
        return files    
    
    def _create_key_section(self, parent):
        """Create the key file section"""
        key_frame = ttk.LabelFrame(parent, text="Key File", padding="5")
        key_frame.grid(row=1, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Key selection
        key_select_frame = ttk.Frame(key_frame)
        key_select_frame.grid(row=0, column=0, pady=5)
        
        ttk.Button(key_select_frame, text="Select Key", command=self._browse_key).grid(row=0, column=0, padx=2)
        ttk.Button(key_select_frame, text="Clear", command=self._clear_key).grid(row=0, column=1, padx=2)
        
        # Key drag and drop area
        self.key_text = tk.Text(key_frame, height=3, width=65)
        self.key_text.grid(row=1, column=0, pady=5)
        self.key_text.insert('1.0', "Drag and drop key file here...")
        self.key_text.configure(state='disabled')
        
        # Configure drag and drop
        self.key_text.drop_target_register(DND_FILES)
        self.key_text.dnd_bind('<<Drop>>', self._drop_key)
        
    def _create_key_generator_section(self, parent):
        """Create the key generator section"""
        gen_frame = ttk.LabelFrame(parent, text="Key Generator", padding="5")
        gen_frame.grid(row=2, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        # Input file selection
        input_frame = ttk.Frame(gen_frame)
        input_frame.grid(row=0, column=0, pady=5)
        
        ttk.Label(input_frame, text="Input Text File:  ").grid(row=0, column=0, padx=2)
        self.input_path_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.input_path_var, width=50).grid(row=0, column=1, padx=2)
        ttk.Button(input_frame, text="Browse", command=self._browse_input_text).grid(row=0, column=2, padx=2)
        
        # Output key file
        output_frame = ttk.Frame(gen_frame)
        output_frame.grid(row=1, column=0, pady=5)
        
        ttk.Label(output_frame, text="Output Key File:").grid(row=0, column=0, padx=2)
        self.key_output_path_var = tk.StringVar()  # Changed variable name here
        ttk.Entry(output_frame, textvariable=self.key_output_path_var, width=50).grid(row=0, column=1, padx=2)
        ttk.Button(output_frame, text="Browse", command=self._browse_output_key).grid(row=0, column=2, padx=2)
        
        # Generate button
        ttk.Button(gen_frame, text="Generate Key", command=self._generate_key).grid(row=2, column=0, pady=5)

        
    def _create_operation_buttons(self, parent):
        """Create the encryption/decryption buttons"""
        ops_frame = ttk.Frame(parent)
        ops_frame.grid(row=3, column=0, pady=10)
        
        # Custom styled buttons
        encrypt_btn = tk.Button(ops_frame, text="Encrypt Files", 
                              command=lambda: self._process_files(True),
                              bg='green', fg='white', width=15, height=2)
        encrypt_btn.grid(row=0, column=0, padx=10)
        
        decrypt_btn = tk.Button(ops_frame, text="Decrypt Files",
                              command=lambda: self._process_files(False),
                              bg='red', fg='white', width=15, height=2)
        decrypt_btn.grid(row=0, column=1, padx=10)
        
    def _create_progress_section(self, parent):
        """Create the progress and status section"""
        progress_frame = ttk.LabelFrame(parent, text="Progress", padding="5")
        progress_frame.grid(row=4, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        self.progress = ttk.Progressbar(progress_frame, length=520, mode='determinate')
        self.progress.grid(row=0, column=0, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready", style='Status.TLabel')
        self.status_label.grid(row=1, column=0, pady=5)
        
    def _drop_files(self, event):
        """Handle file drop events"""
        files = self._parse_drop_data(event.data)
        all_files = []
        
        for file_path in files:
            path = Path(file_path)
            if path.is_dir():
                folder_files = self._get_code_files_from_folder(path)
                all_files.extend(folder_files)
            else:
                all_files.append(path)
        
        self._update_selected_files(all_files)
    
    def _browse_output_path(self):
        """Browse for output directory"""
        folder = filedialog.askdirectory(title="Select Output Folder")
        if folder:
            self.process_output_path_var.set(folder)  # Updated variable name


    def _drop_key(self, event):
        """Handle key file drop events"""
        files = self._parse_drop_data(event.data)
        if files:
            file_path = Path(files[0])
            if file_path.suffix.lower() in ['.key', '.txt']:
                self.key_file = file_path
                self.key_text.configure(state='normal')
                self.key_text.delete('1.0', tk.END)
                self.key_text.insert('1.0', str(file_path))
                self.key_text.configure(state='disabled')
            else:
                messagebox.showerror("Error", "Please drop a .key or .txt file")
                
    def _parse_drop_data(self, data: str) -> List[str]:
        """Parse dropped file data"""
        # Handle different formats of dropped file data
        if '{' in data:  # Windows format
            files = re.findall(r'{(.*?)}', data)
        else:  # Unix format
            files = data.split()
        return [f.strip() for f in files]
        
    def _browse_input_text(self):
        """Browse for input text file"""
        file = filedialog.askopenfilename(
            title="Select Input Text File",
            filetypes=[("Text files", "*.txt")]
        )
        if file:
            self.input_path_var.set(file)
            
    def _browse_output_key(self):
        """Browse for output key file location"""
        file = filedialog.asksaveasfilename(
            title="Save Key File",
            defaultextension=".key",
            filetypes=[("Key files", "*.key")]
        )
        if file:
            self.key_output_path_var.set(file)  # Updated variable name

            
    def _generate_key(self):
        """Generate a key file from text input"""
        input_path = self.input_path_var.get()
        output_path = self.key_output_path_var.get()  # Updated variable name
        
        if not input_path or not output_path:
            messagebox.showerror("Error", "Please specify both input and output files")
            return
            
        success, message = self.key_generator.generate_key_file(Path(input_path), Path(output_path))
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)
            
    def _clear_files(self):
        """Clear selected files"""
        self.selected_files.clear()
        self.files_text.configure(state='normal')
        self.files_text.delete('1.0', tk.END)
        self.files_text.insert('1.0', "Drag and drop files or folders here...")
        self.files_text.configure(state='disabled')
        
    def _clear_key(self):
        """Clear selected key file"""
        self.key_file = None
        self.key_text.configure(state='normal')
        self.key_text.delete('1.0', tk.END)
        self.key_text.insert('1.0', "Drag and drop key file here...")
        self.key_text.configure(state='disabled')
    
    def _browse_files(self):
        """Handle file browsing"""
        files = filedialog.askopenfilenames(
            title="Select Code Files",
            filetypes=[("Code files", "*.py;*.java;*.cpp;*.js;*.html;*.css;*.c;*.encrypted;*.sql;*.docx;*.xlsx;*.pdf"),
                      ("All files", "*.*")]
        )
        self._update_selected_files([Path(f) for f in files])
        
    def _browse_folder(self):
        """Handle folder browsing"""
        folder = filedialog.askdirectory(title="Select Folder")
        if folder:
            folder_path = Path(folder)
            files = self._get_code_files_from_folder(folder_path)
            if files:
                self._update_selected_files(files)
            else:
                messagebox.showwarning("Warning", "No supported code files found in the selected folder")

            
    def _browse_key(self):
        """Handle key file selection"""
        key_file = filedialog.askopenfilename(
            title="Select Key File",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if key_file:
            self.key_file = Path(key_file)
            self.key_text.configure(state='normal')
            self.key_text.delete('1.0', tk.END)
            self.key_text.insert('1.0', str(self.key_file))
            self.key_text.configure(state='disabled')
            
    def _update_selected_files(self, files: List[Path]):
        """Update the display of selected files"""
        self.selected_files.extend(files)
        self.files_text.configure(state='normal')
        self.files_text.delete('1.0', tk.END)
        for file in self.selected_files:
            self.files_text.insert(tk.END, f"{file}\n")
        self.files_text.configure(state='disabled')
            
    def _process_files(self, encrypt: bool):
        """Handle file processing"""
        if not self.selected_files:
            messagebox.showerror("Error", "No files selected")
            return
            
        if not self.key_file:
            messagebox.showerror("Error", "No key file selected")
            return
        
        output_path = self.process_output_path_var.get()  # Updated variable name
        if not output_path:
            messagebox.showerror("Error", "No output path selected")
            return
        
        output_dir = Path(output_path)
        if not output_dir.exists():
            try:
                output_dir.mkdir(parents=True)
            except Exception as e:
                messagebox.showerror("Error", f"Could not create output directory: {str(e)}")
                return
                
        # Start processing thread
        self.progress['value'] = 0
        self.progress['maximum'] = len(self.selected_files)
        
        threading.Thread(target=self._process_files_thread, args=(encrypt, output_dir), daemon=True).start()
        
    def _process_files_thread(self, encrypt: bool, output_dir: Path):
        """Process files in a separate thread"""
        operation = "Encryption" if encrypt else "Decryption"
        failed_files = []

        for file in self.selected_files:
            self.root.after(0, lambda: self.status_label.config(
                text=f"Processing: {file.name}"
            ))

            # Create relative output path
            try:
                # Determine output file path
                relative_path = file.relative_to(file.parent)
                output_file = output_dir / relative_path
                output_file.parent.mkdir(parents=True, exist_ok=True)

                if encrypt:
                    output_file = output_file.with_suffix(output_file.suffix + '.encrypted')
                else:
                    output_file = output_dir / f"decrypted_{file.name}"

                success, message = self.processor.process_file(file, self.key_file, output_file, encrypt)

                if success:
                    self.root.after(0, lambda m=message: self.status_label.config(text=m))
                else:
                    failed_files.append((file, message))

            except Exception as e:
                failed_files.append((file, str(e)))

            self.root.after(0, self._increment_progress)

        self.root.after(0, lambda: self.status_label.config(text=f"{operation} complete"))

        if failed_files:
            self._display_failed_files(failed_files, operation)
        
    def _display_failed_files(self, failed_files: List[Tuple[Path, str]], operation: str):
        """Display a message box with the list of failed files and error messages"""
        message = f"{operation} failed for the following files:\n\n"
        for file, error in failed_files:
            message += f"- {file.name}: {error}\n"

        messagebox.showerror(f"{operation} Errors", message)

    def _increment_progress(self):
        """Update progress bar"""
        self.progress['value'] += 1
        
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = SecureCodeProcessorGUI()
    app.run()
