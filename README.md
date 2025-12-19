# Final Project Report: Secure Vault & Encryption Tool
Course: BİL 420 - Introduction to Cybersecurity 

 
## Abstract
The Secure Vault & Encryption Tool is a robust desktop application designed to address the increasing need for local data confidentiality and integrity. In an environment where personal data is frequently targeted by unauthorized access, this project provides a professional-grade solution by implementing the Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM).
The application serves a dual purpose: it acts as a secure database for sensitive text-based notes and as a standalone utility for file-system-level encryption. This report provides an in-depth analysis of the project's objectives, the three-tier architectural design (comprising the GUI, Cryptographic Core, and Database), the implementation of context-aware security features such as dynamic clipboard management, and an evaluation of the lessons learned during the development of secure software.
 
## 1. Objectives
The primary mission of this project was to create a "Zero-Knowledge" local environment where the user maintains absolute control over their encryption keys and data. The specific objectives included:
•	Data Confidentiality through High Entropy: Implementing key derivation functions that transform simple user passwords into cryptographically strong 256-bit keys, ensuring that stored information remains unreadable to any party without the Master Password.
•	Cryptographic Integrity and Authenticity: Moving beyond simple encryption to "Authenticated Encryption" by utilizing GCM tags. This ensures that any unauthorized modification of the ciphertext (bit-flipping attacks) is immediately detected and rejected by the system.
•	User-Centric Security Accessibility: Bridging the gap between complex cryptographic operations and user experience. The goal was to provide an intuitive GUI that allows students or professionals to manage encrypted files and databases without requiring deep expertise in command-line tools.
•	Comprehensive Audit Traceability: Establishing a rigorous logging system to record every security-sensitive operation. This objective focused on creating a transparent history of encryption, decryption, and data destruction (deletion) to support forensic auditing and debugging.
 
## 2. Technical Approach and Methodology
2.1 Cryptographic Core
The security of the application is built upon industry-standard primitives to ensure the highest level of protection:
•	Key Derivation (PBKDF2): To defend against brute-force and dictionary attacks, we utilized the Password-Based Key Derivation Function 2 (PBKDF2).
o	By using a unique 16-byte salt for every session, the system ensures that identical passwords do not result in the same encryption key.
o	The implementation uses 1,000,000 iterations, a high threshold that significantly increases the computational cost for attackers attempting to guess the Master Password using GPUs or specialized hardware.
•	Advanced Encryption Standard (AES-256-GCM): The project avoids outdated modes like ECB or CBC. Instead, it uses AES-GCM, which provides "Authenticated Encryption with Associated Data" (AEAD).
o	Every encryption produces a unique Nonce (Number used once) and an Authentication Tag.
o	This combination ensures that the ciphertext is unique every time and that its integrity is mathematically verified during decryption.
2.2 System Architecture
The project follows a modular, three-tier architecture to ensure maintainability and security:
•	Presentation Layer (app.py): Developed using Tkinter, this layer handles user interaction and event loops. It manages the visual state of the application, such as switching between "Text Mode" and "File Mode" and providing real-time feedback through message boxes.
•	Logic Layer (crypto_core.py): This is the engine of the application. It remains completely decoupled from the UI, handling only raw data processing, cryptographic transformations, and file-system I/O for binary data.
•	Data Layer (db_manager.py): Utilizing SQLite, this layer manages the persistence of encrypted metadata. It ensures that encrypted strings are stored efficiently and provides a structured way to retrieve or delete secrets without exposing the underlying cryptographic keys.
 


## 3. Implementation Details
3.1 Context-Aware Clipboard Integration
A standout feature of this tool is its dynamic clipboard logic, designed to prevent human error and data leakage:
•	State Tracking: The application utilizes a self.last_action variable within the SecureApp class to monitor the user's most recent successful operation.
•	Dynamic Source Selection: * If the user performs Encryption, the "Copy Clipboard" button automatically targets the Original  field. This allows users to quickly secure their input text after it has been safely saved.
o	If the user performs Decryption, the button targets the Encrypted field. This ensures the user can immediately use their recovered plaintext in other applications without manually selecting text.
•	Security Benefit: This automation minimizes the time sensitive data spends in the system's memory and reduces the risk of accidentally copying the wrong data type (e.g., copying ciphertext instead of plaintext).
3.2 Enhanced Logging Mechanism
To achieve a professional cybersecurity standard, the application implements an advanced audit trail in secure_app.log:
•	Structured Audit Logs: Every action is timestamped and categorized by severity (INFO, WARNING, ERROR).
•	Pre-deletion Verification: A critical security feature was implemented for the data destruction process. When a user deletes a note:
o	The system first queries the database to retrieve the Note Title using the record's ID.
o	It then logs the specific title of the deleted note alongside its ID.
o	Finally, it executes the SQL deletion command.
•	Incident Detection: Failed decryption attempts (due to incorrect passwords) are logged as WARNINGS, providing a clear record of potential unauthorized access attempts or password forgetfulness.
 

## 4. Outcomes and Results
4.1 Performance Analysis
During the final testing phase, the application was evaluated for both speed and resource consumption:
•	Computational Efficiency: The use of the pycryptodome library allowed for near-instant encryption of text data. For files, the stream-based processing ensured that large files could be encrypted without exceeding the system's RAM limits.
•	Key Derivation Latency: The 1,000,000 PBKDF2 iterations introduced a slight, acceptable delay (approx. 0.5–1 second), which serves as a psychological and technical deterrent against rapid-fire brute-force attacks.
4.2 Security Validation
The tool underwent rigorous "Penetration Testing" style checks:
•	Integrity Testing: We manually altered bits in the .enc files and the database strings. In every instance, the AES-GCM tag verification failed, and the system correctly refused to decrypt the corrupted data.
•	Storage Security: Examination of the secure_vault.db showed that no sensitive information (plaintext or master passwords) is stored in the clear. All stored data is Base64 encoded ciphertext packages.
 
## 5. Lessons Learned
5.1 Complexity of State Management
One of the most significant engineering challenges for me was managing the UI state for the clipboard feature. Ensuring that the application "remembered" the correct field to copy required a strict state machine approach. This highlighted the importance of synchronization between the GUI and the underlying logic in secure software.
5.2 The Importance of Audit Trails
The transition from simple error logging to a full audit trail taught the team that "successful" logs are just as important as "error" logs. Knowing exactly when a file was encrypted or which note was deleted is essential for building user trust and providing a professional security product.


5.3 User Experience vs. Security
Striking the balance between high-security parameters (like high iteration counts) and a responsive UI was a key takeaway. We learned that security tools must be usable; otherwise, users will revert to insecure methods (like plain text files) to save time.
 

## 6. Conclusion
The Secure Vault & Encryption Tool successfully demonstrates the practical application of advanced cryptographic concepts in a real-world software environment. By combining the mathematical strength of AES-256-GCM with a modular architecture and user-friendly features like context-aware clipboard management, the project meets all the rigorous requirements of a modern cybersecurity tool.The implementation of detailed logging and authenticated encryption sets this project apart from basic encryption scripts, providing a foundation for a professional-grade secure personal data manager. 

