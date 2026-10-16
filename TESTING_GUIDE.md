# SGitLine: Real-World Testing Guide

This guide provides detailed step-by-step instructions on how to test the SGitLine end-to-end encrypted Git service in the real world.

---

## Prerequisites Check

Before starting, activate the virtual environment and verify your GitHub SSH authentication:

```bash
cd /home/tkapa/E2EE-Git
source .venv/bin/activate

# Verify GitHub SSH connection (should greet you as tanaykapadia)
ssh -T git@github.com
```

---

## Method 1: The Automated Real-World GitHub Test (Fastest & Easiest)

This method runs an automated end-to-end test against a real GitHub repository.

### Step 1: Create an Empty Repository on GitHub
1. Go to [github.com/new](https://github.com/new).
2. Repository name: e.g., `sgit-test` (can be **Private** or **Public**).
3. **Important:** Leave "Add a README file", `.gitignore`, and license **UNCHECKED** (the repository must start completely empty).
4. Click **Create repository**.
5. Copy the SSH clone URL: `git@github.com:<your-username>/sgit-test.git`.

### Step 2: Run the Live Runner Script
Run the automated live test against your GitHub repository:

```bash
.venv/bin/python tests/test_live_github.py --remote git@github.com:<your-username>/sgit-test.git
```

### What You Will See in the Terminal:
1. **Key Generation:** Generates X25519 ephemeral keys, Ed25519 signing keys, and derives a 32-byte master key.
2. **Plaintext Encryption:** Encrypts `README.md` and `data.csv` line-by-line using AES-CTR and Base64.
3. **Signed Genesis Push:** Signs the initial Merkle DAG root and pushes commit to GitHub.
4. **Differential Update (ComDiff):** Modifies 1 line in `README.md` and pushes. You will see that **only ~134 bytes** are transferred across the network (only the edited line was re-encrypted!).
5. **Clone & Verification:** Clones the repository into a separate workspace, verifies the Merkle tree and Ed25519 signatures, and decrypts the exact files byte-for-byte.

### Step 3: Inspect GitHub on the Web
Open your repository on GitHub (`https://github.com/<your-username>/sgit-test`):
- Click on `README.md` or `data.csv`: You will see **only unreadable Base64 ciphertext strings**. GitHub cannot read any part of your files.
- Click on **Commits**: The commit messages contain cryptographic `sgit-v1` tags:
  ```
  sgit-v1
  uid: alice
  prev: 0000000000000000000000000000000000000000000000000000000000000000
  sig: <base64 Ed25519 signature>
  ```

---

## Method 2: Hands-On Interactive CLI Walkthrough

If you want to use the `sgit` CLI manually like everyday `git`:

### Step 1: Register a User & Keystore
Create your cryptographic identity and local passphrase-protected keystore:

```bash
python -m sgit.cli register --uid tanay --passphrase "mysecretpassphrase"
```
*Output: Saves your keystore to `~/.sgit/keystore.dat` and prints your secret token.*

### Step 2: Initialize an Encrypted Repository
Create a directory for your secure project and link it to your GitHub repository:

```bash
mkdir ~/my-encrypted-repo
cd ~/my-encrypted-repo

python -m sgit.cli init . --remote git@github.com:<your-username>/sgit-test.git --passphrase "mysecretpassphrase"
```

Inside `~/my-encrypted-repo`, you will see two folders:
- `plain/`: Your local working folder containing normal, decrypted files. **This is where you edit your code.**
- `ct/`: The encrypted Git repository that syncs with GitHub.

### Step 3: Add Files and Commit
Add confidential files into the `plain/` directory:

```bash
echo "# My Secret Project" > plain/project.txt
echo "Budget: $1,000,000" >> plain/project.txt
echo "Launch date: Q4 2026" >> plain/project.txt

# Encrypt and push to GitHub
python -m sgit.cli commit . -m "Initial confidential project plans" --passphrase "mysecretpassphrase"
```

### Step 4: Check Status
Inspect the verified state of your workspace:

```bash
python -m sgit.cli status .
```
You will see the repository ID, last ciphertext commit hash, and verified Merkle root digest.

### Step 5: Make a Line-Wise Edit (Testing ComDiff Efficiency)
Modify only the budget line in `plain/project.txt`:

```bash
sed -i 's/$1,000,000/$1,500,000/' plain/project.txt

# Commit and push the update
python -m sgit.cli commit . -m "Increase budget" --passphrase "mysecretpassphrase"
```
*Notice: Only line 2 is re-encrypted. Lines 1 and 3 retain their exact original ciphertext bytes!*

### Step 6: Clone and Decrypt on Another "Device"
Simulate cloning your repository on another machine or location:

```bash
mkdir ~/device-2
cd ~/device-2

# Look up your repository ID from 'sgit status' (e.g., tanay.xxxxxxxx)
python -m sgit.cli clone . --rid <your-repo-id> --remote git@github.com:<your-username>/sgit-test.git --passphrase "mysecretpassphrase"
```

Inspect `~/device-2/plain/project.txt`:
```bash
cat ~/device-2/plain/project.txt
```
Your plaintext files are restored and verified!

---

## Method 3: Testing Tamper Detection (Adversarial Protection)

To verify that GitHub or a malicious network attacker cannot tamper with your data:

1. Go to your GitHub repository web page.
2. Click on one of the encrypted files (e.g. `data.csv`), click the **Edit pencil icon**, alter **just one character** in the Base64 text, and click **Commit changes**.
3. Now attempt to pull the changes on your client:
   ```bash
   cd ~/my-encrypted-repo
   python -m sgit.cli pull . --passphrase "mysecretpassphrase"
   ```
4. **Result:** The client will abort with an error (e.g., `bad version signature` or `prev digest mismatch`).
5. Check your `plain/` directory: **Your local files remain completely untouched and uncorrupted.** SGitLine strictly refuses to decrypt tampered data.

---

## Method 4: Running the Full Automated Test Suite

You can run the full automated test suite anytime to verify all components (crypto, line codec, ComDiff, Merkle trees, multi-user sharing, and tamper rejection):

```bash
cd /home/tkapa/E2EE-Git
.venv/bin/python -m pytest -v
```
