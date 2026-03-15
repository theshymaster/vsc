import hashlib
import getpass
import time
import re
 
# ── In-memory "database" ──────────────────────────────────────────────────────
users_db: dict[str, dict] = {}          # {username: {password_hash, email, failed_attempts, locked}}
active_sessions: dict[str, str] = {}    # {session_token: username}
 
MAX_LOGIN_ATTEMPTS = 3
MIN_PASSWORD_LENGTH = 8
 
 
# ── Helpers ───────────────────────────────────────────────────────────────────
 
def hash_password(password: str) -> str:
    """Return a SHA-256 hex digest of the password."""
    return hashlib.sha256(password.encode()).hexdigest()
 
 
def generate_session_token(username: str) -> str:
    """Create a simple (non-cryptographic) session token."""
    raw = f"{username}{time.time()}"
    return hashlib.md5(raw.encode()).hexdigest()
 
 
# ── Password validation (loop-based) ─────────────────────────────────────────
 
def validate_password(password: str) -> list[str]:
    """
    Return a list of unmet requirements.
    Uses a loop over a list of (check_function, error_message) pairs.
    """
    rules = [
        (lambda p: len(p) >= MIN_PASSWORD_LENGTH,
         f"At least {MIN_PASSWORD_LENGTH} characters"),
        (lambda p: any(c.isupper() for c in p),
         "At least one uppercase letter"),
        (lambda p: any(c.islower() for c in p),
         "At least one lowercase letter"),
        (lambda p: any(c.isdigit() for c in p),
         "At least one digit"),
        (lambda p: any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in p),
         "At least one special character (!@#$%^&*…)"),
    ]
 
    failures = []
    for check, message in rules:          # <-- loop over validation rules
        if not check(password):
            failures.append(message)
    return failures
 
 
# ── Registration ──────────────────────────────────────────────────────────────
 
def register_user() -> None:
    """
    Register a new user.
    Loops until a valid, unique username and a strong password are provided.
    """
    print("\n── Register ─────────────────────────────")
 
    # Loop until a valid username is chosen
    while True:
        username = input("Choose a username: ").strip()
        if not username:
            print("  ✗ Username cannot be empty.")
            continue
        if username in users_db:
            print(f"  ✗ '{username}' is already taken.")
            continue
        if not re.match(r"^[A-Za-z0-9_]{3,20}$", username):
            print("  ✗ Username must be 3-20 characters (letters, digits, underscores).")
            continue
        break                             # valid username found
 
    # Loop until a strong password is entered and confirmed
    while True:
        password = getpass.getpass("Choose a password: ")
        errors = validate_password(password)
        if errors:
            print("  ✗ Password must meet ALL requirements:")
            for err in errors:            # <-- loop over error messages
                print(f"      • {err}")
            continue
 
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("  ✗ Passwords do not match.")
            continue
        break                             # password is valid and confirmed
 
    email = input("Enter your email: ").strip()
 
    users_db[username] = {
        "password_hash": hash_password(password),
        "email": email,
        "failed_attempts": 0,
        "locked": False,
    }
    print(f"  ✓ Account '{username}' created successfully!\n")
 
 
# ── Login ─────────────────────────────────────────────────────────────────────
 
def login_user() -> str | None:
    """
    Attempt to log in.
    Loops up to MAX_LOGIN_ATTEMPTS times before locking the account.
    Returns a session token on success, or None on failure.
    """
    print("\n── Login ────────────────────────────────")
    username = input("Username: ").strip()
 
    if username not in users_db:
        print("  ✗ User not found.")
        return None
 
    user = users_db[username]
 
    if user["locked"]:
        print("  ✗ Account is locked. Contact support.")
        return None
 
    # Loop over remaining attempts
    attempts_left = MAX_LOGIN_ATTEMPTS - user["failed_attempts"]
    while attempts_left > 0:             # <-- retry loop
        password = getpass.getpass("Password: ")
 
        if hash_password(password) == user["password_hash"]:
            user["failed_attempts"] = 0
            token = generate_session_token(username)
            active_sessions[token] = username
            print(f"  ✓ Welcome back, {username}! (session: {token[:8]}…)\n")
            return token
 
        user["failed_attempts"] += 1
        attempts_left -= 1
        if attempts_left > 0:
            print(f"  ✗ Wrong password. {attempts_left} attempt(s) left.")
        else:
            user["locked"] = True
            print("  ✗ Too many failures. Account locked.")
 
    return None
 
 
# ── Logout ────────────────────────────────────────────────────────────────────
 
def logout_user(token: str) -> None:
    if token in active_sessions:
        username = active_sessions.pop(token)
        print(f"  ✓ '{username}' logged out.\n")
    else:
        print("  ✗ Invalid session token.\n")
 
 
# ── List users (loop demo) ────────────────────────────────────────────────────
 
def list_users() -> None:
    """Display all registered users using a loop."""
    print("\n── Registered Users ─────────────────────")
    if not users_db:
        print("  (none)")
    else:
        for i, (uname, info) in enumerate(users_db.items(), start=1):  # <-- enumeration loop
            status = "🔒 LOCKED" if info["locked"] else "✓ active"
            print(f"  {i:>2}. {uname:<20} {status}  (email: {info['email']})")
    print()
 
 
# ── Reset locked accounts ─────────────────────────────────────────────────────
 
def reset_all_locked() -> None:
    """Unlock every locked account — demonstrates looping over a dict."""
    unlocked = []
    for username, info in users_db.items():   # <-- dict iteration loop
        if info["locked"]:
            info["locked"] = False
            info["failed_attempts"] = 0
            unlocked.append(username)
 
    if unlocked:
        print(f"  ✓ Unlocked: {', '.join(unlocked)}\n")
    else:
        print("  No locked accounts found.\n")
 
 
# ── Main menu (loop-driven) ───────────────────────────────────────────────────
 
MENU_OPTIONS = {
    "1": ("Register",            register_user),
    "2": ("Login",               None),          # handled inline (needs token)
    "3": ("Logout",              None),          # handled inline (needs token)
    "4": ("List users",          list_users),
    "5": ("Reset locked accounts", reset_all_locked),
    "6": ("Exit",                None),
}
 
def main() -> None:
    print("╔══════════════════════════════════════╗")
    print("║       Python Auth Demo System        ║")
    print("╚══════════════════════════════════════╝")
 
    current_token: str | None = None
 
    while True:                              # <-- main application loop
        print("── Menu ─────────────────────────────────")
        for key, (label, _) in MENU_OPTIONS.items():   # <-- loop to print menu
            active = " ← logged in" if (key == "3" and current_token) else ""
            print(f"  [{key}] {label}{active}")
        print()
 
        choice = input("Select option: ").strip()
 
        if choice == "1":
            register_user()
 
        elif choice == "2":
            if current_token:
                print("  ✗ Already logged in. Logout first.\n")
            else:
                current_token = login_user()
 
        elif choice == "3":
            if not current_token:
                print("  ✗ Not logged in.\n")
            else:
                logout_user(current_token)
                current_token = None
 
        elif choice == "4":
            list_users()
 
        elif choice == "5":
            reset_all_locked()
 
        elif choice == "6":
            print("\nGoodbye!\n")
            break                            # exit the main loop
 
        else:
            print("  ✗ Invalid option. Try again.\n")
 
 
if __name__ == "__main__":
    main()
