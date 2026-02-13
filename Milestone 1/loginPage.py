import streamlit as st
import streamlit_antd_components as sac
import sqlite3
import hashlib
import jwt
import datetime
import re
import time

# --- CONFIGURATION ---
SECRET_KEY = "my_super_secret_key_123" 
DB_NAME = "app_data.db"

# --- 1. DATABASE MANAGEMENT ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Users Table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            username TEXT,
            password_hash TEXT,
            security_question TEXT,
            security_answer TEXT
        )
    ''')
    
    # Password History Table (Linked by Email)
    c.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            password_hash TEXT,
            changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, email, password, question, answer):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    p_hash = hash_password(password)
    
    try:
        # Add to Users Table
        c.execute('INSERT INTO users VALUES (?,?,?,?,?)', 
                  (email, username, p_hash, question, answer))
        
        # Add to History
        c.execute('INSERT INTO password_history (email, password_hash) VALUES (?,?)', 
                  (email, p_hash))
        
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False # Email already exists
    finally:
        conn.close()

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    p_hash = hash_password(password)
    
    c.execute('SELECT username FROM users WHERE email=? AND password_hash=?', (email, p_hash))
    user = c.fetchone()
    conn.close()
    return user[0] if user else None

def get_security_question(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT security_question FROM users WHERE email=?', (email,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def verify_security_answer(email, answer):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT security_answer FROM users WHERE email=?', (email,))
    result = c.fetchone()
    conn.close()
    return result and result[0] == answer

def check_password_history(email, new_password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    new_hash = hash_password(new_password)
    
    # Get the last 3 passwords
    c.execute('SELECT password_hash FROM password_history WHERE email=? ORDER BY id DESC LIMIT 3', (email,))
    history = [row[0] for row in c.fetchall()]
    conn.close()
    
    if new_hash in history:
        return False # Password was used recently
    return True

def update_password(email, new_password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    new_hash = hash_password(new_password)
    
    # 1. Update the Current Password in Users Table
    c.execute('UPDATE users SET password_hash=? WHERE email=?', (new_hash, email))
    
    # 2. Add the NEW password to History
    c.execute('INSERT INTO password_history (email, password_hash) VALUES (?,?)', (email, new_hash))
    
    # 3. CLEANUP: Delete any passwords that fall outside the "Top 3 Newest"
    # This SQL query says: 
    # "Delete from history IF the ID is NOT inside the list of the 3 most recent IDs"
    c.execute('''
        DELETE FROM password_history 
        WHERE email = ? 
        AND id NOT IN (
            SELECT id FROM password_history 
            WHERE email = ? 
            ORDER BY id DESC 
            LIMIT 3
        )
    ''', (email, email))
    
    conn.commit()
    conn.close()

# --- 2. UTILITY FUNCTIONS (JWT & REGEX) ---

def create_jwt_token(username):
    payload = {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    # At least 8 chars, 1 Uppercase, 1 Number
    if len(password) < 8: return False
    if not re.search(r"[A-Z]", password): return False
    if not re.search(r"\d", password): return False
    return True

# --- 3. UI COMPONENTS ---

# Page Setup
st.set_page_config(page_title="Secure Auth System", page_icon="🔒")
init_db() # Ensure DB exists on load

# Initialize Session State
if 'jwt_token' not in st.session_state: st.session_state.jwt_token = None
if 'forgot_step' not in st.session_state: st.session_state.forgot_step = 1
if 'reset_email' not in st.session_state: st.session_state.reset_email = None

# --- 4. MAIN APP LOGIC ---

# CHECK LOGIN STATUS
user = None
if st.session_state.jwt_token:
    user = verify_jwt_token(st.session_state.jwt_token)

if user:
    # --- DASHBOARD (LOGGED IN) ---
    st.balloons()
    st.title(f"Welcome, {user}! 👋")
    st.success("You are securely logged in.")
    
    st.write("Here is your private dashboard.")
    
    if st.button("Logout", type="primary"):
        st.session_state.jwt_token = None
        st.rerun()

else:
    # --- AUTHENTICATION PAGES ---
    
    # Center Layout
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Toggle between Login, Signup, Forgot Password
        auth_mode = sac.segmented(
            items=[
                sac.SegmentedItem(label='Login', icon='box-arrow-in-right'),
                sac.SegmentedItem(label='Sign Up', icon='person-plus-fill'),
                sac.SegmentedItem(label='Forgot Password', icon='key'),
            ],
            align='center', 
            use_container_width=True,
            color='red'
        )

        with st.container(border=True):
            
            # --- LOGIN FLOW ---
            if auth_mode == 'Login':
                st.subheader("Sign In")
                email = st.text_input("Email Address", key="login_email")
                password = st.text_input("Password", type="password", key="login_pass")
                
                if st.button("Log In", type="primary", use_container_width=True):
                    if not email or not password:
                        st.error("All fields are mandatory.")
                    else:
                        username = authenticate_user(email, password)
                        if username:
                            token = create_jwt_token(username)
                            st.session_state.jwt_token = token
                            st.rerun()
                        else:
                            st.error("Invalid Email or Password.")

            # --- SIGN UP FLOW ---
            elif auth_mode == 'Sign Up':
                st.subheader("Create Account")
                new_user = st.text_input("Username")
                new_email = st.text_input("Email Address")
                
                # Password Rules Display
                st.caption("Password must be 8+ chars, contain 1 Upper Case & 1 Number.")
                pass1 = st.text_input("Password", type="password")
                pass2 = st.text_input("Confirm Password", type="password")
                
                # Security Question Dropdown
                sec_q = st.selectbox("Select Security Question", 
                    ["What is your pet's name?", "What city were you born in?", "What is your mother's maiden name?"])
                sec_a = st.text_input("Security Answer")

                if st.button("Sign Up", type="primary", use_container_width=True):
                    # VALIDATIONS
                    if not (new_user and new_email and pass1 and pass2 and sec_a):
                        st.error("All fields are mandatory!")
                    elif not validate_email(new_email):
                        st.error("Invalid Email Format (example@domain.com)")
                    elif pass1 != pass2:
                        st.error("Passwords do not match!")
                    elif not validate_password(pass1):
                        st.error("Password too weak! (Need 8 chars, 1 Uppercase, 1 Number)")
                    else:
                        success = add_user(new_user, new_email, pass1, sec_q, sec_a)
                        if success:
                            st.success("Account Created! Please switch to Login tab.")
                        else:
                            st.error("Email already exists.")

            # --- FORGOT PASSWORD WIZARD ---
            elif auth_mode == 'Forgot Password':
                st.subheader("Reset Password")
                
                # STEP 1: ENTER EMAIL
                if st.session_state.forgot_step == 1:
                    f_email = st.text_input("Enter your registered Email")
                    if st.button("Find Account"):
                        question = get_security_question(f_email)
                        if question:
                            st.session_state.reset_email = f_email
                            st.session_state.security_q_display = question
                            st.session_state.forgot_step = 2
                            st.rerun()
                        else:
                            st.error("Email not found.")
                
                # STEP 2: ANSWER QUESTION
                elif st.session_state.forgot_step == 2:
                    st.info(f"Security Question: {st.session_state.security_q_display}")
                    ans = st.text_input("Your Answer")
                    if st.button("Verify Answer"):
                        if verify_security_answer(st.session_state.reset_email, ans):
                            st.session_state.forgot_step = 3
                            st.rerun()
                        else:
                            st.error("Incorrect Answer.")
                    
                    if st.button("Back"):
                        st.session_state.forgot_step = 1
                        st.rerun()

                # STEP 3: RESET PASSWORD
                elif st.session_state.forgot_step == 3:
                    st.success("Identity Verified!")
                    new_p1 = st.text_input("New Password", type="password")
                    new_p2 = st.text_input("Confirm New Password", type="password")
                    
                    if st.button("Update Password"):
                        if not validate_password(new_p1):
                            st.error("Password too weak (8 chars, 1 Upper, 1 Number).")
                        elif new_p1 != new_p2:
                            st.error("Passwords do not match.")
                        else:
                            # CHECK HISTORY (Last 3 Passwords)
                            if check_password_history(st.session_state.reset_email, new_p1):
                                update_password(st.session_state.reset_email, new_p1)
                                st.success("Password Updated! Go to Login.")
                                # Reset flow
                                st.session_state.forgot_step = 1
                                st.session_state.reset_email = None
                            else:
                                st.error("You cannot reuse any of your last 3 passwords.")