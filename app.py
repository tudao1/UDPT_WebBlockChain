import streamlit as st
import bcrypt
import streamlit_authenticator as stauth
import json

# Dữ liệu người dùng sẽ được lưu trữ trong file JSON
USER_DB = "user_data.json"


# Hàm trợ giúp lưu dữ liệu vào file JSON
def load_users():
    try:
        with open(USER_DB, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def save_users(users):
    with open(USER_DB, 'w') as file:
        json.dump(users, file)


# Hàm đăng ký người dùng mới
def register_user(username, password, privacy_setting="Public", devices=None):
    if devices is None:
        devices = []

    users = load_users()
    if username in users:
        return False, "Username already exists."

    # Mã hóa mật khẩu trước khi lưu
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {
        "password": hashed_password,
        "privacy_setting": privacy_setting,
        "devices": devices,
    }
    save_users(users)
    return True, "User registered successfully!"


# Hàm xác thực đăng nhập
def authenticate_user(username, password):
    users = load_users()
    if username not in users:
        return False, "User does not exist."
    
    hashed_password = users[username]["password"]
    if bcrypt.checkpw(password.encode(), hashed_password.encode()):
        return True, "Authenticated successfully!"
    else:
        return False, "Incorrect password."


# Giao diện Streamlit
st.title("WebChat-Blockchain")

# Lựa chọn giữa Đăng ký và Đăng nhập
auth_choice = st.sidebar.selectbox("Authentication", ["Login", "Register"])

if auth_choice == "Register":
    st.subheader("Register New Account")
    reg_username = st.text_input("Username", key="reg_username")
    reg_password = st.text_input("Password", type="password", key="reg_password")
    reg_privacy = st.selectbox("Privacy Setting", ["Public", "Friends Only", "Private"])

    if st.button("Register"):
        success, message = register_user(reg_username, reg_password, reg_privacy)
        st.success(message) if success else st.error(message)

elif auth_choice == "Login":
    st.subheader("Login to Your Account")
    login_username = st.text_input("Username", key="login_username")
    login_password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login"):
        success, message = authenticate_user(login_username, login_password)
        if success:
            st.session_state["username"] = login_username
            st.success("Logged in successfully!")
        else:
            st.error(message)


# Giao diện Quản lý tài khoản và cài đặt bảo mật khi người dùng đã đăng nhập
if "username" in st.session_state:
    st.sidebar.subheader(f"Welcome, {st.session_state['username']}")
    account_choice = st.sidebar.selectbox("Account Management", ["Profile", "Security Settings", "Device Management"])

    if account_choice == "Profile":
        st.subheader("Profile Management")
        users = load_users()
        user_info = users[st.session_state["username"]]
        
        # Hiển thị và cho phép thay đổi quyền riêng tư
        new_privacy = st.selectbox("Privacy Setting", ["Public", "Friends Only", "Private"], index=["Public", "Friends Only", "Private"].index(user_info["privacy_setting"]))
        if new_privacy != user_info["privacy_setting"]:
            users[st.session_state["username"]]["privacy_setting"] = new_privacy
            save_users(users)
            st.success("Privacy setting updated.")

    elif account_choice == "Security Settings":
        st.subheader("Security Settings")
        st.text("Manage your security settings here.")
        # Thêm chức năng bảo mật khác nếu cần

    elif account_choice == "Device Management":
        st.subheader("Device Management")
        users = load_users()
        devices = users[st.session_state["username"]]["devices"]

        # Hiển thị danh sách thiết bị
        st.write("Logged in Devices:")
        for idx, device in enumerate(devices):
            st.write(f"Device {idx + 1}: {device}")

        # Chức năng đăng xuất từ xa các thiết bị
        if st.button("Logout from All Devices"):
            users[st.session_state["username"]]["devices"] = []
            save_users(users)
            st.success("Logged out from all devices.")

# Đăng xuất người dùng
if st.sidebar.button("Logout"):
    if "username" in st.session_state:
        del st.session_state["username"]
        st.sidebar.success("Logged out successfully.")
