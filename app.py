import streamlit as st
import pandas as pd
import datetime
import os
import hashlib
import io

# ---------- CONFIG ----------
st.set_page_config(page_title="TeamPulse - Daily Report", layout="wide", initial_sidebar_state="expanded")

# ---------- FILES ----------
USER_FILE = "users.csv"
REPORT_FILE = "reports.csv"

# ---------- INIT FILES ----------
def init_files():
    if not os.path.exists(USER_FILE):
        df = pd.DataFrame(columns=["username", "password", "email", "role"])
        df.loc[0] = ["Madesh", hashlib.sha256("madesh1212".encode()).hexdigest(), "madesh6554@gmail.com", "admin"]
        df.to_csv(USER_FILE, index=False)
    if not os.path.exists(REPORT_FILE):
        pd.DataFrame(columns=["username", "date", "time", "today_work", "status"]).to_csv(REPORT_FILE, index=False)

init_files()

# ---------- UTILS ----------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate(username, password):
    df = pd.read_csv(USER_FILE)
    hashed_pw = hash_password(password)
    user = df[(df.username == username) & (df.password == hashed_pw)]
    if not user.empty:
        return user.iloc[0].to_dict()
    return None

def register_user(username, password, email):
    df = pd.read_csv(USER_FILE)
    if username in df.username.values:
        return False
    new_user = pd.DataFrame([{"username": username, "password": hash_password(password), "email": email, "role": "user"}])
    df = pd.concat([df, new_user], ignore_index=True)
    df.to_csv(USER_FILE, index=False)
    return True

def submit_report(username):
    today = datetime.date.today()
    time_now = datetime.datetime.now().strftime("%H:%M:%S")
    today_work = st.text_area("Describe today's work")
    status = st.radio("Work Status", ["Done", "Not Yet"])

    if st.button("Submit Report"):
        new_report = pd.DataFrame([{"username": username, "date": today, "time": time_now,
                                     "today_work": today_work, "status": status}])
        df = pd.read_csv(REPORT_FILE)
        df = pd.concat([df, new_report], ignore_index=True)
        df.to_csv(REPORT_FILE, index=False)
        st.success("Report submitted!")

# ---------- UI ----------
def logout():
    for key in list(st.session_state.keys()):
        del st.session_state[key]
    st.rerun()

def login():
    st.title("TeamPulse Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        user = authenticate(username, password)
        if user:
            st.session_state.username = user["username"]
            st.session_state.role = user["role"]
            st.success("Welcome, {}!".format(user["username"]))
            st.rerun()
        else:
            st.error("Invalid credentials")

    st.markdown("---")
    st.subheader("New User? Register below")
    new_user = st.text_input("New Username")
    new_pw = st.text_input("New Password", type="password")
    email = st.text_input("Email")
    if st.button("Register"):
        if register_user(new_user, new_pw, email):
            st.success("Account created! Now login.")
        else:
            st.warning("Username already exists.")

def show_user_dashboard():
    st.title("Team Member Dashboard")
    st.markdown(f"Welcome, **{st.session_state.username}**!")
    submit_report(st.session_state.username)
    if st.button("Logout"):
        logout()

def show_admin_dashboard():
    st.title("Admin Dashboard - Team Leader")
    st.markdown(f"Hello **{st.session_state.username}**, you're leading the team!")

    with st.expander("Submit Your Own Daily Report"):
        submit_report(st.session_state.username)

    st.subheader("All Team Reports")
    df = pd.read_csv(REPORT_FILE)
    st.dataframe(df)

    # Convert the DataFrame to an Excel file in memory using BytesIO
    excel_file = io.BytesIO()
    with pd.ExcelWriter(excel_file, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Reports")
    excel_file.seek(0)  # Rewind the BytesIO object to the beginning

    st.download_button(
        "Download as Excel", 
        excel_file, 
        file_name="team_reports.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    st.markdown("---")
    if st.button("Logout"):
        logout()

# ---------- MAIN ----------
def main():
    if "username" not in st.session_state:
        login()
    elif st.session_state.get("role") == "admin":
        show_admin_dashboard()
    else:
        show_user_dashboard()

if __name__ == '__main__':
    main()
