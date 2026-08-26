import streamlit as st

if 'sidebar_state' not in st.session_state:
    st.session_state.sidebar_state = 'expanded'

def toggle_sidebar():
    st.session_state.sidebar_state = 'collapsed' if st.session_state.sidebar_state == 'expanded' else 'expanded'

st.set_page_config(initial_sidebar_state=st.session_state.sidebar_state)

st.button("Toggle Sidebar", on_click=toggle_sidebar)
st.sidebar.button("Toggle Sidebar Sidebar", on_click=toggle_sidebar)
