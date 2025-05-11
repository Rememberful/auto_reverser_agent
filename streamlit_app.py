# streamlit_app.py - Placeholder content
import streamlit as st
from analyzer.static_analyzer import analyze_binary
from gpt.gpt_summarizer import generate_summary

def app():
    st.title("Auto-Reverser Agent")

    uploaded_file = st.file_uploader("Upload a binary file", type=["exe", "bin"])

    if uploaded_file is not None:
        # Save the uploaded file to disk
        with open("uploaded_binary", "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Perform static analysis on the file
        analysis_result = analyze_binary("uploaded_binary")
        
        # Generate GPT summary
        summary = generate_summary(analysis_result)
        
        st.write("### Analysis Summary")
        st.text(summary)

if __name__ == "__main__":
    app()
