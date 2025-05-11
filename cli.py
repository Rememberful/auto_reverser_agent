import argparse
from analyzer.static_analyzer import analyze_binary

def main():
    parser = argparse.ArgumentParser(description="Auto Reverser Agent CLI")
    parser.add_argument("file", help="Path to the binary file to analyze")
    args = parser.parse_args()

    file_path = args.file
    print(f"[*] Analyzing: {file_path}")

    try:
        analysis_result = analyze_binary(file_path)

        if analysis_result:
            print("[+] Analysis Result:")
            print(analysis_result)
        else:
            print("[!] No analysis result returned.")
    except Exception as e:
        print(f"[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()
