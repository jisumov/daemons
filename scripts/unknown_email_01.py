"""...you can fake it, infiltrate it, corporate it, little boy..."""

import email
import sys
from email.parser import HeaderParser

def analyze_headers(raw_header_text):
    """Parses raw email headers and extracts key fields for security triage."""
    parser = HeaderParser()
    headers = parser.parsestr(raw_header_text)

    print("\n--- Initial Header Triage ---")
    
    # Extracting standard fields
    print(f"From:    {headers.get('From', 'Not Found')}")
    print(f"To:      {headers.get('To', 'Not Found')}")
    print(f"Subject: {headers.get('Subject', 'Not Found')}")
    print(f"Date:    {headers.get('Date', 'Not Found')}")
    print(f"Message-ID: {headers.get('Message-ID', 'Not Found')}")

if __name__ == "__main__":
    print("Paste the raw email headers below.")
    print("When finished, press Enter to go to a new line, then press Ctrl+D to run the analysis:\n")
    
    # Read all lines from standard input until an EOF (End of File) signal
    raw_input = sys.stdin.read()
    
    # Only run the analysis if the user actually pasted something
    if raw_input.strip():
        analyze_headers(raw_input)
    else:
        print("\nNo headers provided. Exiting daemon.")