import os
import re

def read_email_files(folder_name="Email"):
    if not os.path.exists(folder_name):
        print(f"Error: Folder '{folder_name}' not found.")
        return []

    txt_files = [f for f in os.listdir(folder_name) if f.endswith(".txt")]

    if not txt_files:
        print(f"No .txt files found in '{folder_name}'.")
        return []

    def extract_number(filename):
        match = re.search(r"(\d+)", filename)
        return int(match.group(1)) if match else float("inf")

    txt_files.sort(key=extract_number)

    emails = []
    for filename in txt_files:
        filepath = os.path.join(folder_name, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            emails.append({"filename": filename, "content": content})

    for i, email in enumerate(emails, start=1):
        print(f"{'='*50}")
        print(f"Email {i}: {email['filename']}")
        print(f"{'='*50}")
        print(email["content"])
        print()

    print(f"Total emails read: {len(emails)}")
    return emails

emails = read_email_files()
