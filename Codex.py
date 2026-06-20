from pathlib import Path
import re

def read_email_files(folder_name="Email"):
    email_folder = Path(folder_name)

    if not email_folder.exists():
        print(f"Error: Folder '{folder_name}' not found.")
        return []

    txt_files = list(email_folder.glob("*.txt"))

    if not txt_files:
        print(f"No .txt files found in '{folder_name}'.")
        return []

    def extract_number(file_path):
        match = re.search(r"\d+", file_path.name)
        return int(match.group()) if match else float("inf")

    txt_files = sorted(txt_files, key=extract_number)

    emails = []

    for txt_file in txt_files:
        content = txt_file.read_text(encoding="utf-8")
        emails.append({
            "filename": txt_file.name,
            "content": content
        })

        print(f"File name: {txt_file.name}")
        print("Email content:")
        print(content)
        print("-" * 50)

    print(f"Total files read: {len(emails)}")

    return emails


emails = read_email_files()
