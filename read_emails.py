import os

folder = "emails"
emails = []

for filename in os.listdir(folder):
    filepath = os.path.join(folder, filename)
    if os.path.isfile(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            emails.append({"filename": filename, "content": f.read()})

for email in emails:
    print(f"--- {email['filename']} ---")
    print(email["content"])
    print()

print(f"Total files read: {len(emails)}")
