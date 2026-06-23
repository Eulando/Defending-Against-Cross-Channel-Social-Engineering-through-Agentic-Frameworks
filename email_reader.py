import os
import argparse

def read_emails(directory_path):
    email_contents = []
    
    # Check if the directory exists
    if not os.path.isdir(directory_path):
        print(f"Error: The directory {directory_path} does not exist.")
        return email_contents

    # Walk through the directory tree
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    email_contents.append(content)
            except Exception as e:
                print(f"Could not read file {file_path}: {e}")
    
    return email_contents

def main():
    parser = argparse.ArgumentParser(description="Read contents of all files in an emails directory.")
    parser.add_argument("directory", nargs="?", help="Path to the emails directory")
    
    args = parser.parse_args()

    if args.directory:
        emails_dir = args.directory
    else:
        # Default to "emails" directory in the same directory as the script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        emails_dir = os.path.join(script_dir, "..", "emails")

    emails_dir = os.path.abspath(emails_dir)

    print(f"Reading emails from: {emails_dir}")
    contents = read_emails(emails_dir)
    
    print("\n--- Email Contents ---")
    for idx, content in enumerate(contents, 1):
        print(f"Email {idx}: {content}")
    print("----------------------\n")
    print(f"Total emails read: {len(contents)}")

if __name__ == "__main__":
    main()
