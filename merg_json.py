import json
import os
import tkinter as tk
from tkinter import filedialog, messagebox


def merge_jsonl_files():
    # 1. Initialize the hidden root window for tkinter
    root = tk.Tk()
    root.withdraw()

    # 2. Prompt user to select multiple JSON/log files
    file_paths = filedialog.askopenfilenames(
        title="Select Cowrie JSON/Log files to merge",
        filetypes=[
            ("JSON/Log files", "*.json *.log *.jsonl"),
            ("All files", "*.*"),
        ],
    )

    if not file_paths:
        messagebox.showinfo("Cancelled", "No files selected.")
        return

    merged_data = []

    try:
        for path in file_paths:
            filename = os.path.basename(path)
            with open(path, "r", encoding="utf-8") as f:
                for line_number, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue  # Skip empty lines

                    try:
                        # Parse each line individually as its own JSON object
                        data_object = json.loads(line)
                        merged_data.append(data_object)
                    except json.JSONDecodeError as je:
                        # Alert exactly which line in which file failed
                        raise json.JSONDecodeError(
                            msg=f"Error in {filename} at line {line_number}: {je.msg}",
                            doc=je.doc,
                            pos=je.pos,
                        )

        # 3. Prompt user where to save the merged output
        save_path = filedialog.asksaveasfilename(
            title="Save Merged JSON As",
            defaultextension=".json",
            filetypes=[("Standard JSON File", "*.json")],
        )

        if not save_path:
            messagebox.showinfo("Cancelled", "Save operation cancelled.")
            return

        # 4. Write everything out as a valid single JSON array
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(merged_data, f, indent=4, ensure_ascii=False)

        messagebox.showinfo(
            "Success",
            f"Successfully parsed and merged {len(file_paths)} log files!\n"
            f"Total events processed: {len(merged_data)}\n"
            f"Saved to: {save_path}",
        )

    except json.JSONDecodeError as je:
        messagebox.showerror("Malformed Data", je.msg)
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred:\n{str(e)}")


if __name__ == "__main__":
    merge_jsonl_files()