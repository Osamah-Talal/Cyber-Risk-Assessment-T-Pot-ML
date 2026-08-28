from pathlib import Path

def rename_cowrie_files(directory_path="."):
    # Convert the input string to a Path object
    dir_path = Path(directory_path)
    
    # Track how many files we successfully rename
    rename_count = 0
    
    # Loop through files matching the pattern "cowrie.json.*"
    for file_path in dir_path.glob("cowrie.json.*"):
        # Extract the suffix (the extension number like '1' from '.1')
        # file_path.suffix returns '.1', so we strip the dot
        file_extension = file_path.suffix.lstrip('.')
        
        # Make sure the suffix is actually a number before renaming
        if file_extension.isdigit():
            # Construct the new filename
            new_name = f"cowrie{file_extension}.json"
            new_file_path = dir_path / new_name
            
            try:
                # Rename the file
                file_path.rename(new_file_path)
                print(f"Renamed: {file_path.name} -> {new_name}")
                rename_count += 1
            except Exception as e:
                print(f"Error renaming {file_path.name}: {e}")
                
    print(f"\nTask finished. Total files renamed: {rename_count}")

# Run the function in the current directory
if __name__ == "__main__":
    # If your files are in a different folder, replace "." with the path, 
    # e.g., rename_cowrie_files("/path/to/your/logs")
    rename_cowrie_files(".")