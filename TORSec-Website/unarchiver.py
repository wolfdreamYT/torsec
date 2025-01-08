import curses
import os
import zipfile
import base64
from hashlib import sha256


def hash_key(key):
    """
    Generate a SHA-256 hash from the provided key.
    """
    return sha256(key.encode()).digest()


def unarchive_file(stdscr):
    """
    Unarchive a .torsec file with password validation.
    """
    stdscr.clear()
    stdscr.addstr("Enter the path to the .torsec file: ")
    stdscr.refresh()
    curses.echo() 
    filepath = stdscr.getstr().decode("utf-8").strip()
    curses.noecho()

    if not os.path.exists(filepath):
        stdscr.addstr("\nError: File not found.\n")
        stdscr.refresh()
        curses.napms(2000)
        return

    stdscr.addstr("\nPassword: ")
    stdscr.refresh()
    curses.echo()
    password = stdscr.getstr().decode("utf-8").strip()
    curses.noecho()

    hashed_password = hash_key(password)

    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            signature = zf.read('signature').decode()
            if signature != base64.b64encode(hashed_password).decode():
                stdscr.addstr("\nIncorrect password or file integrity compromised.\n")
                stdscr.refresh()
                curses.napms(2000)
                return

            stdscr.addstr("\nEnter the directory to extract the files: ")
            stdscr.refresh()
            curses.echo()
            output_dir = stdscr.getstr().decode("utf-8").strip()
            curses.noecho()

            for file in zf.namelist():
                if file == 'signature':
                    continue 

                encrypted_content = zf.read(file).decode()
                decrypted_content = base64.b64decode(encrypted_content)

                output_path = os.path.join(output_dir, file)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'wb') as f:
                    f.write(decrypted_content)

            stdscr.addstr(f"\nFiles successfully extracted to: {output_dir}\n")
            stdscr.refresh()
            curses.napms(2000)

    except zipfile.BadZipFile:
        stdscr.addstr("\nError: The specified file is not a valid .torsec file.\n")
        stdscr.refresh()
        curses.napms(2000)
    except Exception as e:
        stdscr.addstr(f"\nAn error occurred: {e}\n")
        stdscr.refresh()
        curses.napms(2000)


def menu(stdscr):
    """
    Interactive menu with functional buttons using curses.
    """
    curses.curs_set(0) 
    stdscr.clear()
    options = ["Unarchive File", "Cancel"]
    current_option = 0 

    while True:
        stdscr.clear()
        stdscr.addstr("#######################################\n")
        stdscr.addstr("#                        Options:                                               #\n")
        stdscr.addstr("# ------------------------------------------------ #\n")
        for idx, option in enumerate(options):
            if idx == current_option:
                stdscr.addstr(f"# >>> {option:<55}#\n", curses.A_REVERSE)  
            else:
                stdscr.addstr(f"#     {option:<55}#\n")
        stdscr.addstr("# ------------------------------------------------ #\n")
        stdscr.addstr("#######################################\n")
        stdscr.refresh()

        key = stdscr.getch()

        if key == curses.KEY_UP and current_option > 0:
            current_option -= 1 
        elif key == curses.KEY_DOWN and current_option < len(options) - 1:
            current_option += 1 
        elif key == ord('\n'): 
            if options[current_option] == "Unarchive File":
                unarchive_file(stdscr)
            elif options[current_option] == "Cancel":
                stdscr.clear()
                stdscr.addstr("Exiting program...\n")
                stdscr.refresh()
                curses.napms(1000)
                break


if __name__ == "__main__":
    curses.wrapper(menu)
