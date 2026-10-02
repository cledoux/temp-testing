import os
import sys

# Command Injection (CWE-78): Raw user input passed directly to the shell
os.system(sys.argv[1])
