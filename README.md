# esm_close_cases
Automatcally close all open cases on McAfee ESM SIEM

This is a script that will set all open cases on a McAfee ESM to closed. 

The script can be run in a Python 3 envirnment (requires 'requests') or as a standalone 32-bit Windows executable.

Both options require that provided ".mfe_saw.ini" file be in the same directory as the script and populated with the ESM credentials and IP address. 

Once the ".mfe_saw.ini" is in place, running the script a single time will immediately set all cases to closed without prompt. 

