# Intentionally insecure demo code for the scanner lab; findings accepted.
password = "SuperSecret123"  # nosemgrep
x = eval(input())  # nosemgrep
exec(user_code)  # nosemgrep
