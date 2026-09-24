import argparse

def run_email():
    print("this is email")

def run_signins():
    print("this is signins")

TOOLS = {
    "email": ("analyze email content in .eml format", run_email),
    "signins": ("analyze Entra ID sign-in logs in .csv format", run_signins)
}

def main():

    parser = argparse.ArgumentParser(prog="socio", description="Cybersecurity tools for accelerating triage based on OSINT APIs")
    subparsers = parser.add_subparsers(dest="tool", help="set of available tools")

    for name, (description, handler) in TOOLS.items():
        subparsers.add_parser(name, help=description)
    
    args = parser.parse_args()

    if args.tool:
        handler = TOOLS[args.tool][1]
        handler()
    else:
        parser.error("enter a valid tool")