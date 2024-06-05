"""This file implement the ssl checker entrypoint
"""
import argparse

from prettytable import PrettyTable
import validators

from ssl_checker import SslChecker
import ssl_checker.exception as SslExceptions

ssl_checker = SslChecker()

class SslCheckerApp():
    """SSL Checker Details
    """

    def __init__(self):
        # Create ssl_checker object
        self._ssl_checker = SslChecker()

    def get_ssl_details(self, domain):
        """Get SSL Details

        Args:
            domain (str): domain name

        Returns:
            PrettyTable: a table which have the domain details
        """
        # Get SSL Certificate
        ssl_details = self._ssl_checker.get_cert_details(domain=domain)

        ssl_details_table = PrettyTable(['Name', 'Subject', 'Expiration', 'OCSP Status'])

        ssl_details_table.add_row(
                                [
                                    ssl_details.get("domain"),
                                    ssl_details.get("subject"),
                                    ssl_details.get("expiration"),
                                    ssl_details.get("status")
                                ])
        return ssl_details_table


def main():
    """App Entrypoint
    """
    # Get domain name as arg
    parser = argparse.ArgumentParser(description="SSL Checker App",
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument('-d','--domain_name',
                        help='Website domain name',
                        required=True,
                        type=str)

    args = vars(parser.parse_args())

    if not validators.domain(args.get("domain_name")):
        print("Error: Please enter a valid domain name")
        raise SystemExit(-1)

    ssl_app = SslCheckerApp()

    try:
        print(ssl_app.get_ssl_details(args.get("domain_name")))
    except Exception as exc:
        print(f"Error: Cannot proccess your request {exc}")


if __name__ == '__main__':
    main()
