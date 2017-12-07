import webbrowser
import requests
import json
import os.path
import argparse
import os.path

from oauth2client import client


class GoogleContacts(object):
    """
    Create a general Google Contacts class
    """

    def __init__(self, credentials_file, secret):
        """
        :param credentials_file: The file where the OAuth2 response will be returned
        :param secret: The secrets file that was obtained from Google Developer Console
        """

        self.secret = secret
        self.credentials_file = credentials_file

    def _read_credentials(self):
        """
        Reads JSON with credentials from file.

        :return: Credentials to that can be used by other processes
        """
        if os.path.isfile(self.credentials_file):

            f = open(self.credentials_file, "r")

            credentials = client.OAuth2Credentials.from_json(f.read())
            f.close()
        else:
            credentials = None

        return credentials

    def _write_credentials(self, credentials):
        """
        Writes credentials as JSON to file.

        :param credentials: The credential data to be written back to a file for reuse
        """

        f = open(self.credentials_file, "w")
        f.write(credentials.to_json())
        f.close()

    def _acquire_oauth2_credentials(self):
        """
        Flows through OAuth 2.0 authorization process for credentials.

        :return: Credentials to that can be used by other processes
        """

        flow = client.flow_from_clientsecrets(
            self.secret,
            scope='http://www.google.com/m8/feeds/contacts/',
            redirect_uri='urn:ietf:wg:oauth:2.0:oob')

        auth_uri = flow.step1_get_authorize_url()
        webbrowser.open(auth_uri)

        auth_code = input('Please enter the authentication code: ')

        credentials = flow.step2_exchange(auth_code)
        return credentials

    def get_all_contacts(self, domain, alt='json', max_results=600, projection='thin'):
        """
        Query Google Contacts for all directory contacts and return the results

        :param domain: Domain to be queried (i.e. example.com)
        :param alt: Choose the format of the return results: json (default), atom, rss
        :param max_results: The number of results to return from the query (Default: 600)
        :param projection: The amount of information to be returned by the query: thin (default) & full

        :return: Results of the request.
        """

        creds = self._read_credentials()

        if creds is None or creds.invalid:
            creds = self._acquire_oauth2_credentials()
            self._write_credentials(creds)

        with open(self.credentials_file, 'r') as f:
            data = json.load(f)

            at = data['access_token']

            url = "https://www.google.com/m8/feeds/contacts/{domain}/{projection}".format(domain=domain,
                                                                                          projection=projection)

            querystring = {"max-results": max_results,
                           "alt": alt}

            headers = {
                'Authorization': "Bearer {0}".format(at)

            }

            response = requests.request("GET", url, headers=headers, params=querystring)

        f.close()

        return response.text

    def create_contact(self, domain, feed_file, projection='thin'):
        """
        Create a single contact object in Google

        :param domain: Domain to be queried (i.e. example.com)
        :param feed_file: Input file to be parsed to create a new contact
        :param projection: The amount of information to be returned by the query: thin (default) & full


        :return: Results of the request sent to Google
        """

        response = []
        creds = self._read_credentials()

        if creds is None or creds.invalid:
            creds = self._acquire_oauth2_credentials()
            self._write_credentials(creds)

        with open(self.credentials_file, 'r') as f:
            data = json.load(f)

            at = data['access_token']

            url = "https://www.google.com/m8/feeds/contacts/{domain}/{projection}".format(domain=domain,
                                                                                          projection=projection)

            headers = {
                'Authorization': "Bearer {0}".format(at),
                'Content-Type': "application/atom+xml",
                'Gdata-Version': "3.0"
                }

            with open(feed_file, 'r') as feed:
                next(feed)
                for entry in feed:
                    user = entry.strip('\n').split(',')

                    payload = """
                            <atom:entry xmlns:atom="http://www.w3.org/2005/Atom"
                                xmlns:gd="http://schemas.google.com/g/2005">
                              <atom:category scheme="http://schemas.google.com/g/2005#kind"
                                term="http://schemas.google.com/contact/2008#contact"/>
                              <gd:name>
                                 <gd:givenName>{first_name}</gd:givenName>
                                 <gd:familyName>{last_name}</gd:familyName>
                                 <gd:fullName>{full_name}</gd:fullName>
                              </gd:name>
                              <atom:content type="text">Notes</atom:content>
                              <gd:email rel="http://schemas.google.com/g/2005#work"
                                primary="true"
                                address="{address}" displayName="{display_name}"/>
                            </atom:entry>
                            """.format(first_name=user[0],
                                       last_name=user[1],
                                       full_name=user[2],
                                       address=user[3],
                                       display_name=user[2])

                    response.append(requests.request("POST", url, data=payload, headers=headers))

            feed.close()
        f.close()
        return response


if __name__ == '__main__':

        """ 
        General example of how this file will work
        
        Example:
        
         
        """
        # Set Default values that can be over written
        creds = 'credentials.json'
        secret = 'client_secret.json'

        # Setup Arg parsing
        parser = argparse.ArgumentParser(description='Google Contacts API Scraper')
        req = parser.add_argument_group('Required Names Arguments')
        req.add_argument('-d', '--domain', help='The name of the domain to be used (i.e. example.com', required=True)
        req.add_argument('-a', '--action', help='Action to be completed. Options include '
                                                'CREATE, DELETE, UPDATE', required=True)
        req.add_argument('FILE', help='File to be parsed for all actions')

        parser.add_argument('-c', '--credentials', help='Credentials file to write back to [OPTIONAL]')
        parser.add_argument('-s', '--secret', help='Secrets file to read from to obtain a new token [OPTIONAL]')

        args = parser.parse_args()

        if os.path.isfile(creds):
            os.remove(creds)

        # Check for override values
        if args.credentials:
            creds = args.credentials
        if args.secret:
            secret = args.secret

        # Check for LIST action
        if args.action.lower() == 'list':
            service = GoogleContacts(creds, secret)
            results = service.get_all_contacts(args.domain)
            print(results)

        # Check for CREATE
        if args.action.lower() == 'create':
            service = GoogleContacts(creds, secret)
            results = service.get_all_contacts(args.domain)
            print(results)

        # Check for DELETE
        if args.action.lower() == 'delete':
            service = GoogleContacts(creds, secret)
            results = service.get_all_contacts(args.domain)
            print(results)

        # Check for UPDATE
        if args.action.lower() == 'update':
            service = GoogleContacts(creds, secret)
            results = service.get_all_contacts(args.domain)
            print(results)



