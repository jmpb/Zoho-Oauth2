from datetime import datetime, timedelta
import requests

class ZOAuth2Client:
    '''
    A simple Oauth2 client for Zoho specific APIs. This will not do the initial authorization
    but is useful for use once the initial access & refresh tokens are obtained.
    '''

    def __init__(self, tokens: dict, domain: str="accounts.zoho", dc: str="eu") -> None:
        '''
        Create a new client for the application.

        @param tokens       - a dict containing client ID, client secret & refresh_token.
                                Optionally also an existing access token.
        @param domain       - the API domain to use. E.G. "workdrive.zoho", "sheet.zoho".
                                Defaults to "accounts.zoho".
        @param dc           - the datacentre to connect to. E.G. "COM", "CH", "AU", "IN"
                                Defaults to "EU".
        '''
        if not all([k in tokens for k in ["client_id", "client_secret", "refresh_token"]]):
            raise ValueError("Client ID, secret and refresh token are all required.")
        self.dc = dc
        self.client_id = tokens["client_id"]
        self.client_secret = tokens["client_secret"]
        self.refresh_token = tokens["refresh_token"]
        self.redirect_uri = "https://localhost/" # Could be another parameter
        self.access_token = tokens["access_token"] if "access_token" in tokens else None
        self.expires_in = None
        self.expires_time = None
        self.domain = f"https://{domain}.{dc}"

    def test_token(self):
        '''
        Sends a get request to an endpoint to check if the token works or needs refreshing.
        Initiates token refresh if needed.
        '''
        h = self.authorize_header()
        # User info URLs are annoyingly different for each Zoho API and also depend on client
        # scope defined. For my current use case (WorkDrive) this will work but this needs
        # work so it will succeed with other Zoho APIs.
        url = f"{self.domain}.{self.dc}/api/v1/users/me"
        response = requests.get(url, headers=h)
        if response.json()["id"] == "F7003": # WorkDrive specific error ID.
            self.request_new_token()
            
    def request_new_token(self) -> bool:
        '''
        Sends a refresh request to Zoho to obtain a new access token.

        @return a boolean indicating whether a new token was obtained.
        '''
        url = f"https://accounts.zoho.{self.dc}/oauth/v2/token"
        p = {
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "refresh_token"
        }
        response = requests.post(url, params=p)
        json_response = response.json()
        if "access_token" not in json_response: return False
        self.access_token = json_response["access_token"]
        self.expires_in = json_response["expires_in"]
        self.expires_time = datetime.now() + timedelta(seconds=self.expires_in)
        return True

    def authorize_header(self, h: dict={}):
        '''
        Add the Authorization bearer header to the given dict of headers.

        @params h       - any headers to preserve.
        @return a dict with the Authorization header as well as any given.
        '''
        h["Authorization"] = f"Bearer {self.access_token}"
        return h

    def has_expired(self) -> bool:
        '''
        Check if the current access token has expired. Assumes True if expiry time unknown.

        @return a boolean indicating expiry status.
        '''
        return self.expires_time == None or datetime.now() > self.expires_time

    def query(self, ep: str, p: dict={}, h: dict={}, d: dict={}, file: dict={}) -> dict:
        '''
        Query the given endpoint. Will auto-detect method based on values given.

        @params ep      - the endpoint to send the request.
        @params p       - any parameters to use.
        @params h       - any headers to use. Note: Authorization header auto-added.
        @params d       - any data to be sent.
        @params file    - any files to be sent as multi-part.
        @return a dict containing the JSON response.
        '''
        if self.has_expired() or not self.access_token:
            if not self.request_new_token():
                raise ValueError("Could not obtain Client access token from Zoho.")

        h = self.authorize_header()

        if len(d) == 0 and len(file) == 0:
            response = requests.get(self.domain + ep, params=p, headers=h)
        elif len(file) == 0:
            response = requests.post(self.domain + ep, data=d, params=p, headers=h)
        else:
            response = requests.post(self.domain + ep, data=d, params=p, headers=h, files=file)

        return response.json()