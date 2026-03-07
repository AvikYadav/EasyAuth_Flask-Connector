import requests

import encryption
class LoginConnector:
    """
    Client connector for interacting with the auth service.

    Usage:
        connector = LoginConnector(
            base_url     = "http://127.0.0.1:5000",
            username     = "john_doe",
            service_name = "my_app",
        )

        # Send user data to the server
        connector.send_user_data(token="<jwt>", data={"theme": "dark"})

        # Retrieve user data from the server
        result = connector.get_user_data(token="<jwt>")
    """

    def __init__(self, username: str, service_name: str,api_key:str,base_url="https://easy-auth.dev",):
        """
        Initialize the connector.

        Args:
            base_url     : Base URL of the auth server (e.g. "http://127.0.0.1:5000")
            username     : The developer's username (collection owner)
            service_name : The registered service name
        """
        self.base_url     = base_url.rstrip("/")
        self.username     = username
        self.service_name = service_name
        self.api_key = api_key
        # Shared endpoint for both send and retrieve
        self.endpoint_retrieve = f"{self.base_url}/retrieve/{self.username}/{self.service_name}"
        self.endpoint_update = f"{self.base_url}/update/{self.username}/{self.service_name}"
        self.endpoint_verify = f"{self.base_url}/verify/{self.username}/{self.service_name}"


    def get_user_data(self, token: str) -> dict | None:
        """
        Retrieve user data from the server for the given JWT token.

        Args:
            token : JWT token of the authenticated user

        Returns:
            dict  : Response data from the server on success
            None  : If the request fails
        """
        payload = {"token": self.decrypt_token(token)}

        try:
            response = requests.post(self.endpoint_retrieve, json=payload)

            if response.status_code == 200:
                return response.json()
            else:
                print(f"[LoginConnector] get_user_data failed — {response.status_code}: {response.text}")
                return None

        except Exception as e:
            print(f"[LoginConnector] get_user_data error: {e}")
            return None


    def send_or_update_user_data(self, token: str, data: dict) -> dict | None:
        """
        Send user data to the server to be stored against the user's account.

        Args:
            token : JWT token of the authenticated user
            data  : Any JSON-serializable dict to store
                    e.g. {"theme": "dark", "last_page": "/home"}

        Returns:
            dict  : Response from the server on success
            None  : If the request fails
        """
        payload = {
            "token":     self.decrypt_token(token),
            "user_data": data,
        }

        try:
            response = requests.post(self.endpoint_update, json=payload)

            if response.status_code == 200:
                return response.json()
            else:
                print(f"[LoginConnector] send_user_data failed — {response.status_code}: {response.text}")
                return None

        except Exception as e:
            print(f"[LoginConnector] send_user_data error: {e}")
            return None



    def verify_user_login(self, token: str) -> dict | None:
        """
        verify user data to the server against the user's account.

        Args:
            token : JWT token of the authenticated user


        Returns:
            dict  : Response from the server on success
            None  : If the request fails
        """
        payload = {
            "token":     self.decrypt_token(token),
        }

        try:
            response = requests.post(self.endpoint_verify, json=payload)

            if response.status_code == 200:
                return response.json()
            else:
                print(f"[LoginConnector] verification failed — {response.status_code}: {response.text}")
                return None

        except Exception as e:
            print(f"[LoginConnector] verification error: {e}")
            return None


    def decrypt_token(self,token):
        token_decrypted = encryption.decrypt_message(token,self.api_key)
        return token_decrypted







# ── Example usage ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    api = "Example-api"
    TOKEN = "Example-token"
    connector = LoginConnector(
        username     = "dummy",
        service_name = "new_ser",
        api_key = api
    )

    # Send some user data
    send_result = connector.send_or_update_user_data(TOKEN, {"msg": "hello from backend"})
    print("Send result:", send_result)

    # Retrieve user data back
    user_data = connector.get_user_data(TOKEN)
    print("User data:", user_data)

    # verify user login
    login_verify = connector.verify_user_login(TOKEN)
    print("Verification:", login_verify)