from birdsong.passbird import Passbird
import unittest as ut


class TestPassbird(ut.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app_name = 'perceptua-twitter'
        cls.callback_url = 'http://localhost:5000'
        cls.passbird = Passbird(cls.app_name, cls.callback_url)
        cls.username = 'cloudgatherdin'

    def testGetDefaultHeaders(self):
        expected_headers = {
            'Host': 'api.twitter.com',
            'User-Agent': self.app_name,
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
        }

        headers = self.passbird.get_default_headers()

        for key, value in expected_headers.items():
            self.assertIn(key, headers.keys())
            self.assertIn(value, headers.values())

    def testGetBearerToken(self):
        bearer_token = self.passbird.get_bearer_token()
        self.assertEqual(bearer_token['token_type'], 'bearer')
        self.assertIn('access_token', bearer_token.keys())


if __name__ == '__main__':
    ut.main()