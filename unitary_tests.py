import unittest
from public_key_infrastructure import *


class AttackUncipherRSA(unittest.TestCase):

    def test_basic_attack_1(self):
        e = 7
        ciphered_message = 298572403473098085554734889867584144892290519988638729056078987038117
        message = 6055499213
        self.assertEqual(attack_uncipher_RSA(e, ciphered_message), message)
    
    def test_basic_attack_2(self):
        e = 3
        ciphered_message = 166375
        message = 55
        self.assertEqual(attack_uncipher_RSA(e, ciphered_message), message)
        
class ShamirThreeSteps(unittest.TestCase):
    
    def test_basic_third_steep_value_1(self):
        m = 725
        p = 877
        kA_e = 403
        kB_e = 619
        correct_value = 49
        self.assertEqual(third_step_exponentiation_ciphering(m, p, kA_e, kB_e), correct_value)
    
    def test_basic_third_steep_value_2(self):
        m = 406
        p = 733
        kA_e = 505
        kB_e = 461
        correct_value = 259
        self.assertEqual(third_step_exponentiation_ciphering(m, p, kA_e, kB_e), correct_value)
    
    def test_basic_three_steps_attack_1(self):
        a = "C331FC34B73CCF3"
        b = "6EABE4220C6FFE1"
        c = "2193002618F4290"
        correct_plain_message = "8C091830A3A7182"
        self.assertEqual(shamir_three_steps_attack(a,b,c), correct_plain_message)
    
    def test_basic_three_steps_attack_2(self):
        a = "4C9FFF995595CF4"
        b = "77F951590E218BA"
        c = "59DFC1A2D1162BE"
        correct_plain_message = "62B96F628AA26F0"
        self.assertEqual(shamir_three_steps_attack(a,b,c), correct_plain_message)
    
class SecretSharing(unittest.TestCase):
    
    def test_basic_secret_sharing_1(self):
        scheme = (3, 5)
        p = 2579
        fragments = [[2218, 620], [1848, 1642], [467, 1645], [2407, 1037], [1099, 988]]
        correct_secret = 901
        self.assertEqual(secret_recuperation(scheme, p, fragments), correct_secret)
    
    def test_basic_secret_sharing_2(self):
        scheme = (3, 5)
        p = 1931
        fragments = [[1, 1915], [4,1218], [5,155]]
        correct_secret = 673
        secret = secret_recuperation(scheme, p, fragments)
        self.assertEqual(secret_recuperation(scheme, p, fragments), correct_secret)
       
    def test_basic_secret_sharing_3(self):
        scheme = (3, 6)
        p = 1109
        fragments = [[919, 1016], [232,422], [841,300], [14,78], [882,1095]]
        correct_secret = 431
        self.assertEqual(secret_recuperation(scheme, p, fragments), correct_secret)
    
    def test_basic_secret_sharing_4(self):
        scheme = (3, 6)
        p = 1249
        fragments = [[459, 336], [428,535], [1104,354], [971,257], [433,567]]
        correct_secret = 808
        self.assertEqual(secret_recuperation(scheme, p, fragments), correct_secret)

class BlindSignature(unittest.TestCase):
    
    def test_basic_blind_signature_1(self):
        m = 6263
        pub_kB = (24287, 2639)
        priv_kB = 6287
        r = 15117
        correct_s = 14475
        self.assertEqual(blind_signature_second_step_value(m, pub_kB, priv_kB, r), correct_s)
        
    def test_basic_blind_signature_2(self):
        m = 12045
        pub_kB = (34081, 9353)
        priv_kB = 12601
        r = 28649
        correct_s = 17170
        self.assertEqual(blind_signature_second_step_value(m, pub_kB, priv_kB, r), correct_s)
    
    def test_basic_blind_signature_3(self):
        m = 8840
        pub_kB = (17947, 10993)
        priv_kB = 5777
        r = 4797
        correct_s = 306
        self.assertEqual(blind_signature_second_step_value(m, pub_kB, priv_kB, r), correct_s)
    

if __name__ == '__main__':

    # create a suite with all tests
    test_classes_to_run = [AttackUncipherRSA, ShamirThreeSteps, SecretSharing,
                           BlindSignature]
    loader = unittest.TestLoader()
    suites_list = []
    for test_class in test_classes_to_run:
        suite = loader.loadTestsFromTestCase(test_class)
        suites_list.append(suite)

    all_tests_suite = unittest.TestSuite(suites_list)

    # run the test suite with high verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    results = runner.run(all_tests_suite)
