from sympy import Rational, Integer, Matrix, invert, solve_linear_system
from sympy.abc import x, y, z

def attack_uncipher_RSA(e, ciphered_message):    
        return round(ciphered_message**(1/e))
    
def third_step_exponentiation_ciphering(message, p, kA_e, kB_e):
    return pow(message, kB_e, p)  

def shamir_three_steps_attack(a = "", b = "", c = ""):
    return hex(int(a, 16) ^ int(b, 16) ^ int(c, 16)).upper()[2:]

def secret_recuperation(scheme, p, fragments):    
    if len(fragments) < scheme[0]:
        print("There are no possibilities to compute it")
        return
    
    matrix_rows = []
    for fragment in fragments[:scheme[0]]:
        matrix_rows.append([1, fragment[0], pow(fragment[0],2), fragment[1] ])
    
    system = Matrix(matrix_rows)
    system_result = solve_linear_system(system, x, y, z)
    
    if system_result is None:
        print("No result for that eq system.")
        return
    else:
        secret = system_result[x]

        if isinstance(secret, Rational):
            result = secret.p * invert(secret.q, p)
        elif isinstance(secret, Integer):              
            result = secret
        else:
            print("There was an unexpected issue.")
            return

        return result % p

def blind_signature_second_step_value(m, pub_key, priv_key, r):
    t = pow(r, pub_key[1], pub_key[0])
    ciphered_m = (m*t)%pub_key[0]
    
    signed_ciphered_m = pow(ciphered_m, priv_key, pub_key[0])
    
    return signed_ciphered_m
