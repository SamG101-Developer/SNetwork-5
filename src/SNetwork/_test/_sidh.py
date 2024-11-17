from sibc.csidh import CSIDH, default_parameters, parameters

csidh = CSIDH(**default_parameters)


A_SEC_KEY, A_PUB_KEY = csidh.keygen()
B_SEC_KEY, B_PUB_KEY = csidh.keygen()

A_SS = csidh.dh(A_SEC_KEY, B_PUB_KEY)
B_SS = csidh.dh(B_SEC_KEY, A_PUB_KEY)

print(A_SS)
print(B_SS)
