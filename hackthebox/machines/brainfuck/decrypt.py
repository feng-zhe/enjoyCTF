# PT + OTP = CT

PT = "Orestis - Hacking for fun and profit"
CT = "Pieagnm - Jkoijeg nbw zwx mle grwsnn"
# Wejmvse - Fbtkqal zqb rso rnl cwihsf
# Qbqquzs - Pnhekxs dpi fca fhf zdmgzt

ORD_A = ord('a')

# def getotp():
    # otp = ""  # the one-time pad
    # for c, p in zip(CT, PT):
        # if not c.isalpha(): continue
        # ord_c, ord_p = ord(c) - ORD_A, ord(p) - ORD_A
        # otp += chr((ord_c - ord_p) % 26 + ORD_A)
    # return otp

OTP = "fuckmybrain"

def decrypt(ct, offset = 0):
    pt = ""
    for c in ct:
        if not c.isalpha():
            pt += c
            continue
        ord_c, ord_otp = ord(c) - ORD_A, ord(OTP[offset % len(OTP)]) - ORD_A
        pt += chr((ord_c - ord_otp) % 26 + ORD_A)
        offset += 1
    return pt

def main():
    while True:
        ct = input("Enter Crypted text:")
        print(decrypt(ct.lower()))

if __name__ == "__main__":
    main()
