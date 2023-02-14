N = 9
T = 6
Q_exp = 64
F_DEG = 8

R.<t> = QQ[]
red_poly = t^8 + t^4 + t^3 + t + 1

def embed(v):
    S.<y> = Integers(2**Q_exp).extension(red_poly, 'y')
    return S([(v >> i) & 1 for i in range(F_DEG)])

def embed_coefs(v):
    S.<y> = Integers(2**Q_exp).extension(red_poly, 'y')
    return S(v)


def compute_lagrange_multiplier(party_id, gamma_ref, gammas):
    S.<y> = Integers(2**Q_exp).extension(red_poly, 'y')
    TT = PolynomialRing(S, 'x')
    x = TT.gen()

    rolling_product = 1
    for i in range(len(gammas)):
        inv_coef = lift_invert_exceptional_pair(gamma_ref, gammas[i])
        rolling_product *= (x - embed_coefs(gammas[i])) * inv_coef

    party_id = embed(party_id)
    assert(rolling_product(party_id) == 1)
    
    return rolling_product

def lift_invert_exceptional_pair(x, y):
    assert(len(x) == len(y))
    diff = [x[i] - y[i] for i in range(len(x))]
    return lift_and_inverse(diff)

def lift_and_inverse(coefs):
    K.<a> = GF(2**8, name='a', modulus=red_poly)
    alpha = K(coefs)
    x0 = alpha**-1

    for i in range(2, Q_exp+1):
        S.<y> = Integers(2**i).extension(red_poly, 'y')
        
        # convert alpha, x0 to the larger ring
        x0 = S(x0.list())
        alpha = S(coefs)
        # compute newton raphson iteration
        x1 = x0 * (2 - alpha * x0)
        # check whether x1*alpha = 1
        x0 = x1
    
    S.<y> = Integers(2**Q_exp).extension(red_poly, 'y')
    assert(S(coefs) * x0 == 1)
    return x0


def coefs(x):
    return [(x >> i) & 1 for i in range(8)]


def pretty_print_gamma_entry(entry):
    print("vec![", end="")
    print(str(entry.list()[0]) + "_u64, ", end="")
    print(",".join(str(_) for _ in entry.list()[1::]), end="")
    print("], ")

def pretty_print_polys(polys):
    print("vec![")
    for i in range(len(polys)):
        poly = polys[i]
        print("vec![")
        poly_list = poly.list()
        for g in poly_list:
            pretty_print_gamma_entry(g)
        if i != len(polys) - 1:
            print("], ")
        else:
            print("]")
    print("]") 

f_deg = 8
gammas = [coefs(i) for i in range(1, N+1)]
polys = list()
for party_id in range(0, len(gammas)):
    polys.append(compute_lagrange_multiplier(party_id + 1, gammas[party_id], gammas[:party_id] + gammas[party_id+1:]))

# pretty_print_polys(polys)
polys.insert(0, None)

def sanity_check(gammas):
    R.<t> = QQ[]
    red_poly = t^8 + t^4 + t^3 + t + 1

    S.<y> = Integers(2**Q_exp).extension(red_poly, 'y')
    TT = PolynomialRing(S, 'x')
    x = TT.gen()

    a = [None] * T
    secret = 100
    a[0] = [secret, 0, 0, 0, 0, 0, 0, 0]
    a[1] = [42, 42, 42, 42, 42, 42, 42, 42]
    a[2] = [42, 42, 42, 42, 42, 42, 42, 42]
    a[3] = [42, 42, 42, 42, 42, 42, 42, 42]
    a[4] = [42, 42, 42, 42, 42, 42, 42, 42]
    a[5] = [42, 42, 42, 42, 42, 42, 42, 42]

    shamir_poly = sum(S(a[i]) * x**i for i in range(T))
    reconstructed_poly = sum(shamir_poly(embed(i)) * gammas[i] for i in range(1, N+1))

    assert(reconstructed_poly(0) == secret)

sanity_check(polys)