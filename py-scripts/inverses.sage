N = 9

R.<t> = QQ[]
red_poly = t^8 + t^4 + t^3 + t + 1

def compute_lagrange_multiplier(party_id, gamma_ref, gammas):
    S.<y> = Integers(2**64).extension(red_poly, 'y')
    TT = PolynomialRing(S, 'x')
    x = TT.gen()

    rolling_product = 1
    for i in range(len(gammas)):
        inv_coef = lift_invert_exceptional_pair(gamma_ref, gammas[i])
        rolling_product *= (x - S(gammas[i])) * S(inv_coef)

    party_coefs = coefs(party_id)
    assert(rolling_product(S(party_coefs)) == 1)
    
    return rolling_product

def lift_invert_exceptional_pair(x, y):
    assert(len(x) == len(y))
    diff = [x[i] - y[i] for i in range(len(x))]
    return lift_and_inverse(diff)

def lift_and_inverse(coefs):
    K.<a> = GF(2**8, name='a', modulus=red_poly)
    alpha = K(coefs)
    x0 = alpha**-1

    for i in range(2, 65):
        S.<y> = Integers(2**i).extension(red_poly, 'y')
        
        # convert alpha, x0 to the larger ring
        x0 = S(x0.list())
        alpha = S(coefs)
        # compute newton raphson iteration
        x1 = x0 * (2 - alpha * x0)
        # check whether x1*alpha = 1
        x0 = x1
    
    assert(S(alpha) * x0 == 1)
    return x0


def coefs(x):
    return [(x >> i) & 1 for i in range(8)]



def pretty_print_gamma_entry(entry):
    print("vec![", end="")
    print(str(entry.list()[0]) + "_u64, ", end="")
    print(",".join(str(_) for _ in entry.list()), end="")
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

pretty_print_polys(polys)